"""Tool for managing a database of tests found through fuzzing."""

from argparse import ArgumentParser, FileType
from binascii import hexlify, unhexlify
from dataclasses import asdict, dataclass
from datetime import datetime
from logging import DEBUG, basicConfig, getLogger
from os import set_blocking
from pathlib import Path
from selectors import EVENT_READ, DefaultSelector
from subprocess import PIPE, Popen
import sys
from typing import Any, BinaryIO, Callable, NamedTuple, Self
from json import JSONDecodeError, dumps, load, dump, loads
from util import get_commit_hash, insert_c_file, make_appender_func

C_SPECIALS = {
    ord("\n"): "\\n",
    ord("\r"): "\\r",
    ord("\t"): "\\t",
    ord('"'): '\\"',
    ord("\\"): "\\\\",
}

JSON_SPECIALS = {
    ord("\n"): "\\n",
    ord("\r"): "\\r",
    ord("\t"): "\\t",
    ord('"'): '\\"',
    ord("\\"): "\\\\",
}

HEX_DIGITS = "0123456789abcdefABCDEF"


logger = getLogger(__name__)


def _escape_cchar(c: int) -> str:
    return f"\\x{c:02X}"


def _escape_cstr(a: bytes) -> str:
    # Return escaped bytes as a C string.
    def gen():
        last_char_was_escaped = False
        for b in a:
            if chr(b) in HEX_DIGITS and last_char_was_escaped:
                yield _escape_cchar(b)
            elif b in C_SPECIALS:
                yield C_SPECIALS[b]
                last_char_was_escaped = False
            elif b >= 0x20 and b <= 0x7F:
                yield chr(b)
                last_char_was_escaped = False
            else:
                yield _escape_cchar(b)
                last_char_was_escaped = True

    return '"' + "".join(gen()) + '"'


def _declare_cstr(id: str, a: bytes) -> str:
    if (
        len(a) > 500
    ):  # c89 disallows 509+ bytes but let's be safe here... you never know when you might hit a compiler limit!!!
        return f"const re_u8 {id}[{len(a)}] = {{" + ",".join(map(str, a)) + "};"
    return f"const char* {id} = {_escape_cstr(a)};"


class TestStamp(NamedTuple):
    """Holds registration information for a test case."""

    identifier: str
    commit_hash: str
    created: datetime

    @classmethod
    def from_dict(cls, obj) -> Self | None:
        """Read a"""
        if "identifier" not in obj:
            return None
        return cls(
            obj["identifier"],
            obj["commit_hash"],
            datetime.fromisoformat(obj["created"]),
        )

    def to_dict(self) -> dict:
        """Convert this stamp into a dictionary."""
        return {
            "identifier": self.identifier,
            "commit_hash": self.commit_hash,
            "created": self.created.isoformat(),
        }


def deserialize_bytes(obj: dict | str | list) -> bytes:
    if isinstance(obj, str):
        return obj.encode()
    elif isinstance(obj, list):
        return bytes(obj)
    encoding = obj.get("encoding", "utf-8")
    data: str = obj["data"]
    assert isinstance(data, str)
    if encoding == "utf-8":

        def decoder_func(s: str) -> bytes:
            return s.encode()

    elif encoding == "binascii":

        def decoder_func(s: str) -> bytes:
            return unhexlify(s.replace("_", ""))

    else:
        raise ValueError(f"unknown regex encoding {encoding}")
    return decoder_func(data)


def serialize_bytes(b: bytes) -> dict | str | list:
    try:
        encoded = b.decode()
        return encoded
    except UnicodeDecodeError:
        return {"encoding": "binascii", "data": hexlify(b, "_").decode()}


class Test:
    """Represents a single test case."""

    REGISTRY: dict[str, type[Self]] = {}
    test_type: str
    _stamp: TestStamp | None
    extra: Any

    def __init_subclass__(cls, **kwargs) -> None:
        Test.REGISTRY[cls.test_type] = cls
        super().__init_subclass__(**kwargs)

    def __init__(self, stamp: TestStamp | None, extra: Any | None = None):
        self._stamp = stamp
        self.extra = extra

    @classmethod
    def from_dict(cls, obj) -> Self:
        """Read this from a dictionary."""
        return cls(TestStamp.from_dict(obj), obj.get("extra", None))

    def to_dict(self) -> dict:
        """Convert this test case into a dictionary."""
        return {"type": self.test_type} | (
            {"extra": self.extra} if self.extra is not None else {}
        )

    @classmethod
    def deserialize(cls, obj) -> "Test":
        """Convert this test case and its stamp into a dictionary."""
        return Test.REGISTRY[obj["type"]].from_dict(obj)

    def serialize(self) -> dict:
        """Convert this test case and its stamp into a dictionary."""
        return (
            self._stamp.to_dict() if self._stamp is not None else {}
        ) | self.to_dict()

    def to_c_code(self) -> list[str]:
        """Convert this test to C code."""
        return NotImplemented

    def __eq__(self, other) -> bool:
        assert isinstance(other, Test)
        return self.to_dict() == other.to_dict()

    def __hash__(self) -> int:
        return hash(self.to_dict())

    def get_stamp(self) -> TestStamp | None:
        return self._stamp

    def stamp(self, stamp: TestStamp):
        self._stamp = stamp


class ParseTest(Test):
    """
    A test that runs the parser and checks whether or not the given regexes parse.
    """

    test_type = "parse"

    regexes: tuple[bytes, ...]
    should_parse: tuple[bool, ...]
    error_posns: tuple[int, ...] | None

    def __init__(
        self,
        stamp: TestStamp | None,
        extra: Any | None,
        regexes: tuple[bytes, ...],
        should_parse: tuple[bool, ...],
        error_msgs: tuple[str, ...] | None,
        error_posns: tuple[int, ...] | None,
    ):
        super().__init__(stamp, extra)
        self.regexes = regexes
        self.should_parse = should_parse
        self.error_msgs = error_msgs
        self.error_posns = error_posns

    @classmethod
    def from_dict(cls, obj: dict) -> Self:
        return cls(
            TestStamp.from_dict(obj),
            obj.get("extra", None),
            tuple(map(deserialize_bytes, obj["regexes"])),
            tuple(obj["should_parse"]),
            obj.get("error_msgs", None),
            obj.get("error_posns", None),
        )

    def to_dict(self) -> dict:
        return super().to_dict() | {
            "regexes": [serialize_bytes(b) for b in self.regexes],
            "should_parse": self.should_parse,
            "error_msgs": self.error_msgs,
            "error_posns": self.error_posns,
        }

    def to_c_code(self) -> list[str]:
        assert len(self.regexes) == 1
        return [
            "PROPAGATE(check_noparse_n(",
            _escape_cstr(self.regexes[0]) + ",",
            str(len(self.regexes[0])) + ",",
            _escape_cstr((self.error_msgs[0] if self.error_msgs else "").encode())
            + ",",
            str(self.error_posns[0] if self.error_posns else 0),
            "));",
            "PASS();",
        ]


class MatchTest(Test):
    """A test that runs a match on a string."""

    test_type = "match"

    def __init__(
        self,
        stamp: TestStamp | None,
        extra: Any | None,
        regexes: tuple[bytes, ...],
        num_spans: int,
        num_sets: int,
        match_string: bytes,
        match_spans: tuple[tuple[int, int], ...],
        match_sets: tuple[int],
        match_anchor: str,
    ):
        super().__init__(stamp, extra)
        self.regexes = regexes
        self.num_spans = num_spans
        self.num_sets = num_sets
        self.match_string = match_string
        self.match_spans = match_spans
        self.match_sets = match_sets
        self.match_anchor = match_anchor

    @classmethod
    def from_dict(cls, obj: dict) -> Self:
        return cls(
            TestStamp.from_dict(obj),
            obj.get("extra", None),
            tuple(map(deserialize_bytes, obj["regexes"])),
            obj["num_spans"],
            obj["num_sets"],
            deserialize_bytes(obj["match_string"]),
            obj["match_spans"],
            obj["match_sets"],
            obj["match_anchor"],
        )

    def to_dict(self) -> dict:
        return super().to_dict() | {
            "regexes": [serialize_bytes(b) for b in self.regexes],
            "num_spans": self.num_spans,
            "num_sets": self.num_sets,
            "match_string": serialize_bytes(self.match_string),
            "match_spans": self.match_spans,
            "match_sets": self.match_sets,
            "match_anchor": self.match_anchor,
        }

    def to_c_code(self) -> list[str]:
        output, out = make_appender_func()
        out("const char *regexes[] = {")
        out(*[_escape_cstr(r) + "," for r in self.regexes])
        out("};")
        out(_declare_cstr("text", self.match_string))
        out("size_t regexes_n[] = {")
        out(*[str(len(r)) + "," for r in self.regexes])
        out("};")
        if self.num_spans != 0:
            out("span spans[] = {")
            out(",".join(f"{{{s[0]}, {s[1]}}}" for s in self.match_spans) + "};")
        if self.num_sets != 0:
            out("re_u32 sets[] = {")
            out(",".join([str(s) for s in self.match_sets]) + ";")
        out("PROPAGATE(check_matches_n(")
        out(
            ",".join(
                [
                    "regexes",
                    "regexes_n",
                    f"{len(self.regexes)}",
                    "(const char*)text",
                    f"{len(self.match_string)}",
                    f"{self.num_spans}",
                    f"{self.num_sets}",
                    f"'{self.match_anchor}'",
                    "spans" if self.num_spans != 0 else "NULL",
                    "sets" if self.num_sets != 0 else "NULL",
                    f"{len(self.match_sets) if len(self.match_sets) != 0 else 1}",
                ]
            ),
        )
        out("));")
        out("PASS();")
        return output


def _read_tests(json: BinaryIO) -> tuple[list, list[Test]]:
    return (
        doc := load(json),
        list(Test.deserialize(test) for test in doc),
    )


def _cmd_show(args) -> int:
    _, tests = _read_tests(args.tests_file)
    for test in tests:
        if (stamp := test.get_stamp()) is None:
            continue
        print(stamp.identifier, stamp.commit_hash, stamp.created.isoformat())
    return 0


def _import_tests(args, tests: list[Test]):
    doc, original_tests = _read_tests(args.tests_file)
    commit_hash = get_commit_hash()

    for test in tests:
        try:
            original_test_idx = original_tests.index(test)
            assert (stamp := original_tests[original_test_idx].get_stamp())
            logger.debug(
                "skipping existing test %s",
                stamp.identifier,
            )
            continue
        except ValueError:
            pass
        new_identifier = f"{len(original_tests):04d}"
        test.stamp(TestStamp(new_identifier, commit_hash, datetime.now()))
        logger.debug("imported new test %s", new_identifier)
        doc.append(test.serialize())

    args.tests_file.seek(0)
    args.tests_file.truncate()
    dump(doc, args.tests_file, indent="  ")

    return 0


def _cmd_import_parser(args) -> int:

    _import_tests(
        args,
        [
            ParseTest(None, None, (new_corpus_file.read(),), (False,), None, None)
            for new_corpus_file in args.import_files
        ],
    )

    return 0


def _cmd_run_fuzzington(args) -> int:
    selector = DefaultSelector()
    current_test: dict | None = None
    commit_hash = int(get_commit_hash()[: 64 // 4], 16)  # 64 bits worth of hash
    fuzzington_cmdline = [
        args.fuzzington.resolve(),
        "-n",
        str(args.num_iterations),
        "-s",
        str(commit_hash),
    ]
    logger.debug("args: %s", " ".join(map(str, fuzzington_cmdline)))
    with Popen(
        fuzzington_cmdline,
        encoding="utf-8",
        stdout=PIPE,
    ) as proc:
        assert proc.stdout is not None
        selector.register(proc.stdout.fileno(), EVENT_READ)
        set_blocking(proc.stdout.fileno(), True)
        i = 0
        while True:
            events = selector.select(timeout=args.timeout)
            if len(events) == 0:
                if proc.poll() is not None:
                    if i == args.num_iterations:
                        # done
                        return 0
                    logger.debug("process died after %i iterations", i)
                    break
                logger.debug("test timed out after %i iterations", i)
                break
            if i == args.num_iterations:
                # done
                return 0
            i += 1
            if i % 100000 == 0:
                logger.info("status: %i iterations", i)
            current_output = proc.stdout.readline()
            try:
                current_test = loads(current_output)
            except JSONDecodeError:
                logger.debug(
                    "invalid JSON received after %i iterations: %s",
                    i,
                    repr(current_output),
                )
                logger.debug("logging previous test")
                break
    assert current_test is not None

    _import_tests(args, [Test.deserialize(current_test)])

    return 1


def _cmd_gen_tests(args) -> int:
    output, out = make_appender_func()

    _, tests = _read_tests(args.tests_file)

    test_names = []

    for test in tests:
        stamp = test.get_stamp()
        assert stamp is not None
        test_name = f"fuzz_regression_{stamp.identifier}"
        out(f"TEST({test_name}) {{")
        out(*test.to_c_code(), suffix="")
        out("}")
        test_names.append(test_name)

    out("SUITE(fuzz_regression) {")
    for test_name in test_names:
        out(f"RUN_TEST({test_name});")
    out("}")

    insert_c_file(args.file, output, "gen_fuzz_regression_tests")

    logger.debug("generated %i tests", len(tests))

    return 0


def main() -> int:
    """Main method."""
    ap = ArgumentParser()
    ap.add_argument(
        "--debug",
        action="store_const",
        const=True,
        default=False,
        help="show debug info",
    )

    ap.add_argument("tests_file", type=FileType("r+"), default="fuzz_db.json")
    subcmds = ap.add_subparsers()

    ap_show = subcmds.add_parser("show", help="show fuzz test database")
    ap_show.set_defaults(func=_cmd_show)

    ap_import_parser = subcmds.add_parser(
        "import_parser", help="import llvm fuzzer parser tests"
    )
    ap_import_parser.add_argument(
        "import_files",
        nargs="+",
        type=FileType("rb"),
        help="the artifact files to import",
    )
    ap_import_parser.set_defaults(func=_cmd_import_parser)

    ap_run_fuzzington = subcmds.add_parser("run_fuzzington", help="run fuzzington")
    ap_run_fuzzington.add_argument(
        "--fuzzington", type=Path, default="build/fuzzington/release/fuzzington"
    )
    ap_run_fuzzington.add_argument("--timeout", type=float, default=2)
    ap_run_fuzzington.add_argument("--num-iterations", type=int, default=1)
    ap_run_fuzzington.set_defaults(func=_cmd_run_fuzzington)

    ap_gen_tests = subcmds.add_parser("gen_tests", help="generate tests")
    ap_gen_tests.add_argument("file", type=FileType("r+"))
    ap_gen_tests.set_defaults(func=_cmd_gen_tests)

    args = ap.parse_args()

    if args.debug:
        basicConfig(level=DEBUG)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
