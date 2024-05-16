"""Tool for managing a database of tests found through fuzzing."""

from argparse import ArgumentParser, FileType
from binascii import hexlify, unhexlify
from dataclasses import asdict, dataclass
from datetime import datetime
from itertools import starmap
from logging import DEBUG, basicConfig, getLogger
from os import set_blocking
from pathlib import Path
from selectors import EVENT_READ, DefaultSelector
from subprocess import PIPE, Popen
from typing import Any, BinaryIO
from json import load, dump, loads
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


logger = getLogger(__name__)


def _sanitize_char_for_c_string(c: int) -> str:
    assert 0 <= c <= 255
    return C_SPECIALS.get(c, chr(c) if c >= 0x20 and c < 0x7F else f"\\x{c:02X}")


def _sanitize_for_c_string(a: bytes) -> str:
    return '"' + "".join(map(_sanitize_char_for_c_string, a)) + '"'


def _sanitize_for_json(a: bytes) -> str:
    return a.decode()


@dataclass
class FuzzTest:
    """Holds a single fuzz test."""

    regexes: tuple[bytes, ...]
    should_parse: tuple[bool, ...]
    num_spans: int | None = None
    num_sets: int | None = None
    match_string: bytes | None = None
    match_spans: tuple[tuple[int, int], ...] | None = None
    match_sets: tuple[int, ...] | None = None
    match_anchor: str | None = None
    identifier: str | None = None
    commit_hash: str | None = None
    created: datetime | None = None

    @classmethod
    def from_dict(cls, obj: dict[str, Any], identifier: str | None = None):
        """Instantiate a FuzzTest from a given JSON object."""
        encoding = obj.get("encoding", "raw")
        if encoding == "utf-8":

            def decoder_func(s: str | list[int]) -> bytes:
                assert isinstance(s, str)
                return s.encode()

        elif encoding == "binascii":

            def decoder_func(s: str | list[int]) -> bytes:
                assert isinstance(s, str)
                return unhexlify(s.replace("_", ""))

        elif encoding == "raw":

            def decoder_func(s: str | list[int]) -> bytes:
                assert isinstance(s, list)
                return bytes(s)

        else:
            raise ValueError(f"unknown regex encoding {encoding}")

        regexes = obj["regexes"]
        regexes = tuple(map(decoder_func, regexes))

        should_parse: tuple[bool] = tuple(obj["should_parse"])

        commit_hash = obj.get("commit_hash")
        created = (
            datetime.fromisoformat(obj["created"])
            if obj.get("created") is not None
            else None
        )

        if len(should_parse) != len(regexes):
            raise ValueError("length of should_parse should equal length of regexes")

        all_parse = all(should_parse)

        if not all_parse or obj.get("match_string") is None:
            return cls(
                regexes,
                should_parse,
                identifier=identifier,
                commit_hash=commit_hash,
                created=created,
            )

        return cls(
            regexes,
            should_parse,
            obj["num_spans"],
            obj["num_sets"],
            decoder_func(obj["match_string"]),
            tuple([tuple(x) for x in obj["match_spans"]]),
            tuple(obj["match_sets"]),
            obj.get("match_anchor"),
            identifier,
            commit_hash,
            created,
        )

    def to_dict(self) -> dict:
        """Convert this FuzzTest into a JSON object."""
        try:
            encoding = "utf-8"
            encoded_regexes = [_sanitize_for_json(r) for r in self.regexes]
            encoded_match = (
                _sanitize_for_json(self.match_string)
                if self.match_string is not None
                else None
            )
        except UnicodeDecodeError:
            encoding = "binascii"
            encoded_regexes = [hexlify(r, "_").decode() for r in self.regexes]
            encoded_match = (
                hexlify(self.match_string, "_")
                if self.match_string is not None
                else None
            )
        assert self.created is not None
        assert self.commit_hash is not None
        return {
            k: v
            for k, v in sorted(
                {
                    "encoding": encoding,
                    "regexes": encoded_regexes,
                    "should_parse": self.should_parse,
                    "num_spans": self.num_spans,
                    "num_sets": self.num_sets,
                    "match_string": encoded_match,
                    "match_spans": self.match_spans,
                    "match_sets": self.match_sets,
                    "match_anchor": self.match_anchor,
                    "commit_hash": self.commit_hash,
                    "created": self.created.isoformat(),
                }.items()
            )
            if v is not None
        }

    def to_c_code(self) -> list[str]:
        """Output this test case as C code."""
        assert len(self.regexes) == 1
        if not self.parses():
            return [
                "PROPAGATE(check_noparse_n(",
                _sanitize_for_c_string(self.regexes[0]) + ",",
                str(len(self.regexes[0])),
                "));",
                "PASS();",
            ]
        else:
            assert self.match_spans is not None
            assert self.match_sets is not None
            assert self.match_string is not None
            output, out = make_appender_func()
            out("const char *regexes[] = {")
            out(*[_sanitize_for_c_string(r) + "," for r in self.regexes])
            out("};")
            out("size_t regexes_n[] = {")
            out(*[str(len(r)) + "," for r in self.regexes])
            out("};")
            if self.num_spans != 0:
                out("span spans[] = {")
                out(",".join(f"{{{s[0]}, {s[1]}}}" for s in self.match_spans) + "};")
            if self.num_sets != 0:
                out("u32 sets[] = {")
                out(",".join([str(s) for s in self.match_sets]) + ";")
            out("PROPAGATE(check_matches_n(")
            out(
                ",".join(
                    [
                        "regexes",
                        "regexes_n",
                        f"{len(self.regexes)}",
                        _sanitize_for_c_string(self.match_string),
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

    def dump(self):
        """Dump test info to stdout."""
        print(f"{self.identifier}: {len(self.regexes)} regexes")
        for regex, parse in zip(self.regexes, self.should_parse):
            print(
                f"  {_sanitize_for_c_string(regex)}: {["parses", "doesn't parse"][parse]}"
            )
        if all(self.should_parse) and self.match_string is not None:
            print(f"  match with {_sanitize_for_c_string(self.match_string)}:")
            assert self.match_spans is not None and self.num_spans is not None
            assert self.match_sets is not None and self.num_sets is not None
            print(
                f"    spans: {self.num_spans} sets: {self.num_sets} anchor: {self.match_anchor}"
            )
            print(f"    expect spans: {','.join(map(_fmt_span, self.match_spans))}")
            print(f"    expect sets:  {','.join(map(str, self.match_sets))}")

    def _key(self):
        cmp_dict = asdict(self)
        del cmp_dict["identifier"]
        del cmp_dict["commit_hash"]
        del cmp_dict["created"]
        return tuple(cmp_dict.values())

    def parses(self) -> bool:
        """Check if this regex parses."""
        return all(self.should_parse)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return self._key() == other._key()


def _read_tests(json: BinaryIO) -> tuple[dict, list[FuzzTest]]:
    return (
        doc := load(json),
        list(
            [FuzzTest.from_dict(test, identifier) for identifier, test in doc.items()]
        ),
    )


def _fmt_span(span: tuple[int, int]) -> str:
    return f"({span[0]}, {span[1]})"


def _cmd_show(args) -> int:
    _, tests = _read_tests(args.tests_file)
    for test in tests:
        test.dump()
    return 0


def _import_tests(args, tests: list[FuzzTest]):
    doc, original_tests = _read_tests(args.tests_file)
    commit_hash = get_commit_hash()

    for test in tests:
        try:
            original_test_idx = original_tests.index(test)
            logger.debug(
                "skipping existing test %s",
                original_tests[original_test_idx].identifier,
            )
            continue
        except ValueError:
            pass
        new_identifier = f"{len(original_tests):04d}"
        test.identifier = new_identifier
        test.commit_hash = commit_hash
        test.created = datetime.now()
        logger.debug("imported new test %s", test.identifier)
        doc[new_identifier] = test.to_dict()

    args.tests_file.seek(0)
    args.tests_file.truncate()
    dump(doc, args.tests_file, indent="  ")

    return 0


def _cmd_import_parser(args) -> int:

    _import_tests(
        args,
        [
            FuzzTest(
                (new_corpus_file.read(),),
                (False,),
            )
            for new_corpus_file in args.import_files
        ],
    )

    return 0


def _cmd_run_fuzzington(args) -> int:
    selector = DefaultSelector()
    current_test: dict | None = None
    with Popen(
        [args.fuzzington.resolve(), "-n", str(args.num_iterations)],
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
                logger.debug("test timed out after %i iterations", i)
                break
            if i == args.num_iterations:
                # done
                return 0
            if proc.poll() is not None:
                logger.debug("process died after %i iterations", i)
                break
            i += 1
            current_test = loads(proc.stdout.readline())
    assert current_test is not None

    _import_tests(args, [FuzzTest.from_dict(current_test)])

    return 1


def _cmd_gen_tests(args) -> int:
    output, out = make_appender_func()

    _, tests = _read_tests(args.tests_file)

    test_names = []

    for test in tests:
        test_name = f"fuzz_regression_{test.identifier}"
        out(f"TEST({test_name}) {{")
        out(*test.to_c_code(), suffix="")
        out("}")
        test_names.append(test_name)

    out("SUITE(fuzz_regression) {")
    for test_name in test_names:
        out(f"RUN_TEST({test_name});")
    out("}")

    insert_c_file(args.file, output, "gen_parser_fuzz_regression_tests")

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
        "--fuzzington", type=Path, default="tools/fuzzington/target/debug/fuzzington"
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
    exit(main())
