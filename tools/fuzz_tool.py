"""Tool for managing a database of tests found through fuzzing."""

from argparse import ArgumentParser, FileType
from binascii import hexlify, unhexlify
from dataclasses import asdict, dataclass
from itertools import starmap
from logging import getLogger
from typing import Any, BinaryIO, Callable

from tomlkit import dump
try:
    from tomlkit import load, TOMLDocument
except ImportError:
    # tomlkit doesn't exist -- we can still read the db with std tomllib
    from tomllib import load
    # TOMLDocument = Any

from util import get_commit_hash

C_SPECIALS = {
    ord("\n"): "\\n",
    ord("\r"): "\\r",
    ord("\t"): "\\t",
    ord('"'): '\\"',
    ord("\\"): "\\\\",
}

TOML_SPECIALS = {
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


def _sanitize_for_toml(a: bytes) -> str:
    return a.decode()


@dataclass
class FuzzTest:
    """Holds a single fuzz test."""

    identifier: str
    commit_hash: str
    regexes: tuple[bytes, ...]
    should_parse: tuple[bool, ...]
    num_spans: int | None = None
    num_sets: int | None = None
    match_string: bytes | None = None
    match_spans: tuple[tuple[int, int], ...] | None = None
    match_sets: tuple[int, ...] | None = None
    match_anchor: str = 'B'

    @classmethod
    def from_dict(cls, identifier: str, obj: dict[str, Any]):
        """Instantiate a FuzzTest from a given TOML object."""
        encoding = obj["encoding"]
        decoder_func: Callable[[str], bytes] = str.encode
        if encoding == "utf-8":
            decoder_func = str.encode
        elif encoding == "binascii":
            decoder_func = lambda s: unhexlify(s.replace("_", ""))
        else:
            raise ValueError(f"unknown regex encoding {encoding}")

        regexes = obj["regexes"]
        regexes = tuple(map(decoder_func, regexes))

        should_parse: tuple[bool] = tuple(obj["should_parse"])

        if len(should_parse) != len(regexes):
            raise ValueError("length of should_parse should equal length of regexes")

        all_parse = all(should_parse)
        if not all_parse or obj.get("match_string") is None:
            return cls(identifier, obj["commit_hash"], regexes, should_parse)

        return cls(
            identifier,
            obj["commit_hash"],
            regexes,
            should_parse,
            obj["num_spans"],
            obj["num_sets"],
            decoder_func(obj["match_string"]),
            tuple([tuple(x) for x in obj["match_spans"]]),
            tuple(obj["match_sets"]),
            obj["match_anchor"]
        )

    def to_dict(self) -> dict:
        """Convert this FuzzTest into a TOML object."""
        try:
            encoding = "utf-8"
            encoded_regexes = [_sanitize_for_toml(r) for r in self.regexes]
            encoded_match = (
                _sanitize_for_toml(self.match_string)
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
        return {k: v for k, v in {
            "commit_hash": self.commit_hash,
            "encoding": encoding,
            "regexes": encoded_regexes,
            "should_parse": self.should_parse,
            "num_spans": self.num_spans,
            "num_sets": self.num_sets,
            "match_string": encoded_match,
            "match_spans": self.match_spans,
            "match_sets": self.match_sets,
        }.items() if v is not None }

    def dump(self):
        """Dump test info to stdout."""
        print(f"{self.identifier}: {len(self.regexes)} regexes")
        for regex, parse in zip(self.regexes, self.should_parse):
            print(f"  {_sanitize_for_c_string(regex)}: {["parses", "doesn't parse"][parse]}")
        if all(self.should_parse) and self.match_string is not None:
            print(f"  match with {_sanitize_for_c_string(self.match_string)}:")
            assert self.match_spans is not None and self.num_spans is not None
            assert self.match_sets is not None and self.num_sets is not None
            print(f"    spans: {self.num_spans} sets: {self.num_sets} anchor: {self.match_anchor}")
            print(f"    expect spans: {','.join(map(_fmt_span, self.match_spans))}")
            print(f"    expect sets:  {','.join(map(str, self.match_sets))}")

    def _key(self):
        cmp_dict = asdict(self)
        del cmp_dict["identifier"]
        del cmp_dict["commit_hash"]
        return tuple(cmp_dict.values())

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        return self._key() == other._key()

def _read_tests(toml: BinaryIO) -> tuple[TOMLDocument, list[FuzzTest]]:
    doc = load(toml)
    return (doc, list(starmap(FuzzTest.from_dict, doc.items())))

def _fmt_span(span: tuple[int, int]) -> str:
    return f"({span[0]}, {span[1]})"

def _cmd_show(args) -> int:
    _, tests = _read_tests(args.tests_file)
    for test in tests:
        test.dump()
    return 0

def _cmd_import(args) -> int:
    doc, original_tests = _read_tests(args.tests_file)
    original_tests_set = set(original_tests)
    commit_hash = get_commit_hash()

    for new_corpus_file in args.import_files:
        new_identifier = f"{len(original_tests):04d}"
        test = FuzzTest(new_identifier, commit_hash, (new_corpus_file.read(),), (False,))
        if test in original_tests_set:
            logger.debug("skipping existing corpus %s", new_corpus_file.name)
            continue
        logger.debug("importing new corpus %s", new_corpus_file.name)
        doc[new_identifier] = test.to_dict()

    args.tests_file.seek(0)
    args.tests_file.truncate()
    dump(doc, args.tests_file)

    return 0
    

def main() -> int:
    """Main method."""
    ap = ArgumentParser()

    ap.add_argument("tests_file", type=FileType("r+"), default="fuzz_db.toml")
    subcmds = ap.add_subparsers()

    ap_show = subcmds.add_parser("show", help="show fuzz test database")
    ap_show.set_defaults(func=_cmd_show)

    ap_import_parser = subcmds.add_parser("import_parser", help="import llvm fuzzer parser tests")
    ap_import_parser.add_argument("import_files", nargs='+', type=FileType("rb"),
                                  help="the artifact files to import")
    ap_import_parser.set_defaults(func=_cmd_import)

    args = ap.parse_args()
    args.func(args)

    return 0


if __name__ == "__main__":
    exit(main())
