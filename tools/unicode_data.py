"""Unicode data manager for generating tables"""

import argparse
import io
from logging import DEBUG, basicConfig, getLogger
from pathlib import Path
import sys
from typing import IO, Callable, Iterator, Iterable, NamedTuple
import shutil
from urllib.request import urlopen
import zipfile
from itertools import chain
from enum import StrEnum, auto

from squish_casefold import (
    calculate_masks,
    calculate_shifts,
    check_arrays,
    find_best_arrays,
    build_arrays,
)
from util import (
    UTF_MAX,
    DataType,
    RuneRanges,
    SyntacticRanges,
    RuneRange,
    insert_c_file,
    nranges_invert,
    nranges_normalize,
    ranges_expand,
    make_appender_func,
)

UCD_URL = "https://www.unicode.org/Public/zipped"
CLEAR_TERM = "\x1b[0K"

logger = getLogger(__name__)


def _fetch_ucd(db: Path, version: str):
    url = UCD_URL + "/" + version + "/UCD.zip"
    logger.debug("fetching %s into %s... ", url, db)
    with urlopen(url) as req, open(db, "wb") as out_file:
        shutil.copyfileobj(req, out_file)
        logger.debug("fetched %i bytes", out_file.tell())


def cmd_fetch(args):
    """Fetch the UCD."""
    _fetch_ucd(args.db, args.version)
    return 0


class UnicodeData:
    """Manages a UCD and performs simple file retrieval/parsing."""

    def __init__(self, path: Path, db_version: str):
        if not path.exists():
            logger.debug("UCD file %s does not exist, downloading...", path)
            _fetch_ucd(path, db_version)

        def open_zip() -> zipfile.ZipFile:
            # suppresses 'consider-using-with'
            return zipfile.ZipFile(path)

        self.source: zipfile.ZipFile | Path = (
            open_zip() if path.name.endswith(".zip") else path
        )

    @staticmethod
    def _remove_comments(line: str) -> list[str] | None:
        parts = line.split(";")
        if len(parts) < 3:
            return None
        return list(map(str.strip, parts))

    def load_file(
        self,
        relpath: Path,
        *,
        line_filter: Callable[[str], list[str] | None] | None = None,
    ) -> Iterator[list[str]]:
        """Load a file from the UCD, applying `line_filter` to each line."""
        line_filter = self._remove_comments if line_filter is None else line_filter
        if isinstance(self.source, zipfile.ZipFile):
            file = io.TextIOWrapper(self.source.open(str(relpath)), "utf-8")
        else:

            def open_file():
                assert isinstance(self.source, Path)
                return open(self.source / relpath, "r", encoding="utf-8")

            file = open_file()
        for line in file:
            if (result := line_filter(line)) is not None:
                yield result


def _casefold_load(args) -> list[int]:
    # Load casefold data into a deltas array.
    udata = UnicodeData(args.db, args.version)
    equivalence_classes: dict[int, set[int]] = {}
    logger.debug("loading casefold data...")
    for code_str, status, mapped_codepoints_str, *_ in udata.load_file(
        Path("CaseFolding.txt")
    ):
        if status in ("C", "S"):
            # We currently only support simple casefolding
            mapped_codepoints = [int(s, 16) for s in mapped_codepoints_str.split(" ")]
            codepoint = int(code_str, 16)
            assert len(mapped_codepoints) == 1
            mapping_target = mapped_codepoints[0]
            # Combine the equivalence classes of the codepoint and the mapping target
            new_equivalence_class: set[int] = equivalence_classes.get(
                mapping_target, {mapping_target}
            ) | equivalence_classes.get(codepoint, {codepoint})
            for member in new_equivalence_class:
                # Then set each member's equivalence class to the new one
                equivalence_classes[member] = new_equivalence_class
    # For each equivalence class, map every member to the next member, or itself
    # if the class is empty
    loops = list(range(UTF_MAX + 1))
    for equivalence_class in equivalence_classes.values():
        for member, next_member in zip(
            (sort := sorted(equivalence_class)), sort[1:] + sort[:1]
        ):
            loops[member] = next_member
    return [l - i for i, l in enumerate(loops)]


def _cmd_casefold_search(args):
    # Search for optimal casefold compression schemes.
    deltas = _casefold_load(args)
    array_sizes, arrays = find_best_arrays(
        deltas,
        num_tables=args.max_arrays,
        max_rune=UTF_MAX,
    )
    check_arrays(deltas, array_sizes, arrays, max_rune=UTF_MAX)
    # output the array sizes
    print(",".join(map(str, array_sizes)))
    return 0


def _cmd_gen_casefold(args) -> int:
    # Generate C code for casefolding.
    deltas = _casefold_load(args)
    array_sizes = tuple(map(int, args.sizes.split(",")))
    logger.debug("building casefold arrays...")
    arrays = build_arrays(deltas, array_sizes)
    shifts = calculate_shifts(array_sizes)
    masks = calculate_masks(array_sizes, UTF_MAX)
    data_types = list(map(DataType.from_list, arrays))
    output, out = make_appender_func()

    def fmt_hex(n: int, data_type: DataType, num_digits: int = 0) -> str:
        return f"{'-' if n < 0 else '+' if data_type.signed else ''}0x{abs(n):0{num_digits}X}"

    for i, array in enumerate(arrays):
        num_digits = (max(map(abs, array)).bit_length() + 3) // 4
        out(f"static const {data_types[i].to_ctype()} re_compcc_fold_array_{i}[] = {{")
        out(",".join(fmt_hex(n, data_types[i], num_digits) for n in array))
        out("};")

    out("static re_s32 re_compcc_fold_next(re_u32 rune) { return ")

    def shift_mask_expr(name: str, i: int) -> str:
        shift_expr = f"({name} >> {shifts[i]})" if shifts[i] != 0 else name
        return f"({shift_expr} & 0x{masks[i]:02X})"

    for i in range(len(arrays)):
        out(f"re_compcc_fold_array_{i}[")
    for i in reversed(range(len(arrays))):
        out(f"{'+' if i != len(arrays) - 1 else ''}{shift_mask_expr('rune', i)}]")
    out(";}")

    out(
        "static int re_compcc_fold_range(re *r, re_u32 begin, re_u32 end, re_buf(re_rune_range) *cc_out) {"
    )

    types = {
        "int": ["err = 0"],
        "re_u32": ["current"] + [f"x{i}" for i in range(len(arrays))],
    }

    for i, data_type in enumerate(data_types):
        types[data_type.to_ctype()] = types.setdefault(data_type.to_ctype(), []) + [
            f"a{i}"
        ]

    for data_type, defs in sorted(types.items()):
        out(f"{data_type} {','.join(defs)};")

    out("assert(begin <= RE_UTF_MAX && end <= RE_UTF_MAX && begin <= end);")

    for i, array in reversed(list(enumerate(arrays))):
        limit = len(arrays[-1]) if i == len(array_sizes) else array_sizes[i]
        out("for (")
        out(f"  x{i} = {shift_mask_expr('begin', i)};")
        out(f"  x{i} <= 0x{limit - 1:X} && begin <= end;")
        out(f"  x{i}++")
        out(") {")
        out("if (")
        decl_name = f"a{i+1} +" if i != len(arrays) - 1 else ""
        out(f"  (a{i} = re_compcc_fold_array_{i}[{decl_name}x{i}])")
        out(f"    == {fmt_hex(arrays[i].zero_location, data_types[i])}")
        out(") {")
        out(f"  begin = ((begin >> {shifts[i]}) + 1) << {shifts[i]};")
        out("  continue;")
        out("}")

    out("current = begin + a0;")
    out("while (current != begin) {")
    out("  if ((err = re_buf_push(r, cc_out, re_rune_range_make(current, current))))")
    out("    return err;")
    out("  current = (re_u32)((re_s32)current + re_compcc_fold_next(current));")
    out("}")
    out("begin++;")

    for _ in range(len(arrays)):
        out("}")

    out("  return err;")
    out("}")

    file: IO = args.file
    insert_c_file(file, output, "gen_casefold")
    file.close()
    return 0


ASCII_CHARCLASSES: dict[str, SyntacticRanges] = {
    "alnum": (("0", "9"), ("A", "Z"), ("a", "z")),
    "alpha": (("A", "Z"), ("a", "z")),
    "ascii": ((0, 0x7F),),
    "blank": ("\t", " "),
    "cntrl": ((0, 0x1F), 0x7F),
    "digit": (("0", "9"),),
    "graph": ((0x21, 0x7E),),
    "lower": (("a", "z"),),
    "print": ((0x20, 0x7E),),
    "punct": ((0x21, 0x2F), (0x3A, 0x40), (0x5B, 0x60), (0x7B, 0x7E)),
    "space": (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20),
    "perl_space": (0x09, 0x0A, 0x0C, 0x0D, 0x20),
    "upper": (("A", "Z"),),
    "word": (("0", "9"), ("A", "Z"), ("a", "z"), "_"),
    "xdigit": (("0", "9"), ("A", "F"), ("a", "f")),
}

PERL_CHARCLASSES = {"d": "digit", "s": "perl_space", "w": "word"}


def _encode_array_deltas(arr: Iterable[int]) -> Iterator[int]:
    last = 0
    for el in arr:
        yield el - last
        last = el


def _encode_shit4(arr: Iterator[int]) -> Iterator[int]:
    prev = None
    for el in arr:
        if el == 2:
            el = 1
        elif el == 1:
            el = 2
        if el == 0:
            yield 0
        elif el == 1:
            if prev == 0:
                yield 0
            else:
                yield from [1, 0]
        else:
            if prev == 0:
                yield 1
            else:
                yield from [1, 1]
            nel = el - 2
            chunks, chunk = [], []
            while nel > 7:
                chunk = []
                for _ in range(3):
                    chunk.append(nel & 1)
                    nel >>= 1
                chunks.append(chunk)
            chunk = []
            for _ in range(3):
                chunk.append(nel & 1)
                nel >>= 1
            chunks.append(chunk)
            while len(chunks) > 1:
                yield from reversed(chunks.pop())
                yield 1
            yield from reversed(chunks.pop())
            yield 0
        prev = el


def _pack_bits_words(arr: Iterator[int]) -> Iterator[int]:
    i, idx = 0, 0
    for el in arr:
        i |= el << idx
        idx += 1
        if idx == 32:
            yield i
            idx = 0
            i = 0
    yield i


def _normalize_ords(ords: list[int]) -> Iterator[RuneRange]:
    ranges = [(o, o) for o in ords]
    norm = nranges_normalize(ranges)
    yield from norm


def _flatten_ords(ords: Iterator[RuneRange]) -> Iterator[int]:
    for l, h in ords:
        yield l
        yield h


class _BuiltinCCType(StrEnum):
    ASCII = auto()
    UNICODE_PROPERTY = auto()
    PERL = auto()


class _BuiltinCC(NamedTuple):
    cctype: _BuiltinCCType
    name: str
    ranges: tuple[RuneRange, ...]

    def encode(self) -> list[int]:
        return list(
            _pack_bits_words(
                _encode_shit4(
                    chain(iter(_encode_array_deltas(_flatten_ords(iter(self.ranges)))))
                )
            )
        )


def _gen_builtin_ccs(args) -> set[_BuiltinCC]:
    udata = UnicodeData(args.db, args.version)
    logger.debug("loading unicode property data...")
    builtin_ccs: set[_BuiltinCC] = set()
    categories: dict[str, set[int]] = {}
    for code_str, _, general_category, *_ in udata.load_file(Path("UnicodeData.txt")):
        categories[general_category] = categories.get(general_category, set())
        categories[general_category].add(int(code_str, 16))
    for category, ords in categories.items():
        builtin_ccs.add(
            _BuiltinCC(
                _BuiltinCCType.UNICODE_PROPERTY,
                category,
                tuple(_normalize_ords(sorted(ords))),
            )
        )
    for name, cc in ASCII_CHARCLASSES.items():
        builtin_ccs.add(
            _BuiltinCC(
                _BuiltinCCType.ASCII,
                name,
                tuple((nranges_normalize(list(ranges_expand(cc))))),
            )
        )
    for name, source in PERL_CHARCLASSES.items():
        builtin_ccs.add(
            _BuiltinCC(
                _BuiltinCCType.PERL,
                name,
                tuple(
                    nranges_normalize(list(ranges_expand(ASCII_CHARCLASSES[source])))
                ),
            )
        )
    return builtin_ccs


def _cmd_gen_ccs_impl(args) -> int:
    builtin_ccs = _gen_builtin_ccs(args)
    lines, out = make_appender_func()
    encoded_arr = []
    encoded_locs = {}
    for builtin_cc in sorted(builtin_ccs):
        if builtin_cc.ranges not in encoded_locs:
            encoded_locs[builtin_cc.ranges] = len(encoded_arr)
            encoded_arr.extend(builtin_cc.encode())
    num_ranges = sum([len(bcc.ranges) for bcc in builtin_ccs])
    out(
        f"/* {num_ranges} ranges, {num_ranges * 2} integers, {len(encoded_arr) * 4} bytes */"
    )
    out(f"const re_u32 re_builtin_cc_data[{len(encoded_arr)}] = {{")
    out(",".join(f"0x{e:08X}" for e in encoded_arr))
    out("};")
    for cc_type in _BuiltinCCType:
        ccs = sorted([cc for cc in builtin_ccs if cc.cctype == cc_type])
        out(f"const re_builtin_cc re_builtin_ccs_{cc_type}[{len(ccs) + 1}] = {{")
        for builtin_cc in ccs:
            out(
                f'{{ {len(builtin_cc.name)}, {len(builtin_cc.ranges)}, {encoded_locs[builtin_cc.ranges]}, "{builtin_cc.name}"}},'
            )
        out('{0, 0, 0, ""}')
        out("};")
    insert_c_file(args.file, lines, "gen_ccs impl")
    return 0


def _cmd_gen_ccs_test(args) -> int:
    builtin_ccs = _gen_builtin_ccs(args)
    tests = {}
    lines, out = make_appender_func()

    def make_test(
        test_name: str, cc: tuple[RuneRange, ...], regex: str, invert: int
    ) -> str:
        regex = '"' + regex.replace("\\", "\\\\") + '"'
        encoded_ranges = {",".join(f"0x{lo:X} 0x{hi:X}" for lo, hi in cc)}
        return f"""
        TEST({test_name}) {{
            static const re_u32 ranges[] = {{{",".join(f"0x{r:X}" for c in cc for r in c)}}};
            PROPAGATE(assert_cc_match_raw(
                {regex},
                ranges, {len(cc)}, {int(invert)}));
            PASS();
        }}
        """

    def make_suite(suite_name: str, tests: dict[str, str]) -> str:
        return f"""
            SUITE({suite_name}) {{
                {chr(0x0A).join([f"RUN_TEST({test_name});" for test_name in tests])}
            }}
            """

    for cctype in _BuiltinCCType:
        ccs = sorted([cc for cc in builtin_ccs if cc.cctype == cctype])
        tests: dict[str, str] = {}
        for cc in ccs:
            for inverted in [False, True]:
                test_name = f"cls_builtin_{cctype}_{cc.name}" + (
                    "_inverted" if inverted else ""
                )
                match cctype:
                    case _BuiltinCCType.ASCII:
                        regexp = f"[[:{'^' if inverted else ''}{cc.name}:]]"
                    case _BuiltinCCType.UNICODE_PROPERTY:
                        regexp = f"\\{'P' if inverted else 'p'}{{{cc.name}}}"
                    case _BuiltinCCType.PERL:
                        regexp = f"\\{cc.name.upper() if inverted else cc.name}"
                    case _:
                        raise ValueError("unknown cc type")
                tests[test_name] = make_test(test_name, cc.ranges, regexp, inverted)
        out("\n".join(tests.values()))
        out(make_suite(f"cls_builtin_{cctype}", tests))
    out(
        f"""SUITE(cls_builtin) {{
                {chr(0x0A).join([f"RUN_SUITE(cls_builtin_{cctype});" for cctype in _BuiltinCCType])}
            }}
            """
    )
    insert_c_file(args.file, lines, "gen_ccs test")
    return 0


def main() -> int:
    """Main method."""
    parse = argparse.ArgumentParser()
    parse.add_argument(
        "--db",
        type=Path,
        help="unicode database (either a directory or a zip file)",
        default=Path(".ucd.zip"),
    )
    parse.add_argument(
        "--debug",
        action="store_const",
        const=True,
        default=False,
        help="show debug info",
    )
    parse.add_argument(
        "--version", type=str, default="latest", help="UCD version to use"
    )

    subcmds = parse.add_subparsers(help="subcommands", required=True)
    subcmd_fetch = subcmds.add_parser("fetch", help="fetch unicode database")
    subcmd_fetch.set_defaults(func=cmd_fetch)

    subcmd_casefold_search = subcmds.add_parser(
        "casefold_search", help="search for an optimal casefold compression scheme"
    )
    subcmd_casefold_search.set_defaults(func=_cmd_casefold_search)
    subcmd_casefold_search.add_argument("--max-arrays", type=int, default=5)

    subcmd_gen_casefold = subcmds.add_parser(
        "gen_casefold", help="generate C code for casefold arrays"
    )
    subcmd_gen_casefold.set_defaults(func=_cmd_gen_casefold)
    subcmd_gen_casefold.add_argument("file", type=argparse.FileType("r+"))
    subcmd_gen_casefold.add_argument(
        "sizes", type=str, nargs="?", default="2,4,2,32,16"
    )

    subcmd_gen_ccs = subcmds.add_parser(
        "gen_ccs", help="generate code for builtin character classes"
    )
    subcmd_gen_ccs_subcmds = subcmd_gen_ccs.add_subparsers()
    subcmd_gen_ccs_impl = subcmd_gen_ccs_subcmds.add_parser("impl")
    subcmd_gen_ccs_impl.set_defaults(func=_cmd_gen_ccs_impl)
    subcmd_gen_ccs_impl.add_argument("file", type=argparse.FileType("r+"))
    subcmd_gen_ccs_test = subcmd_gen_ccs_subcmds.add_parser("test")
    subcmd_gen_ccs_test.set_defaults(func=_cmd_gen_ccs_test)
    subcmd_gen_ccs_test.add_argument("file", type=argparse.FileType("r+"))

    args = parse.parse_args()

    if args.debug:
        basicConfig(level=DEBUG)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
