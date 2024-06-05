"""Unicode data manager for generating tables"""

import argparse
import io
from logging import DEBUG, basicConfig, getLogger
from pathlib import Path
import sys
from typing import IO, Any, Callable, Iterator, Iterable
import shutil
from urllib.request import urlopen
import zipfile
from itertools import chain, groupby

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
        return f"({f"({name} >> {shifts[i]})" if shifts[i] != 0 else name} & 0x{masks[i]:02X})"

    for i in range(len(arrays)):
        out(f"re_compcc_fold_array_{i}[")
    for i in reversed(range(len(arrays))):
        out(f"{'+' if i != len(arrays) - 1 else ''}{shift_mask_expr("rune", i)}]")
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
        out(f"  x{i} = {shift_mask_expr("begin", i)};")
        out(f"  x{i} <= 0x{limit - 1:X} && begin <= end;")
        out(f"  x{i}++")
        out(") {")
        out("if (")
        out(
            f"  (a{i} = re_compcc_fold_array_{i}[{f"a{i+1} +" if i != len(arrays) - 1 else ""}x{i}])"
        )
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
    "digit": (("0", "9")),
    "graph": ((0x21, 0x7E)),
    "lower": (("a", "z")),
    "print": ((0x20, 0x7E),),
    "punct": ((0x21, 0x2F), (0x3A, 0x40), (0x5B, 0x60), (0x7B, 0x7E)),
    "space": (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20),
    "perl_space": (0x09, 0x0A, 0x0C, 0x0D, 0x20),
    "upper": (("A", "Z")),
    "word": (("0", "9"), ("A", "Z"), ("a", "z"), "_"),
    "xdigit": (("0", "9"), ("A", "F"), ("a", "f")),
}

PERL_CHARCLASSES = {
    "D": ("digit", True),
    "d": ("digit", False),
    "S": ("perl_space", True),
    "s": ("perl_space", False),
    "W": ("word", True),
    "w": ("word", False),
}


def _cmd_gen_ascii_charclasses_impl(args) -> int:
    out_lines = [
        f"static const re_parse_builtin_cc re_parse_builtin_ccs[{len(ASCII_CHARCLASSES)}] = {{\n"
    ]
    for name, cc in ASCII_CHARCLASSES.items():
        normalized = list((nranges_normalize(list(ranges_expand(cc)))))
        serialized = "".join(f"\\x{lo:02X}\\x{hi:02X}" for lo, hi in normalized)
        out_lines.append(
            f'{{{len(name)}, {len(normalized)}, "{name}", "{serialized}"}},\n'
        )
    out_lines.append("};\n")
    file: IO = args.file
    insert_c_file(file, out_lines, "gen_ascii_charclasses impl")
    file.close()
    return 0


def _cmd_gen_ascii_charclasses_test(args) -> int:
    tests = {}
    output, out = make_appender_func()

    def make_test(test_name: str, cc: SyntacticRanges, regex: str, invert: int) -> str:
        regex = '"' + regex.replace("\\", "\\\\") + '"'
        return f"""
        TEST({test_name}) {{
            PROPAGATE(assert_cc_match(
                {regex},
                "{','.join(f"0x{lo:X} 0x{hi:X}"
                           for lo, hi in nranges_normalize(list(ranges_expand(cc))))}", {invert}));
            PASS();
        }}
        """

    def make_suite(suite_name: str, tests: dict[str, str]) -> str:
        return f"""
            SUITE({suite_name}) {{
                {'\n'.join([f"RUN_TEST({test_name});" for test_name in tests])}
            }}
            """

    # named charclasses
    for name, cc in ASCII_CHARCLASSES.items():
        test_name = f"cls_named_{name}"
        tests[test_name] = make_test(test_name, cc, f"[[:{name}:]]", 0)
        tests[test_name + "_invert"] = make_test(
            test_name + "_invert", cc, f"[[:^{name}:]]", 1
        )

    out("\n".join(tests.values()))
    out(make_suite("cls_named", tests))
    tests = {}
    # Perl charclasses
    for ch, (name, inverted) in PERL_CHARCLASSES.items():
        test_name = f"escape_perlclass_{ch}"
        regex = f"\\{ch}"
        cc = nranges_normalize(list(ranges_expand(ASCII_CHARCLASSES[name])))
        if inverted:
            cc = nranges_invert(list(cc), UTF_MAX)
        tests[test_name] = make_test(test_name, tuple(cc), regex, 0)
    out("\n".join(tests.values()))
    out(make_suite("escape_perlclass", tests))

    insert_c_file(args.file, output, "gen_ascii_charclasses test")
    return 0


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


def _cmd_gen_props(args) -> int:
    udata = UnicodeData(args.db, args.version)
    logger.debug("loading casefold data...")
    categories: dict[str, set[int]] = {}
    for code_str, _, general_category, *_ in udata.load_file(Path("UnicodeData.txt")):
        categories[general_category] = categories.get(general_category, set())
        categories[general_category].add(int(code_str, 16))
    uncompressed = {
        cat: list(_normalize_ords(sorted(ords))) for cat, ords in categories.items()
    }
    shit = {
        cat: list(
            _encode_shit4(
                chain(iter(_encode_array_deltas(_flatten_ords(iter(norm))))),
            )
        )
        for cat, norm in uncompressed.items()
    }
    encoded = {cat: list(_pack_bits_words(iter(ords))) for cat, ords in shit.items()}
    lines, out = make_appender_func()
    encoded_arr = []
    encoded_locs = {}
    for cat, encoding in sorted(encoded.items()):
        encoded_locs[cat] = len(encoded_arr)
        encoded_arr.extend(encoding)
    num_ranges = sum(map(len, uncompressed.values()))
    out(
        f"/* {num_ranges} ranges, {num_ranges * 2} integers, {len(encoded_arr) * 4} bytes */"
    )
    out(f"const re_u32 re_utf8_prop_data[{len(encoded_arr)}] = {{")
    out(",".join(f"0x{e:08X}" for e in encoded_arr))
    out("};")
    out(f"const re_utf8_prop re_utf8_props[{len(encoded)}] = {{")
    for cat in sorted(encoded):
        out(f'{{ {len(cat)}, {len(uncompressed[cat])}, {encoded_locs[cat]}, "{cat}"}},')
    out("};")
    insert_c_file(args.file, lines, "gen_props")
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

    subcmd_gen_ascii_charclasses = subcmds.add_parser(
        "gen_ascii_charclasses", help="generate ascii character classes"
    )
    subcmd_gen_ascii_charclasses_subcmds = subcmd_gen_ascii_charclasses.add_subparsers()
    subcmd_gen_ascii_charclasses_subcmd_impl = (
        subcmd_gen_ascii_charclasses_subcmds.add_parser("impl")
    )
    subcmd_gen_ascii_charclasses_subcmd_impl.add_argument(
        "file", type=argparse.FileType("r+")
    )
    subcmd_gen_ascii_charclasses_subcmd_impl.set_defaults(
        func=_cmd_gen_ascii_charclasses_impl
    )

    subcmd_gen_ascii_charclasses_subcmd_test = (
        subcmd_gen_ascii_charclasses_subcmds.add_parser("test")
    )
    subcmd_gen_ascii_charclasses_subcmd_test.set_defaults(
        func=_cmd_gen_ascii_charclasses_test
    )
    subcmd_gen_ascii_charclasses_subcmd_test.add_argument(
        "file", type=argparse.FileType("r+")
    )

    subcmd_gen_prop = subcmds.add_parser(
        "gen_props", help="generate C code for property arrays"
    )
    subcmd_gen_prop.set_defaults(func=_cmd_gen_props)
    subcmd_gen_prop.add_argument("file", type=argparse.FileType("r+"))
    args = parse.parse_args()

    if args.debug:
        basicConfig(level=DEBUG)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
