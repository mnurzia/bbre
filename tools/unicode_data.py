"""Unicode data manager for generating tables"""

import argparse
import io
from pathlib import Path
from sys import stderr
from typing import IO, Callable, Iterator
import shutil
import zipfile
import urllib3

from squish_casefold import (
    calculate_masks,
    calculate_shifts,
    check_arrays,
    find_best_arrays,
    build_arrays,
)
from util import DataType

UCD_URL = "https://www.unicode.org/Public/zipped"
CLEAR_TERM = "\x1b[0K"

UTF_MAX = 0x10FFFF


class UnicodeData:
    """Manages a UCD and performs simple file retrieval/parsing."""

    def __init__(self, path: Path):
        self.source: zipfile.ZipFile | Path = (
            zipfile.ZipFile(path) if path.name.endswith(".zip") else path
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
            file = open(self.source / relpath, "r", encoding="utf-8")
        for line in file:
            if (result := line_filter(line)) is not None:
                yield result


def cmd_fetch(args):
    """Fetch the UCD."""
    http = urllib3.PoolManager()
    with http.request(
        "GET", UCD_URL + "/" + args.version + "/UCD.zip", preload_content=False
    ) as req, open(args.db, "wb") as out_file:
        shutil.copyfileobj(req, out_file)
    return 0


def _casefold_load(args) -> list[int]:
    # Load casefold data into a deltas array.
    udata = UnicodeData(args.db)
    equivalence_classes: dict[int, set[int]] = {}
    if args.debug:
        print("loading casefold data...", file=stderr)
    for code_str, status, mapped_codepoints_str, *_ in udata.load_file(
        Path("CaseFolding.txt")
    ):
        if status == "C" or status == "S":
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
        show_progress=args.debug,
    )
    check_arrays(
        deltas, array_sizes, arrays, max_rune=UTF_MAX, show_progress=args.debug
    )
    # output the array sizes
    print(",".join(map(str, array_sizes)))
    return 0


def _insert_c_file(file: IO, insert_lines: list[str], tag: str):
    lines = file.readlines()
    start_tag, end_tag = (
        f"/*{t} Generated by `unicode_data.py {tag}` */\n" for t in "Tt"
    )
    start_index, end_index = map(lines.index, (start_tag, end_tag))
    assert end_index > start_index  # if this fails, end tag was after start tag
    file.seek(0)
    file.truncate(0)
    file.writelines(lines[: start_index + 1] + insert_lines + lines[end_index:])


def _cmd_gen_casefold(args) -> int:
    # Generate C code for casefolding.
    deltas = _casefold_load(args)
    array_sizes = tuple(map(int, args.sizes.split(",")))
    arrays = build_arrays(deltas, array_sizes)
    shifts = calculate_shifts(array_sizes)
    masks = calculate_masks(array_sizes, UTF_MAX)
    output: list[str] = []

    def out(s: str):
        output.append(s + "\n")

    for i, array in enumerate(arrays):
        num_digits = (max(map(abs, array)).bit_length() + 3) // 4
        data_type = DataType.from_list(array)
        out(f"static const {data_type.to_ctype()} casefold_array_{i}[] = {{")
        out(
            ",".join(
                [
                    f"{'-' if n < 0 else '+' if data_type.signed else ''}0x{abs(n):0{num_digits}X}"
                    for n in array
                ]
            )
        )
        out("};")

    out("u32 casefold_next(u32 rune) { return ")

    for i in range(len(arrays)):
        out(f"casefold_array_{i}[")
    for i, (shift, mask) in enumerate(reversed(list(zip(shifts, masks)))):
        shift_expr = f"rune >> {shift}" if shift != 0 else "rune"
        out(f"{'+' if i else ''}(({shift_expr}) & 0x{mask:02X})]")
    out(";}")

    file: IO = args.file
    _insert_c_file(file, output, "gen_casefold")
    file.close()
    return 0


_Range = tuple[str | int, str | int] | str | int
_NRange = tuple[int, int]

_Ranges = tuple[_Range, ...]
_NRanges = list[_NRange]

ASCII_CHARCLASSES: dict[str, _Ranges] = {
    "alnum": (("0", "9"), ("A", "Z"), ("a", "z")),
    "alpha": (("A", "Z"), ("a", "z")),
    "ascii": ((0, 0x7F)),
    "blank": ("\t", " "),
    "cntrl": ((0, 0x1F), 0x7F),
    "digit": (("0", "9")),
    "graph": ((0x21, 0x7E)),
    "lower": (("a", "z")),
    "print": ((0x20, 0x7E)),
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


def _ranges_expand(r: _Ranges) -> Iterator[_NRange]:
    for range_expr in r:
        if isinstance(range_expr, int):
            yield (range_expr, range_expr)
        elif isinstance(range_expr, str):
            yield (ord(range_expr), ord(range_expr))
        else:
            start, end = range_expr
            if isinstance(start, str):
                start = ord(start)
            if isinstance(end, str):
                end = ord(end)
            yield (start, end)


def _nranges_normalize(r: _NRanges) -> Iterator[_NRange]:
    local_min: int | None = None
    local_max: int | None = None
    for i, (cur_min, cur_max) in enumerate(r):
        if i == 0:
            local_min, local_max = cur_min, cur_max
            continue
        assert local_min is not None and local_max is not None
        if cur_min <= local_max + 1:
            local_max = cur_max if cur_max > local_max else local_max
        else:
            yield local_min, local_max
            local_min, local_max = cur_min, cur_max
    if local_min is not None and local_max is not None:
        yield local_min, local_max


def _nranges_invert(r: _NRanges, max_rune: int) -> Iterator[_NRange]:
    local_max = 0
    cur_max = -1
    for cur_min, cur_max in r:
        if cur_min > local_max:
            yield local_max, cur_min - 1
            local_max = cur_max + 1
    if cur_max < max_rune:
        yield cur_max + 1, max_rune


def _cmd_gen_ascii_charclasses_impl(args) -> int:
    out_lines = ["const ccdef builtin_cc[] = {\n"]
    for name, cc in ASCII_CHARCLASSES.items():
        normalized = list((_nranges_normalize(list(_ranges_expand(cc)))))
        serialized = "".join(f"\\x{lo:02X}\\x{hi:02X}" for lo, hi in normalized)
        out_lines.append(
            f'{{{len(name)}, {len(normalized)}, "{name}", "{serialized}"}},\n'
        )
    out_lines.append("{0},};\n")
    file: IO = args.file
    _insert_c_file(file, out_lines, "gen_ascii_charclasses impl")
    file.close()
    return 0


def _cmd_gen_ascii_charclasses_test(args) -> int:
    tests = {}
    output: list[str] = []

    def out(s: str):
        output.append(s + "\n")

    def make_test(test_name: str, cc: _Ranges, regex: str) -> str:
        regex = '"' + regex.replace("\\", "\\\\") + '"'
        return f"""
        TEST({test_name}) {{
            return assert_cc_match(
                {regex},
                "{','.join(f"0x{lo:X} 0x{hi:X}"
                           for lo, hi in _nranges_normalize(list(_ranges_expand(cc))))}");
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
        regex = f"[[:{name}:]]"
        tests[test_name] = make_test(test_name, cc, regex)
    out("\n".join(tests.values()))
    out(make_suite("cls_named", tests))
    tests = {}
    # Perl charclasses
    for ch, (name, inverted) in PERL_CHARCLASSES.items():
        test_name = f"escape_perlclass_{ch}"
        regex = f"\\{ch}"
        cc = _nranges_normalize(list(_ranges_expand(ASCII_CHARCLASSES[name])))
        if inverted:
            cc = _nranges_invert(list(cc), UTF_MAX)
        tests[test_name] = make_test(test_name, tuple(cc), regex)
    out("\n".join(tests.values()))
    out(make_suite("escape_perlclass", tests))

    _insert_c_file(args.file, output, "gen_ascii_charclasses test")
    return 0


def main():
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

    subcmds = parse.add_subparsers(help="subcommands", required=True)
    subcmd_fetch = subcmds.add_parser("fetch", help="fetch unicode database")
    subcmd_fetch.set_defaults(func=cmd_fetch)
    subcmd_fetch.add_argument("--version", type=str, default="latest")

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

    args = parse.parse_args()
    exit(args.func(args))


if __name__ == "__main__":
    main()
