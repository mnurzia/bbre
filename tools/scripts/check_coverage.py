from argparse import ArgumentParser, FileType
from sys import stdin
import re
from pathlib import Path
from typing import Counter

from util import FileWarning

HIT_REGEX = r"(FNF|FNH|BRF|BRH|LF|LH):(\d*)"
TEST_FN_REGEX = r"FNDA:(\d*),(.*)"
TEST_FN_LINE_REGEX = r"FN:(\d*),\d*,(.*)"
BASE_DIRECTORY = Path(__file__).parent.parent.parent

if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument(
        "lcov_info",
        help="lcov.info source",
        type=FileType("r"),
        default=stdin,
        nargs="?",
    )
    args = ap.parse_args()

    files = {}

    cur_sect = None
    for line in args.lcov_info.readlines():
        if sect_name_match := re.match("SF:(.*)", line):
            cur_sect = Path(sect_name_match[1]).relative_to(BASE_DIRECTORY)
        if line == "end_of_record":
            cur_sect = None
        if cur_sect is None:
            continue
        files[cur_sect] = files.get(cur_sect, []) + [line]

    warnings: list[FileWarning] = []

    impl_hit_counts = {
        directive: int(num)
        for directive, num in re.findall(HIT_REGEX, "".join(files[Path("bbre.c")]))
    }

    for code, name in [("FN", "functions"), ("BR", "branches"), ("L", "lines")]:
        if (hit := impl_hit_counts[code + "H"]) != (
            found := impl_hit_counts[code + "F"]
        ):
            warnings.append(
                FileWarning(Path("bbre.c"), 0, 0, f"not all {name} hit ({hit}/{found})")
            )

    for test_file in [Path("tools/test.c"), Path("tools/test_gen.c")]:
        fn_lines = {
            name: int(line)
            for line, name in re.findall(TEST_FN_LINE_REGEX, "".join(files[test_file]))
        }
        fn_hit_counts = {
            name: int(count)
            for count, name in re.findall(TEST_FN_REGEX, "".join(files[test_file]))
        }

        for name, count in fn_hit_counts.items():
            if count == 0 and "test" in name:
                warnings.append(
                    FileWarning(
                        test_file, fn_lines[name], 0, f"test {name} is never run"
                    )
                )

    FileWarning.exit_with(warnings)
