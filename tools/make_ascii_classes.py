from argparse import ArgumentParser, Namespace
from typing import Iterator


ASCII_CHARCLASSES = {
    "alnum": [["0", "9"], ["A", "Z"], ["a", "z"]],
    "alpha": [["A", "Z"], ["a", "z"]],
    "ascii": [[0, 0x7F]],
    "blank": ["\t", " "],
    "cntrl": [[0, 0x1F], 0x7F],
    "digit": [["0", "9"]],
    "graph": [[0x21, 0x7E]],
    "lower": [["a", "z"]],
    "print": [[0x20, 0x7E]],
    "punct": [[0x21, 0x2F], [0x3A, 0x40], [0x5B, 0x60], [0x7B, 0x7E]],
    "space": [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20],
    "perl_space": [0x09, 0x0A, 0x0C, 0x0D, 0x20],
    "upper": [["A", "Z"]],
    "word": [["0", "9"], ["A", "Z"], ["a", "z"], "_"],
    "xdigit": [["0", "9"], ["A", "F"], ["a", "f"]],
}

PERL_CHARCLASSES = {
    "D": ("digit", True),
    "d": ("digit", False),
    "S": ("perl_space", True),
    "s": ("perl_space", False),
    "W": ("word", True),
    "w": ("word", False),
}

Range = tuple[str | int, str | int] | str | int
NRange = tuple[int, int]

Ranges = list[Range]
NRanges = list[NRange]


def expand(r: Ranges) -> Iterator[NRange]:
    for range in r:
        if isinstance(range, int):
            yield [range, range]
        elif isinstance(range, str):
            yield [ord(range), ord(range)]
        else:
            if isinstance(range[0], str):
                range[0] = ord(range[0])
            if isinstance(range[1], str):
                range[1] = ord(range[1])
            yield range


def normalize(r: NRanges) -> Iterator[NRange]:
    min, max = None, None
    for i, (cur_min, cur_max) in enumerate(r):
        if i == 0:
            min, max = cur_min, cur_max
        elif cur_min <= max + 1:
            max = cur_max if cur_max > max else max
        else:
            yield min, max
            min, max = cur_min, cur_max
    if None not in (min, max):
        yield min, max


def invert(r: NRanges, utf_max=0x10FFFF) -> Iterator[NRange]:
    max = 0
    for cur_min, cur_max in r:
        if cur_min > max:
            yield max, cur_min - 1
            max = cur_max + 1
    if cur_max < utf_max:
        yield cur_max + 1, utf_max


def cmd_impl(args: Namespace) -> int:
    for name, cc in ASCII_CHARCLASSES.items():
        normalized = list((normalize(expand(cc))))
        serialized = "".join(f"\\x{lo:02X}\\x{hi:02X}" for lo, hi in normalized)
        print(f'{{{len(name)}, {len(normalized)}, "{name}", "{serialized}"}},')
    return 0


def make_test(test_name: str, cc: NRanges, regex: str) -> str:
    regex = '"' + regex.replace("\\", "\\\\") + '"'
    return f"""
    TEST({test_name}) {{
        return assert_cc_match({regex}, "{','.join(f"0x{lo:X} 0x{hi:X}" for lo, hi in normalize(expand(cc)))}");
    }}
    """


def make_suite(suite_name: str, tests: dict[str, str]) -> str:
    return f"""
        SUITE({suite_name}) {{
            {'\n'.join([f"RUN_TEST({test_name});" for test_name in tests])}
        }}
        """


def cmd_tests(args: Namespace) -> int:
    tests = {}
    print('#include "../mptest/_cpack/mptest.h"')
    print("mptest__result assert_cc_match(const char *regex, const char *spec);")
    # named charclasses
    for name, cc in ASCII_CHARCLASSES.items():
        test_name = f"cls_named_{name}"
        regex = f"[[:{name}:]]"
        tests[test_name] = make_test(test_name, cc, regex)
    print("\n".join(tests.values()))
    print(make_suite("cls_named", tests))
    tests = {}
    # Perl charclasses
    for ch, (name, inverted) in PERL_CHARCLASSES.items():
        test_name = f"escape_perlclass_{ch}"
        regex = f"\\{ch}"
        cc = normalize(expand(ASCII_CHARCLASSES[name]))
        if inverted:
            cc = invert(cc)
        tests[test_name] = make_test(test_name, cc, regex)
    print("\n".join(tests.values()))
    print(make_suite("escape_perlclass", tests))
    return 0


if __name__ == "__main__":
    ap = ArgumentParser()
    parsers = ap.add_subparsers(dest="command", required=True)
    parser_impl = parsers.add_parser("impl")
    parser_impl.set_defaults(func=cmd_impl)

    parser_tests = parsers.add_parser("tests")
    parser_tests.set_defaults(func=cmd_tests)

    args = ap.parse_args()
    exit(args.func(args))
