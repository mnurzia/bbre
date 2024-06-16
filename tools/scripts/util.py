"""Utilities for the tools folder."""

from subprocess import run
from typing import IO, Iterator, NamedTuple, Protocol

UTF_MAX = 0x10FFFF


class DataType(NamedTuple):
    """Represents a C datatype."""

    size_bytes: int
    signed: bool

    @staticmethod
    def from_int(i: int, signed: bool) -> "DataType":
        """Given an integer, determine the minimum-sized data type required."""
        for width in [1, 2, 4]:
            if i < (2 ** ((8 * width) - (1 if signed else 0))):
                return DataType(width, signed)
        raise ValueError("value out of range")

    @staticmethod
    def from_list(l: list[int]) -> "DataType":
        """Given an array of integers, determine the minimum-sized data type required."""
        return DataType.from_int(max(abs(x) for x in l), any(x < 0 for x in l))

    def to_ctype(self) -> str:
        """Return the C type name for this datatype."""
        return f"bbre_{'s' if self.signed else 'u'}{8 * self.size_bytes}"


def _find_tags(lines: list[str], start_tag: str, end_tag: str | None):
    start_index = lines.index(start_tag + "\n")
    end_index = (
        lines.index(end_tag + "\n", start_index) if end_tag is not None else len(lines)
    )
    return start_index, end_index


def extract_between_tags(lines: list[str], start_tag: str, end_tag: str) -> list[str]:
    """Extract lines between the two tags."""
    start_index, end_index = _find_tags(lines, start_tag, end_tag)
    return [l.rstrip("\n") for l in lines[start_index + 1 : end_index]]


def insert_file(file: IO, insert_lines: list[str], start_tag: str, end_tag: str | None):
    """
    Search for a tagged begin/end string pair in the given file, and insert the
    given lines between those tags.
    """
    lines = file.readlines()
    start_index, end_index = _find_tags(lines, start_tag, end_tag)
    file.seek(0)
    file.truncate(0)
    file.writelines(lines[: start_index + 1] + insert_lines + lines[end_index:])


def insert_c_file(
    file: IO, insert_lines: list[str], tag: str, *, file_name="unicode_data.py"
):
    """
    Search for a standard tag pair in the given file, and insert contents between this pair.
    """
    insert_file(
        file,
        insert_lines,
        *(f"/*{t} Generated by `{file_name} {tag}` */" for t in "{}"),
    )


SyntacticRange = tuple[str | int, str | int] | str | int
RuneRange = tuple[int, int]

SyntacticRanges = tuple[SyntacticRange, ...]
RuneRanges = list[RuneRange]

ByteRange = tuple[int, int]


def ranges_expand(r: SyntacticRanges) -> Iterator[RuneRange]:
    """
    Convert syntactic ranges to pairs of (unnormalized) ranges.
    """
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


def nranges_normalize(r: RuneRanges) -> Iterator[RuneRange]:
    """
    Normalize a list of pairs of ranges.
    """
    local_min: int | None = None
    local_max: int | None = None
    for i, (cur_min, cur_max) in enumerate(sorted(r)):
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


def nranges_invert(r: RuneRanges, max_rune: int = UTF_MAX) -> Iterator[RuneRange]:
    """
    Invert a normalized list of ranges.
    """
    local_max = 0
    cur_max = -1
    for cur_min, cur_max in r:
        if cur_min > local_max:
            yield local_max, cur_min - 1
            local_max = cur_max + 1
    if cur_max < max_rune:
        yield cur_max + 1, max_rune


def nrange_isect(r1: RuneRange, r2: RuneRange) -> bool:
    """
    Check if two ranges intersect.
    """
    return r1[0] <= r2[1] and r2[0] <= r1[1]


def get_commit_hash() -> str:
    """Get the commit hash of the current Git repository."""
    return run(
        ["git", "rev-parse", "HEAD"], captubbreoutput=True, encoding="utf-8", check=True
    ).stdout.strip()


class _Appender(Protocol):
    def __call__(self, *args: str, suffix: str = "\n"): ...


def make_appender_func() -> tuple[list[str], _Appender]:
    """Convenience function to make a line builder."""
    array = []

    def out(*s: str, suffix: str = "\n"):
        array.extend([x + suffix for x in s])

    return array, out