"""Unicode data manager for generating tables"""

import argparse
from functools import cache
import io
from itertools import accumulate, pairwise
from pathlib import Path
from sys import stderr
from typing import Callable, Iterator, NamedTuple
import math
import shutil
import zipfile
import urllib3

UCD_URL = "https://www.unicode.org/Public/zipped"
CLEAR_TERM = "\x1b[0K"


def cmd_fetch(args):
    """Fetch the UCD."""
    http = urllib3.PoolManager()
    with http.request(
        "GET", UCD_URL + "/" + args.version + "/UCD.zip", preload_content=False
    ) as req, open(args.db, "wb") as out_file:
        shutil.copyfileobj(req, out_file)


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


UTF_MAX = 0x10FFFF


class DataType(NamedTuple):
    """Represents a C datatype."""

    size_bytes: int
    signed: bool


def data_type(arr) -> DataType:
    """Given an array of integers, determine the minimum-sized data type required."""
    max_val = max([abs(x) for x in arr])
    signed = any(x < 0 for x in arr)
    for width in [1, 2, 4]:
        if max_val < (2 ** (8 * width) - (1 if signed else 0)):
            return DataType(width, signed)
    raise ValueError(f"invalid maximum value {max_val}")


Sizes = tuple[int, ...]


def cached_make_arrays(deltas: list[int]) -> Callable[[Sizes], list[list[int]]]:
    """Return a make_arrays function that uses a cache."""

    @cache
    def make_arrays_recursive(sizes: Sizes) -> list[list[int]]:
        *prev_sizes, my_size = sizes
        arrays = (
            [deltas] if len(sizes) == 1 else make_arrays_recursive(tuple(prev_sizes))
        )
        blocks: list[Block] = list(
            list(arrays[-1][i * my_size : (i + 1) * my_size])
            for i in range(len(arrays[-1]) // my_size)
        )
        unique_blocks: dict[tuple[int, ...], int] = {}
        block_refs = []
        for block in map(tuple, blocks):
            unique_blocks[block] = (
                index := unique_blocks.get(block, len(unique_blocks))
            )
            block_refs.append(index)
        my_array, my_locs = _heuristic_squish(list(map(list, unique_blocks.keys())))
        prev_refs = list([my_locs[x] for x in block_refs])
        result = arrays[:-1] + [my_array, prev_refs]
        return result

    return make_arrays_recursive


def _combo_iterator(pow2: list[int], max_val: int, start_val=1, *, repeat: int = 0):
    # Yield permutations with repetition of `pow2` such that their product is
    # never greater than `max_val`.
    if repeat == 0:
        yield tuple()
        return
    for ipow in pow2:
        if (next_start_val := start_val * ipow) > max_val:
            continue
        for combo in _combo_iterator(pow2, max_val, next_start_val, repeat=repeat - 1):
            yield (ipow, *combo)


def _calculate_num_bytes(arrays: list[list[int]]) -> int:
    # Compute the number of bytes needed to store the resulting arrays.
    return sum(len(a) * data_type(a).size_bytes for a in arrays)


def _try_all_sizes(
    deltas: list[int], num_tables: int
) -> Iterator[tuple[int, Sizes, list[list[int]]]]:
    max_rune = UTF_MAX + 1
    pow2: list[int] = [2**x for x in range(1, max_rune.bit_length())]
    make_arrays = cached_make_arrays(deltas)
    best: int | float = math.inf
    for array_sizes in _combo_iterator(pow2, max_rune, repeat=num_tables):
        yield (
            (size := _calculate_num_bytes(arrays := make_arrays(array_sizes))),
            array_sizes,
            arrays,
        )
        best = min(best, size)
        print(
            CLEAR_TERM + f"best: {best}, sizes:",
            *array_sizes,
            sep="\t",
            end="\r",
            file=stderr,
        )
    print(file=stderr)


def _find_best_size(deltas: list[int], num_tables: int):
    # Exhaustively try bit lengths for each array.
    lowest: tuple[int, Sizes, list[list[int]]] = min(_try_all_sizes(deltas, num_tables))
    return lowest[1], lowest[2]


class Repeat(NamedTuple):
    """Represents a run of repeated leading or trailing numbers."""

    start_value: int
    repeat_count: int


Arrangement = tuple[int, ...]


class SquishSpec(NamedTuple):
    """Represents an arrangement and its squish factor."""

    squish_factor: int
    arrangement: Arrangement


class FixSpec(NamedTuple):
    """Holds lead and trail repeats."""

    leads: tuple[Repeat, ...]
    trails: tuple[Repeat, ...]

    def spec(self, arrangement: Arrangement) -> SquishSpec:
        """
        Given an arrangement of block indices, calculate the total number of
        elements saved by squishing them.
        """
        # assert all(arrangement.count(a) == 1 for a in set(arrangement))
        total_factor = 0
        for i in range(1, len(arrangement)):
            if (
                self.trails[arrangement[i]].start_value
                == self.leads[arrangement[i]].start_value
            ):
                total_factor += min(
                    self.trails[arrangement[i - 1]].repeat_count,
                    self.leads[arrangement[i]].repeat_count,
                )
        return SquishSpec(total_factor, arrangement)

    def squish(
        self, arrangement: Arrangement, blocks: list[list[int]]
    ) -> tuple[list[int], list[int]]:
        """
        Given an arrangement of block indices, and the blocks, return an array
        containing the squished blocks, and an array containing the locations
        of each block inside the squished array.
        """
        out, locations = [], []
        for i, idx in enumerate(arrangement):
            move_up = 0
            if i > 0:
                trail, lead = self.trails[arrangement[i - 1]], self.leads[idx]
                move_up = (
                    min(trail.repeat_count, lead.repeat_count)
                    if trail.start_value == lead.start_value
                    else 0
                )
            locations.append(len(out) - move_up)
            out.extend(blocks[idx][move_up:])
        return out, locations


def _find_start_indices(fix: FixSpec) -> SquishSpec:
    # Find the pair of indexes that have the best squished size.
    return max(
        fix.spec((i, j))
        for i in range(len(fix.leads))
        for j in range(len(fix.trails))
        if i != j
    )


def _find_best_prepend(fix: FixSpec, spec: SquishSpec) -> SquishSpec:
    # Find the index that, when prepended to the arrangement, has the best
    # squished size.
    return max(
        fix.spec((i, *spec.arrangement))
        for i in range(len(fix.trails))
        if i not in spec.arrangement
    )


def _find_best_append(fix: FixSpec, spec: SquishSpec) -> SquishSpec:
    # Find the index that, when appended to the arrangement, has the best
    # squished size.
    return max(
        fix.spec((*spec.arrangement, i))
        for i in range(len(fix.trails))
        if i not in spec.arrangement
    )


def _heuristic_squish_loop(fix: FixSpec, spec: SquishSpec) -> SquishSpec:
    if len(spec.arrangement) == len(fix.leads):
        # we are done if we've added every block to the working list
        return fix.spec(spec.arrangement)
    if len(fix.leads) == 1:
        return fix.spec((0,))
    if len(spec.arrangement) == 0:
        # initial block, find the two blocks that fit best
        return _find_start_indices(fix)
    else:
        # check whether to prepend or append
        return max(
            _find_best_prepend(fix, spec),
            _find_best_append(fix, spec),
        )


def _heuristic_squish_slice(fix: FixSpec, spec: SquishSpec) -> SquishSpec:
    # Find an index in the arrangement that results in a better squish after
    # transposing both resulting partitions of the arrangement aroudnd the index
    return max(
        fix.spec(
            spec.arrangement[slice_index:] + spec.arrangement[:slice_index],
        )
        for slice_index in range(len(fix.leads))
    )


def _heuristic_squish_swap(fix: FixSpec, spec: SquishSpec) -> SquishSpec:
    # Find two indices that, when their values are swapped, results in a better
    # squish.
    if len(fix.leads) == 1:
        return spec
    return max(
        fix.spec(
            (
                *spec.arrangement[:i],
                spec.arrangement[i],
                *spec.arrangement[i + 1 : j],
                spec.arrangement[j],
                *spec.arrangement[j + 1 :],
            ),
        )
        for i in range(len(fix.leads))
        for j in range(i + 1, len(fix.leads))
    )


Block = list[int]


def _calculate_leading(l: Block) -> Repeat:
    # Given an array, calculate the number of times its first member is
    # subsequently repeated.
    for i, x in enumerate(l):
        if x != l[0]:
            return Repeat(l[0], i)
    return Repeat(l[0], len(l))


def _calculate_trailing(l: Block) -> Repeat:
    # Given an array, calculate the number of times its last member is
    # repeated precedingly.
    for i, x in enumerate(reversed(l)):
        if x != l[-1]:
            return Repeat(l[-1], i)
    return Repeat(l[0], len(l))


def _improve_squish(
    fix: FixSpec,
    best_spec: SquishSpec,
    map_func: Callable[[FixSpec, SquishSpec], SquishSpec],
) -> SquishSpec:
    while True:
        next_spec = map_func(fix, best_spec)
        if next_spec.squish_factor > best_spec.squish_factor or len(
            next_spec.arrangement
        ) > len(best_spec.arrangement):
            best_spec = next_spec
        else:
            break
    return best_spec


def _heuristic_squish(blocks: list[Block]) -> tuple[list[int], list[int]]:
    fix = FixSpec(
        tuple(map(_calculate_leading, blocks)), tuple(map(_calculate_trailing, blocks))
    )
    best_spec = SquishSpec(0, ())
    for func in (
        _heuristic_squish_loop,
        _heuristic_squish_slice,
        _heuristic_squish_swap,
    ):
        best_spec = _improve_squish(fix, best_spec, func)
    array, locs = fix.squish(best_spec.arrangement, blocks)
    locs = list(map(lambda a: a[1], sorted(zip(best_spec.arrangement, locs))))
    return (array, locs)


def _check_arrays(
    deltas: list[int],
    array_sizes: Sizes,
    arrays: list[list[int]],
    max_rune=UTF_MAX,
):
    field_widths = map(int, map(math.log2, array_sizes))
    shifts = [0] + list(accumulate(field_widths))
    masks = [
        (2 ** (h - l) - 1) for l, h in pairwise(shifts + [(max_rune + 1).bit_length()])
    ]

    def lookup(start_index, rune, level=len(arrays) - 1):
        index = (rune >> shifts[level]) & masks[level]
        next_index = arrays[level][start_index + index]
        return lookup(next_index, rune, level - 1) if level != 0 else next_index

    for rune in range(max_rune + 1):
        print(CLEAR_TERM + "checking: ", rune, file=stderr, sep="\t", end="\r")
        assert lookup(0, rune) == deltas[rune]
    print(file=stderr)


def cmd_make_casefold_data(args):
    """Generate casefold data."""
    udata = UnicodeData(args.db)
    equivalence_classes: dict[int, set[int]] = {}
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
    deltas = [l - i for i, l in enumerate(loops)]
    if args.sizes is None:
        array_sizes, arrays = _find_best_size(deltas, args.explore_amt)
    else:
        array_sizes = (
            tuple(int(x) for x in args.sizes.split(",")) if args.sizes != "" else ()
        )
        arrays = cached_make_arrays(deltas)(array_sizes)
    print("using array sizes", ",".join(map(str, array_sizes)), file=stderr)
    _check_arrays(deltas, array_sizes, arrays)


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

    parse_cmds = parse.add_subparsers(help="subcommands", required=True)
    parse_cmd_fetch = parse_cmds.add_parser("fetch", help="fetch unicode database")
    parse_cmd_fetch.set_defaults(func=cmd_fetch)
    parse_cmd_fetch.add_argument("--version", type=str, default="latest")

    parse_cmd_make_casefold = parse_cmds.add_parser(
        "make_casefold_data", help="make casefolding data"
    )
    parse_cmd_make_casefold.set_defaults(func=cmd_make_casefold_data)
    parse_cmd_make_casefold.add_argument("--explore", action="store_true")
    parse_cmd_make_casefold.add_argument("--explore-amt", type=int)
    parse_cmd_make_casefold.add_argument("--sizes", type=str)

    args = parse.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
