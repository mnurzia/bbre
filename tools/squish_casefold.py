"""Algorithms for compressing sparse Unicode casefold data"""

from functools import cache
from itertools import accumulate, pairwise
from math import log2
from sys import stderr
from typing import Callable, Iterator, NamedTuple

from util import DataType

# A list of block sizes.
_Sizes = tuple[int, ...]
# A block within a compressed array.
_Block = list[int]
# A list of block indices that specify the squish order of the bl
_Arrangement = tuple[int, ...]


class _Repeat(NamedTuple):
    # Represents a run of repeated leading or trailing numbers.

    start_value: int
    repeat_count: int


class _SquishSpec(NamedTuple):
    # Represents an arrangement and its squish factor.

    squish_factor: int
    arrangement: _Arrangement


class _FixSpec(NamedTuple):
    # Holds lead and trail repeats.

    leads: tuple[_Repeat, ...]
    trails: tuple[_Repeat, ...]

    def spec(self, arrangement: _Arrangement) -> _SquishSpec:
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
        return _SquishSpec(total_factor, arrangement)

    def squish(
        self, arrangement: _Arrangement, blocks: list[list[int]]
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


def _find_start_indices(fix: _FixSpec) -> _SquishSpec:
    # Find the pair of indexes that have the best squished size.
    return max(
        fix.spec((i, j))
        for i in range(len(fix.leads))
        for j in range(len(fix.trails))
        if i != j
    )


def _find_best_prepend(fix: _FixSpec, spec: _SquishSpec) -> _SquishSpec:
    # Find the index that, when prepended to the arrangement, has the best
    # squished size.
    return max(
        fix.spec((i, *spec.arrangement))
        for i in range(len(fix.trails))
        if i not in spec.arrangement
    )


def _find_best_append(fix: _FixSpec, spec: _SquishSpec) -> _SquishSpec:
    # Find the index that, when appended to the arrangement, has the best
    # squished size.
    return max(
        fix.spec((*spec.arrangement, i))
        for i in range(len(fix.trails))
        if i not in spec.arrangement
    )


def _heuristic_squish_loop(fix: _FixSpec, spec: _SquishSpec) -> _SquishSpec:
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


def _heuristic_squish_slice(fix: _FixSpec, spec: _SquishSpec) -> _SquishSpec:
    # Find an index in the arrangement that results in a better squish after
    # transposing both resulting partitions of the arrangement aroudnd the index
    return max(
        fix.spec(
            spec.arrangement[slice_index:] + spec.arrangement[:slice_index],
        )
        for slice_index in range(len(fix.leads))
    )


def _heuristic_squish_swap(fix: _FixSpec, spec: _SquishSpec) -> _SquishSpec:
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


def _calculate_leading(l: _Block) -> _Repeat:
    # Given an array, calculate the number of times its first member is
    # subsequently repeated.
    for i, x in enumerate(l):
        if x != l[0]:
            return _Repeat(l[0], i)
    return _Repeat(l[0], len(l))


def _calculate_trailing(l: _Block) -> _Repeat:
    # Given an array, calculate the number of times its last member is
    # repeated precedingly.
    for i, x in enumerate(reversed(l)):
        if x != l[-1]:
            return _Repeat(l[-1], i)
    return _Repeat(l[0], len(l))


def _improve_squish(
    fix: _FixSpec,
    best_spec: _SquishSpec,
    map_func: Callable[[_FixSpec, _SquishSpec], _SquishSpec],
) -> _SquishSpec:
    while True:
        next_spec = map_func(fix, best_spec)
        if next_spec.squish_factor > best_spec.squish_factor or len(
            next_spec.arrangement
        ) > len(best_spec.arrangement):
            best_spec = next_spec
        else:
            break
    return best_spec


def _heuristic_squish(blocks: list[_Block]) -> tuple[list[int], list[int]]:
    fix = _FixSpec(
        tuple(map(_calculate_leading, blocks)), tuple(map(_calculate_trailing, blocks))
    )
    best_spec = _SquishSpec(0, ())
    for func in (
        _heuristic_squish_loop,
        _heuristic_squish_slice,
        _heuristic_squish_swap,
    ):
        best_spec = _improve_squish(fix, best_spec, func)
    array, locs = fix.squish(best_spec.arrangement, blocks)
    locs = list(map(lambda a: a[1], sorted(zip(best_spec.arrangement, locs))))
    return (array, locs)


def _cached_make_arrays(deltas: list[int]) -> Callable[[_Sizes], list[list[int]]]:
    """Return a make_arrays function that uses a cache."""

    @cache
    def make_arrays_recursive(sizes: _Sizes) -> list[list[int]]:
        *prev_sizes, my_size = sizes
        arrays = (
            [deltas] if len(sizes) == 1 else make_arrays_recursive(tuple(prev_sizes))
        )
        blocks: list[_Block] = list(
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


def _calculate_num_bytes(arrays: list[list[int]]) -> int:
    # Compute the number of bytes needed to store the resulting arrays.
    return sum(len(a) * DataType.from_list(a).size_bytes for a in arrays)


def _combo_iterator(
    pow2: list[int], max_val: int, start_val=1, *, repeat: int = 0
) -> Iterator[tuple[tuple[int, ...], int]]:
    # Yield permutations with repetition of `pow2` such that their product is
    # never greater than `max_val`.
    power = len(pow2) ** repeat
    if repeat == 0:
        yield (tuple(), power)
        return
    for i, ipow in enumerate(pow2):
        if (next_start_val := start_val * ipow) > max_val:
            continue
        for combo, progress in _combo_iterator(
            pow2, max_val, next_start_val, repeat=repeat - 1
        ):
            yield ((ipow, *combo), i * power + progress)


def _try_all_sizes(
    deltas: list[int], num_tables: int, max_rune: int, show_progress: bool
) -> Iterator[tuple[int, _Sizes, list[list[int]]]]:
    pow2: list[int] = [2**x for x in range(1, max_rune.bit_length())]
    make_arrays = _cached_make_arrays(deltas)
    max_progress = len(pow2) ** (num_tables + 1)
    for array_sizes, progress in _combo_iterator(pow2, max_rune, repeat=num_tables):
        if show_progress:
            print(
                f"\x1b[0Kexploring: {(progress / max_progress) * 100:.2f}%",
                end="\r",
                file=stderr,
            )
        yield (
            _calculate_num_bytes(arrays := make_arrays(array_sizes)),
            array_sizes,
            arrays,
        )
    if show_progress:
        print(file=stderr)


def find_best_arrays(
    deltas: list[int], *, num_tables: int, max_rune: int, show_progress: bool = False
):
    """
    Exhaustively try array size combinations, finding the one that compresses
    to the least bytes.
    """
    lowest: tuple[int, _Sizes, list[list[int]]] = min(
        _try_all_sizes(deltas, num_tables, max_rune, show_progress)
    )
    if show_progress:
        print(
            "best:", ",".join(map(str, lowest[1])), f"({lowest[0]} bytes)", file=stderr
        )
    return lowest[1:]


def build_arrays(deltas: list[int], sizes: _Sizes) -> list[list[int]]:
    """
    Given the list of array block sizes, build and compress the output arrays.
    """
    return _cached_make_arrays(deltas)(sizes)


def calculate_shifts(array_sizes: _Sizes) -> list[int]:
    """Calculate the magnitude of the shifts needed on the rune for each array lookup."""
    field_widths = map(int, map(log2, array_sizes))
    return [0] + list(accumulate(field_widths))


def calculate_masks(array_sizes: _Sizes, max_rune: int) -> list[int]:
    """Calculate the bitmasks needed for the rune on each array lookup."""
    return [
        (2 ** (h - l) - 1)
        for l, h in pairwise(
            calculate_shifts(array_sizes) + [(max_rune + 1).bit_length()]
        )
    ]


def check_arrays(
    deltas: list[int],
    array_sizes: _Sizes,
    arrays: list[list[int]],
    max_rune: int,
    *,
    show_progress: bool = False,
):
    """
    Given base casefold deltas, array sizes, and the resulting arrays, ensure
    that the arrays compress the deltas exactly.
    """
    shifts = calculate_shifts(array_sizes)
    masks = calculate_masks(array_sizes, max_rune)

    def lookup(start_index, rune, level=len(arrays) - 1):
        index = (rune >> shifts[level]) & masks[level]
        next_index = arrays[level][start_index + index]
        return lookup(next_index, rune, level - 1) if level != 0 else next_index

    for rune in range(max_rune + 1):
        if show_progress:
            print(f"\x1b[0Kchecking 0x{rune:06X}...", end="\r", file=stderr)
        assert lookup(0, rune) == deltas[rune]
    if show_progress:
        print(file=stderr)
