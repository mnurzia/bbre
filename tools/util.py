"""Utilities for the tools folder."""

from typing import NamedTuple


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
        return DataType.from_int(max([abs(x) for x in l]), any(x < 0 for x in l))

    def to_ctype(self) -> str:
        """Return the C type name for this datatype."""
        return f"{'s' if self.signed else 'u'}{8 * self.size_bytes}"
