"""A readable implementation of the character class compiler."""

from dataclasses import dataclass
from typing import Iterator, Self
from util import BRange, NRRange, NRRanges, nrange_isect


def byte_length_digits(l: int):
    """
    Return the number of hex digits needed to represent a Unicode codepoint of the given length.
    """
    return {1: 2, 2: 3, 3: 4, 4: 6}[l]


X_BITS = {1: 0, 2: 6, 3: 12, 4: 18}
Y_BITS = {1: 7, 2: 5, 3: 4, 4: 3}


class CCTree:
    """A tree node."""

    def __hash__(self) -> int:
        assert False
        return 0

    def __eq__(self, other) -> bool:
        assert isinstance(other, TreeNode)
        return NotImplemented

    def graphviz_properties(self) -> str:
        """Return Graphviz properties of this tree."""
        return NotImplemented

    def build(self, parent: Self) -> bool:
        """Run a step of the build process."""
        assert False and parent



@dataclass
class TreeFront(CCTree):
    """A front node for the tree."""

    range: NRRange
    x_bits: int
    y_bits: int
    left: CCTree | None

    def graphviz_properties(self) -> str:
        digits = byte_length_digits(list(X_BITS.values()).index(self.x_bits) + 1)
        return f'shape=oval,label="U+{
            self.range[0]:0{digits}}-U+{self.range[1]:0{digits}}, {self.x_bits}/{self.y_bits}"'

    def build(self, parent: Self) -> bool:
        assert isinstance(parent, TreeNode)
        if self.left is not None and self.left.build(self):
            return True
        # pop ourselves from parent
        parent.right = self.left
        x_mask = (1 << self.x_bits) - 1
        y_min, y_max = (self.range[0] >> self.x_bits, self.range[1] >> self.x_bits)
        u_mask = (0xFE << self.y_bits) & 0xFF
        byte_min, byte_max = (y_min & 0xFF) | u_mask, (y_max & 0xFF) | u_mask
        x_min, x_max = (self.range[0] & x_mask, self.range[1] & x_mask)
        if self.x_bits == 0:
            # terminal
            parent.right = TreeNode((byte_min, byte_max), self.left, None)
            return True
        leftover: NRRange | None = None
        if y_min == y_max or (x_min == 0 and x_max == x_mask):
            byte_range = (byte_min, byte_max)
            x_range = (x_min, x_max)
        elif x_min == 0:
            byte_range = (byte_min, byte_max - 1)
            x_range = (0, x_mask)
            leftover = (y_max << self.x_bits, self.range[1])
        elif x_max == x_mask:
            byte_range = (byte_min, byte_min)
            x_range = (x_min, x_mask)
            leftover = ((y_min + 1) << self.x_bits, self.range[1])
        elif y_min == y_max - 1:
            byte_range = (byte_min, byte_min)
            x_range = (x_min, x_mask)
            leftover = (y_max << self.x_bits, self.range[1])
        else:
            byte_range = (byte_min, byte_min)
            x_range = (x_min, x_mask)
            leftover = ((y_min + 1) << self.x_bits, self.range[1])
        child: TreeNode | None = None
        if parent.right is not None:
            assert isinstance(parent.right, TreeNode)
            if nrange_isect(
                (parent.right.range[0], parent.right.range[1]), byte_range
            ):
                child = parent.right
        if child is None:
            parent.right = (child := TreeNode(byte_range, parent.right, None))
        child.right = TreeFront(x_range, self.x_bits - 6, 6, child.right)
        if leftover is not None:
            parent.right = TreeFront(leftover, self.x_bits, self.y_bits, parent.right)
        return True

@dataclass
class TreeNode(CCTree):
    """A range node for the tree."""

    range: BRange
    left: CCTree | None
    right: CCTree | None

    def _key(self) -> tuple: ...

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        assert isinstance(other, TreeNode)
        return self._key() == other._key()

    def graphviz_properties(self) -> str:
        return f'shape=rect,label="0x{self.range[0]:02X}-0x{self.range[1]:02X}"'

    def build(self, parent: CCTree) -> bool:
        return (self.left is not None and self.left.build(self)
                or self.right is not None and self.right.build(self))

    def reduce(self, cache: dict['TreeNode', 'TreeNode']) -> bool:
        """Run a reduce step"""
        if self.left is not None:
            assert isinstance(self.left, TreeNode)
        if self.right is not None:
            assert isinstance(self.right, TreeNode)
        if (self.left is not None and self.left.reduce(cache)) \
            or (self.right is not None and self.right.reduce(cache)):
            return True
        if self.left is not None and (found := cache.get(self.left)) and found is not self.left:
            self.left = found
            return True
        if self.right is not None and (found := cache.get(self.right)) and found is not self.right:
            self.right = found
            return True
        return False


class Tree(TreeNode):
    """The root node for the tree. This is a dummy node and never gets considered."""
    cache: dict[TreeNode, TreeNode] = {}

    def __init__(self):
        super().__init__((0, 0), None, None)

    def add(self, range_: NRRange, x_bits: int, y_bits: int):
        """Add a tree front to the tree."""
        self.right = TreeFront(range_, x_bits, y_bits, self.right)

    def step_build(self) -> bool:
        """Run a step of the build process."""
        return self.build(self)

    def build_cache(self, tree: TreeNode | None = None):
        """Build the tree cache."""
        if tree is None:
            self.cache = {}
            tree = self
        if tree.left is not None:
            assert isinstance(tree.left, TreeNode)
            self.build_cache(tree.left)
        if tree.right is not None:
            assert isinstance(tree.right, TreeNode)
            self.build_cache(tree.right)
        if tree not in self.cache:
            self.cache[tree] = tree

    def step_reduce(self) -> bool:
        """Run a reduction step."""
        return self.reduce(self.cache)

    def as_graphviz(self, title: str = "") -> str:
        """Generate Graphviz code describing this tree."""
        names: dict[int, str] = {}
        stack: list[CCTree | None] = [self.right]
        edges: list[tuple[int, int]] = []
        lines = ["digraph D {"]
        lines.append(f" label=\"{title}\";")

        while len(stack) > 0:
            top = stack.pop()
            children: list[CCTree | None] = []
            if top is None:
                continue
            if id(top) in names:
                continue
            if isinstance(top, TreeFront):
                children = [top.left]
            if isinstance(top, TreeNode):
                children = [top.right, top.left]
            name = f"N{len(names):04X}"
            names[id(top)] = name

            lines.append(f"{name} [{top.graphviz_properties()}]")
            for child in children:
                if child is None:
                    continue
                edges.append((id(top), id(child)))

            stack.extend(children)

        for v1, v2 in edges:
            lines.append(f"{names[v1]} -> {names[v2]}")

        lines = lines + ["}"]
        return '\n'.join(lines)

def split_ranges_utf8(ranges: NRRanges) -> Iterator[tuple[NRRange, int]]:
    """Split a list of ranges among UTF-8 byte length boundaries."""
    for cur_min, cur_max in ranges:
        min_bound = 0
        for byte_length in range(1, 5):
            max_bound = (1 << (X_BITS[byte_length] + Y_BITS[byte_length])) - 1
            if min_bound <= cur_max and cur_min <= max_bound:
                clamped_min = min_bound if cur_min < min_bound else cur_min
                clamped_max = max_bound if cur_max > max_bound else cur_max
                yield ((clamped_min, clamped_max), byte_length)
            min_bound = max_bound + 1
