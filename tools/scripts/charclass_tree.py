"""A readable implementation of the character class compiler."""

from argparse import ArgumentParser, FileType
from dataclasses import dataclass
from typing import Iterator, Self
from util import (
    ByteRange,
    RuneRange,
    RuneRanges,
    insert_c_file,
    make_appender_func,
    nrange_isect,
    UTF_MAX,
)
from functools import reduce
from operator import and_


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
        return super().__hash__() and NotImplemented

    def __eq__(self, other) -> bool:
        assert isinstance(other, TreeNode)
        return NotImplemented

    def graphviz_properties(self) -> str:
        """Return Graphviz properties of this tree."""
        return NotImplemented

    def build(self, parent: Self) -> bool:
        """Run a step of the build process."""
        return NotImplemented and parent


@dataclass
class TreeFront(CCTree):
    """A front node for the tree."""

    range: RuneRange
    x_bits: int
    y_bits: int
    left: CCTree | None

    def graphviz_properties(self) -> str:
        digits = byte_length_digits(list(X_BITS.values()).index(self.x_bits) + 1)

        return f'shape=oval,label="U+{self.range[0]:0{digits}}-U+{self.range[1]:0{digits}}, {self.x_bits}/{self.y_bits}"'

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
        leftover: RuneRange | None = None
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
            if nrange_isect((parent.right.range[0], parent.right.range[1]), byte_range):
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

    range: ByteRange
    left: CCTree | None
    right: CCTree | None

    def key(self) -> tuple:
        """Return a unique key describing this tree."""
        return (
            self.range,
            self.left.key() if isinstance(self.left, TreeNode) else None,
            self.right.key() if isinstance(self.right, TreeNode) else None,
        )

    def __hash__(self) -> int:
        return hash(self.key())

    def __eq__(self, other) -> bool:
        assert isinstance(other, TreeNode)
        return self.key() == other.key()

    def graphviz_properties(self) -> str:
        return f'shape=rect,label="0x{self.range[0]:02X}-0x{self.range[1]:02X}"'

    def build(self, parent: CCTree) -> bool:
        assert parent is None or parent is not None  # suppress not accessed
        return (
            self.left is not None
            and self.left.build(self)
            or self.right is not None
            and self.right.build(self)
        )

    def reduce(self, cache: dict["TreeNode", "TreeNode"]) -> bool:
        """Run a reduce step"""
        if self.left is not None:
            assert isinstance(self.left, TreeNode)
        if self.right is not None:
            assert isinstance(self.right, TreeNode)
        if (self.left is not None and self.left.reduce(cache)) or (
            self.right is not None and self.right.reduce(cache)
        ):
            return True
        if (
            self.left is not None
            and (found := cache.get(self.left))
            and found is not self.left
        ):
            self.left = found
            return True
        if (
            self.right is not None
            and (found := cache.get(self.right))
            and found is not self.right
        ):
            self.right = found
            return True
        return False

    def transpose(self, root: Self, cache: dict["TreeNode", "TreeNode"]) -> "TreeNode":
        if self.left is not None:
            assert isinstance(self.left, TreeNode)
            self.left.transpose(root, cache)
        if self.right is None:
            # add to root
            root.right = (out := TreeNode(self.range, root.right, None))
            cache[self] = out
            return out
        else:
            # add to self.right
            assert isinstance(self.right, TreeNode)
            if (found := cache.get(self.right)) is None:
                found = self.right.transpose(root, cache)
            found.right = (out := TreeNode(self.range, found.right, None))
            return out


class Tree(TreeNode):
    """The root node for the tree. This is a dummy node and never gets considered."""

    cache: dict[TreeNode, TreeNode] = {}

    def __init__(self):
        super().__init__((0, 0), None, None)

    def add(self, range_: RuneRange, x_bits: int, y_bits: int):
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
        edges: list[tuple[int, int, str]] = []
        lines = ["digraph D {"]
        lines.append(f' label="{title}";')

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
                children = [top.left, top.right]
            name = f"N{len(names):04X}"
            names[id(top)] = name

            lines.append(f"{name} [{top.graphviz_properties()}]")
            for i, child in enumerate(children):
                if child is None:
                    continue
                edge_type = ["dashed", "solid"]
                edges.append((id(top), id(child), edge_type[i]))

            stack.extend(children)

        for v1, v2, edge_type in edges:
            lines.append(f"{names[v1]} -> {names[v2]} [style={edge_type}]")

        lines = lines + ["}"]
        return "\n".join(lines)


def split_ranges_utf8(
    ranges: RuneRanges,
) -> Iterator[tuple[RuneRange, int]]:
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


def cmd_dfa(args) -> int:
    RANGES = [(0, 0xD7FF), (0xE000, UTF_MAX)]
    tree = Tree()
    for r, l in split_ranges_utf8(RANGES):
        tree.add(r, X_BITS[l], Y_BITS[l])
        while tree.step_build():
            continue
    while tree.step_reduce():
        continue

    state_n: dict[CCTree, int] = {}

    def make_byte_classes(in_node: CCTree) -> dict[CCTree, list[frozenset[int]]]:
        out: dict[CCTree, list[frozenset[int]]] = {}
        byte_classes: list[frozenset[int]] = list(frozenset() for _ in range(256))
        node: CCTree | None = in_node
        state_n[in_node] = state_n.get(in_node, len(state_n))
        while node is not None:
            assert isinstance(node, TreeNode)
            this_set = frozenset(range(node.range[0], node.range[1] + 1))
            for i in range(node.range[0], node.range[1] + 1):
                byte_classes[i] = this_set
            if node.right is not None:
                out |= make_byte_classes(node.right)
            node = node.left
        empties = frozenset(i for i in range(256) if len(byte_classes[i]) == 0)
        for i in empties:
            byte_classes[i] = empties
        out[in_node] = byte_classes
        return out

    assert tree.right is not None
    node_classes = make_byte_classes(tree.right)
    common_classes: list[frozenset[int]] = list(
        sorted(
            frozenset(
                reduce(lambda l, r: l & r, (v[i] for v in node_classes.values()))
                for i in range(256)
            ),
            key=tuple,
        )
    )

    class_table = [0] * 256
    for i, cc in enumerate(common_classes):
        for j in cc:
            class_table[j] = i

    state_table = []
    for state in state_n.keys():
        this_trans_table = [len(state_n)] * 256
        node = state
        row = []
        while node is not None:
            assert isinstance(node, TreeNode)
            for j in range(node.range[0], node.range[1] + 1):
                this_trans_table[j] = (
                    state_n[node.right] if isinstance(node.right, TreeNode) else 0
                )
            node = node.left
        for i, cc in enumerate(common_classes):
            assert all(
                this_trans_table[next(iter(cc))] == this_trans_table[elem]
                for elem in cc
            )
            row.append(this_trans_table[next(iter(cc))])
        state_table.append(row)

    def shift_amt(n):
        binv = f"{n:08b}"
        return len(binv) - len(binv.lstrip("1")) if n >= 0xC0 and n <= 0xF4 else 0

    lines, out = make_appender_func()
    out(f"#define RE_UTF8_DFA_NUM_CLASS {len(common_classes)}")
    out(f"#define RE_UTF8_DFA_NUM_STATE {len(state_n) + 1}")
    out(f"static const re_u8 re_utf8_dfa_class[256] = {{")
    out(",".join(map(str, class_table)) + "};")
    out(
        f"static const re_u8 re_utf8_dfa_trans[RE_UTF8_DFA_NUM_STATE][RE_UTF8_DFA_NUM_CLASS] = {{"
    )
    out(",".join("{" + ",".join(map(str, row)) + "}" for row in state_table) + "};")
    out(f"static const re_u8 re_utf8_dfa_shift[RE_UTF8_DFA_NUM_CLASS] = {{")
    out(",".join(map(str, (shift_amt(next(iter(cc))) for cc in common_classes))) + "};")

    insert_c_file(args.file, lines, "dfa", file_name="charclass_tree.py")
    return 0


if __name__ == "__main__":
    ap = ArgumentParser()
    sub = ap.add_subparsers()
    sub_cmd_dfa = sub.add_parser("dfa")
    sub_cmd_dfa.set_defaults(func=cmd_dfa)
    sub_cmd_dfa.add_argument("file", type=FileType("r+"))
    args = ap.parse_args()
    exit(args.func(args))
