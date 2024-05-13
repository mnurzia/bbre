"""Generate documentation files."""

from argparse import ArgumentParser, FileType
from contextlib import redirect_stdout
from io import StringIO
from logging import DEBUG, basicConfig, getLogger
from pathlib import Path
from re import match
from subprocess import run
from typing import BinaryIO

from cc_tree import X_BITS, Y_BITS, Tree, byte_length_digits, split_ranges_utf8
from util import (
    NRRange,
    NRRanges,
    extract_between_tags,
    insert_file,
    nranges_invert,
)

logger = getLogger(__name__)


def _strip_common_indent(lines: list[str]) -> list[str]:
    # Strip a uniform amount of whitespace from every line.
    indent = min(len(line) - len(line.lstrip()) for line in lines)
    return [line[indent:] for line in lines]


def _pop_comment(lines: list[str]) -> list[str]:
    # Assuming `lines` begins with a multiline comment, pop the comment.
    out_lines: list[str] = []
    assert lines[0].lstrip().startswith("/*")
    while not lines[0].endswith("*/"):
        out_lines.append(lines.pop(0))
    assert lines[0].endswith("*/")
    out_lines.append(lines.pop(0)[:-2])
    return _strip_common_indent(
        [l.lstrip().lstrip("/").lstrip("*").rstrip() for l in out_lines]
    )


def _parse_regex(regex: str) -> str:
    regex = regex.lstrip().rstrip()
    assert regex.startswith("/") and regex.endswith("/")
    return regex[1:-1]


def _generate_dot(
    dot: str,
    output: BinaryIO,
    *,
    output_format: str = "svg",
    args: list[str] | None = None,
):
    svg = run(
        [
            "dot",
            f"-T{output_format}",
            "-Gfontname=sans-serif",
            "-Nfontname=monospace",
        ]
        + (args if args is not None else []),
        capture_output=True,
        input=dot.encode(),
        check=True,
    ).stdout
    output.write(svg)


def _generate_visualization(args, regex: str, viz_type: str, output: BinaryIO):
    logger.debug("generating %s...", output.name)
    _generate_dot(
        run(
            [str(args.viz), viz_type],
            capture_output=True,
            input=regex,
            encoding="utf-8",
            check=True,
        ).stdout,
        output,
    )


def _doc_ast(args, lines: list[str]) -> int:
    enum_regex = r"\s*([^\s,]*)\s*(?:=\s*.*)?\s*,?"

    my_path: Path = args.file
    ast_contents = extract_between_tags(lines, "typedef enum ast_type {", "} ast_type;")
    svgs_path = my_path.parent / "generated" / my_path.stem.lower()
    svgs_path.mkdir(parents=True, exist_ok=True)
    output = StringIO()
    with redirect_stdout(output):
        while len(ast_contents):
            comment = _pop_comment(ast_contents)
            assert (m := match(enum_regex, ast_contents.pop(0))) is not None
            name = m.group(1)
            brief, example = comment[0].split(": ")
            example = _parse_regex(example)
            print(f"### {name}")
            print(f"{brief}.")
            if len(comment) > 1:
                print("#### Arguments:")
                print(*[f"  - {argument}" for argument in comment[1:]], sep="\n")
            print()
            print(f"#### Example: `{example}`")
            ast_path = svgs_path / f"{name.lower()}_ast.svg"
            prog_path = svgs_path / f"{name.lower()}_prog.svg"
            with open(ast_path, "wb") as svg:
                _generate_visualization(args, example, "ast", svg)
                print(f"![{name} AST example]({ast_path.relative_to(my_path.parent)})")
            print()
            with open(prog_path, "wb") as svg:
                _generate_visualization(args, example, "prog", svg)
                print(
                    f"![{name} program example]({prog_path.relative_to(my_path.parent)})"
                )
            print()
    with open(my_path, "r+", encoding="utf-8") as my_file:
        insert_file(
            my_file,
            output.getvalue().splitlines(keepends=True),
            "## AST Reference",
            None,
        )
    return 0


CC_EXAMPLE_REGEX = r"[^a-zA-Z]"
CC_EXAMPLE_REGEX_INVERTED = True
CC_EXAMPLE_REGEX_RANGES: NRRanges = [(ord("a"), ord("z")), (ord("A"), ord("Z"))]


def _doc_cccomp(args, _: list[str]) -> int:

    def dot_array(arr: list[str]) -> str:
        return f"""digraph D {{
            A [shape=record label="{'|'.join(arr)}"];
        }}"""

    def cc_array(arr: list[tuple[int, int]]):
        return dot_array([f"{lo:X}-{hi:X}" for lo, hi in arr])

    my_path: Path = args.file
    generated_path = my_path.parent / "generated" / my_path.stem.lower()
    generated_path.mkdir(parents=True, exist_ok=True)
    with open(generated_path / "ast.svg", "wb") as out_ast:
        _generate_visualization(args, CC_EXAMPLE_REGEX, "ast", out_ast)
    with open(generated_path / "array.svg", "wb") as out_array:
        _generate_dot(cc_array(CC_EXAMPLE_REGEX_RANGES), out_array)
    with open(generated_path / "array_normalized.svg", "wb") as out_array:
        _generate_dot(cc_array(sorted(CC_EXAMPLE_REGEX_RANGES)), out_array)
    with open(generated_path / "array_normalized_inverted.svg", "wb") as out_array:
        if CC_EXAMPLE_REGEX_INVERTED:
            _generate_dot(
                cc_array(
                    norm_arr := list(nranges_invert(sorted(CC_EXAMPLE_REGEX_RANGES)))
                ),
                out_array,
            )
        else:
            _generate_dot(
                cc_array(norm_arr := list(sorted(CC_EXAMPLE_REGEX_RANGES))), out_array
            )

    byte_lengths_array: list[tuple[NRRange, int]]
    with open(generated_path / "array_split.svg", "wb") as out_array:
        byte_lengths_array = list(split_ranges_utf8(norm_arr))
        _generate_dot(
            dot_array(
                [
                    f"{lo:0{byte_length_digits(l)}X}-{hi:0{byte_length_digits(l)}X} [{l} byte]"
                    for (lo, hi), l in byte_lengths_array
                ]
            ),
            out_array,
        )

    first, first_num_bytes = byte_lengths_array.pop(0)
    tree = Tree()
    tree.add(first, X_BITS[first_num_bytes], Y_BITS[first_num_bytes])

    with open(generated_path / "tree_00.svg", "wb") as out_tree_00:
        _generate_dot(tree.as_graphviz("initial front"), out_tree_00)

    with open(generated_path / "tree_01.svg", "wb") as out_tree_01:
        while tree.step_build():
            continue
        _generate_dot(tree.as_graphviz("front exhausted"), out_tree_01)

    next_range, next_num_bytes = byte_lengths_array.pop(0)
    tree.add(next_range, X_BITS[next_num_bytes], Y_BITS[next_num_bytes])

    with open(generated_path / "tree_02.svg", "wb") as out_tree_02:
        _generate_dot(tree.as_graphviz("front of second range"), out_tree_02)

    with open(generated_path / "tree_03.svg", "wb") as out_tree_03:
        while tree.step_build():
            continue
        _generate_dot(tree.as_graphviz("front of second range exhausted"), out_tree_03)

    with open(generated_path / "tree_04.svg", "wb") as out_tree_04:
        while len(byte_lengths_array) and byte_lengths_array[0][1] == 1:
            next_range, next_num_bytes = byte_lengths_array.pop(0)
            tree.add(next_range, X_BITS[next_num_bytes], Y_BITS[next_num_bytes])
            while tree.step_build():
                continue
        _generate_dot(tree.as_graphviz("all 1-byte sequences done"), out_tree_04)

    with open(generated_path / "tree_05.svg", "wb") as out_tree_05:
        next_range, next_num_bytes = byte_lengths_array.pop(0)
        tree.add(next_range, X_BITS[next_num_bytes], Y_BITS[next_num_bytes])
        _generate_dot(tree.as_graphviz("initial 2-byte front"), out_tree_05)

    with open(generated_path / "tree_06.svg", "wb") as out_tree_06:
        tree.step_build()
        _generate_dot(tree.as_graphviz("2-byte front expanded"), out_tree_06)

    with open(generated_path / "tree_07.svg", "wb") as out_tree_07:
        while tree.step_build():
            continue
        _generate_dot(tree.as_graphviz("2-byte front done"), out_tree_07)

    with open(generated_path / "tree_08.svg", "wb") as out_tree_08:
        while len(byte_lengths_array):
            next_range, next_num_bytes = byte_lengths_array.pop(0)
            tree.add(next_range, X_BITS[next_num_bytes], Y_BITS[next_num_bytes])
            while tree.step_build():
                continue
        tree.step_build()
        _generate_dot(tree.as_graphviz("completed tree"), out_tree_08)

    tree.build_cache()
    tree.step_reduce()

    with open(generated_path / "tree_09.svg", "wb") as out_tree_09:
        _generate_dot(tree.as_graphviz("after first reduce"), out_tree_09)

    while tree.step_reduce() is True:
        continue

    with open(generated_path / "tree_10.svg", "wb") as out_tree_10:
        _generate_dot(tree.as_graphviz("after all reductions"), out_tree_10)

    with open(generated_path / "program.svg", "wb") as out_program:
        _generate_visualization(args, CC_EXAMPLE_REGEX, "prog", out_program)

    return 0


PATH_FUNCS = {
    "internals/AST.md": _doc_ast,
    "internals/Charclass_Compiler.md": _doc_cccomp,
}


def main() -> int:
    """Main method."""
    ap = ArgumentParser()
    ap.add_argument("--folder", type=Path, default=Path("docs"))
    ap.add_argument("--viz", type=Path, default=Path("build/viz"))
    ap.add_argument("--debug", default=False, action="store_true")
    ap.add_argument("re_source", type=FileType("r"))
    ap.add_argument("file", type=Path)
    args = ap.parse_args()

    if str(args.file) not in PATH_FUNCS:
        ap.error(f"I don't know how to build the documentation file {args.file}")

    func = PATH_FUNCS[str(args.file)]
    args.file = args.folder / args.file
    if args.debug:
        basicConfig(level=DEBUG)

    return func(args, args.re_source.readlines())


if __name__ == "__main__":
    exit(main())
