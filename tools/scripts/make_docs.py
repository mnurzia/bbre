"""Generate documentation files."""

from argparse import ArgumentParser, FileType
from contextlib import redirect_stdout
from io import StringIO
from logging import DEBUG, basicConfig, getLogger
from pathlib import Path
from re import match, split
from subprocess import run
import sys
from typing import BinaryIO
from tree_sitter import Language, Parser, Node
import tree_sitter_c as tsc
import marko
import marko.inline

from charclass_tree import X_BITS, Y_BITS, Tree, byte_length_digits, split_ranges_utf8
from util import (
    RuneRange,
    RuneRanges,
    extract_between_tags,
    insert_file,
    make_appender_func,
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
    output: BinaryIO | Path,
    *,
    output_format: str = "svg",
    args: list[str] | None = None,
):
    logger.debug("generating %s...", output.name)
    with open(output, "wb") if isinstance(output, Path) else output as file:
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
        file.write(svg)


def _generate_visualization(args, regex: str, viz_type: str, output: BinaryIO | Path):
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
    ast_contents = extract_between_tags(
        lines, "typedef enum bbre_ast_type {", "} bbre_ast_type;"
    )
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
            _generate_visualization(args, example, "ast", ast_path)
            print(f"![{name} AST example]({ast_path.relative_to(my_path.parent)})")
            print()
            _generate_visualization(args, example, "prog", prog_path)
            print(f"![{name} program example]({prog_path.relative_to(my_path.parent)})")
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
CC_EXAMPLE_REGEX_RANGES: RuneRanges = [
    (ord("a"), ord("z")),
    (ord("A"), ord("Z")),
]


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
    _generate_visualization(args, CC_EXAMPLE_REGEX, "ast", generated_path / "ast.svg")
    array = CC_EXAMPLE_REGEX_RANGES
    _generate_dot(cc_array(CC_EXAMPLE_REGEX_RANGES), generated_path / "array.svg")
    array = sorted(array)
    _generate_dot(cc_array(array), generated_path / "array_normalized.svg")
    array = (
        list(nranges_invert(sorted(CC_EXAMPLE_REGEX_RANGES)))
        if CC_EXAMPLE_REGEX_INVERTED
        else array
    )
    _generate_dot(cc_array(array), generated_path / "array_normalized_inverted.svg")

    byte_lengths_array: list[tuple[RuneRange, int]] = list(split_ranges_utf8(array))
    _generate_dot(
        dot_array(
            [
                f"{lo:0{byte_length_digits(l)}X}-{hi:0{byte_length_digits(l)}X} [{l} byte]"
                for (lo, hi), l in byte_lengths_array
            ]
        ),
        generated_path / "array_split.svg",
    )

    def make_dump_tree():
        frames = []

        def _dump_tree(label: str):
            _generate_dot(
                tree.as_graphviz(label),
                generated_path / f"tree_{len(frames):02}.svg",
            )
            frames.append(label)

        return _dump_tree

    dump_tree = make_dump_tree()

    first_range, first_num_bytes = byte_lengths_array.pop(0)
    tree = Tree()
    tree.add(first_range, X_BITS[first_num_bytes], Y_BITS[first_num_bytes])

    dump_tree("initial front")

    while tree.step_build():
        continue

    dump_tree("front exhausted")

    next_range, next_num_bytes = byte_lengths_array.pop(0)
    tree.add(next_range, X_BITS[next_num_bytes], Y_BITS[next_num_bytes])

    dump_tree("front of second range")

    while tree.step_build():
        continue

    dump_tree("front of second range exhausted")

    while len(byte_lengths_array) > 0 and byte_lengths_array[0][1] == 1:
        next_range, next_num_bytes = byte_lengths_array.pop(0)
        tree.add(next_range, X_BITS[next_num_bytes], Y_BITS[next_num_bytes])
        while tree.step_build():
            continue

    dump_tree("all 1-byte sequences done")

    next_range, next_num_bytes = byte_lengths_array.pop(0)
    tree.add(next_range, X_BITS[next_num_bytes], Y_BITS[next_num_bytes])

    dump_tree("initial 2-byte front")

    tree.step_build()

    dump_tree("2-byte front expanded")

    while tree.step_build():
        continue

    dump_tree("2-byte front done")

    while len(byte_lengths_array) > 0:
        next_range, next_num_bytes = byte_lengths_array.pop(0)
        tree.add(next_range, X_BITS[next_num_bytes], Y_BITS[next_num_bytes])
        while tree.step_build():
            continue

    tree.step_build()

    dump_tree("completed tree")

    tree.build_cache()
    tree.step_reduce()

    dump_tree("after first reduce")

    while tree.step_reduce() is True:
        continue

    dump_tree("after all reductions")

    next_root = Tree()

    tree.transpose(next_root, {})

    tree.right = next_root.right
    tree.cache = {}

    dump_tree("after transposition")

    _generate_visualization(
        args, CC_EXAMPLE_REGEX, "prog", generated_path / "program.svg"
    )

    return 0


def _doc_api(args, lines: list[str]) -> int:
    C_LANGUAGE = Language(tsc.language())

    DOC_QUERY = C_LANGUAGE.query(
        r"""(
            (comment) @comment
            (#match? @comment "/[*][*](.|[\n])*[*]/")
            .
            [
                (type_definition) @node
                (declaration) @node
                (preproc_def) @node
            ]+
        )
        """
    )

    FUNCTION_NAME_QUERY = C_LANGUAGE.query(
        r"""
        (function_declarator
            declarator: (identifier) @name)
        """
    )

    NAME_QUERY = C_LANGUAGE.query(
        r"""[
            (type_identifier) @name
            (identifier) @name
        ]"""
    )

    class API:
        def __init__(self, comment: Node, nodes: list[Node]):
            assert comment.text is not None
            self.header, *self.description = API._format_comment(comment.text.decode())
            self.comment = comment
            self.node = nodes
            self.names: list[str] = []
            for sub in self.node:
                chosen_name_query = (
                    NAME_QUERY
                    if sub.type in ["type_definition", "preproc_def"]
                    else FUNCTION_NAME_QUERY
                )
                name = chosen_name_query.matches(sub)[0][1]["name"]
                assert isinstance(name, Node) and name.text is not None
                self.names.append(name.text.decode())

        @staticmethod
        def _format_comment(comment: str) -> list[str]:
            comment = comment.strip().lstrip("/").rstrip("/").rstrip("*")
            lines = [line.strip().lstrip("*") for line in comment.splitlines()]
            num_leading_spaces = min(
                len(line) - len(line.lstrip()) for line in lines if len(line) > 0
            )
            return [line[num_leading_spaces:] for line in lines]

    def code(s: str) -> str:
        return f"<code>{s}</code>"

    link_names: dict[str, str] = {}

    def heading(s: str, ids: list[str], lvl: int) -> str:
        return f'<h{lvl} id="{ids[0]}">{s}</h{lvl}>'

    def ref(s: str, name: str) -> str:
        return f'<a href="#{link_names[name]}">{s}</a>'

    def splitwords(s: str):
        return split(r"\b", s)

    def insert_references(s: str, api: list[str]):
        doc = marko.parse(s)

        def replace_text_nodes(node):
            # this function is very poorly written.
            if node.get_type() == "RawText":
                assert isinstance(node.children, str)
                lead = node.children[: len(node.children) - len(node.children.lstrip())]
                tail = node.children[len(node.children.rstrip()) :]
                next = marko.parse(
                    "".join(
                        [
                            (w if w not in api else ref(w, w))
                            for w in splitwords(node.children)
                        ]
                    )
                )
                assert isinstance(next.children[0], marko.block.Paragraph)
                return (
                    [marko.inline.RawText(lead)]
                    + list(next.children[0].children)
                    + [marko.inline.RawText(tail)]
                )
            elif node.get_type() not in ["CodeBlock", "FencedCode"]:
                if hasattr(node, "children") and isinstance(node.children, list):
                    node.children = sum(
                        (replace_text_nodes(child) for child in node.children), []
                    )
            return [node]

        replaced = replace_text_nodes(doc)
        assert len(replaced) == 1 and isinstance(
            new_doc := replaced[0], marko.block.Document
        )
        return marko.render(new_doc)

    parser = Parser(C_LANGUAGE)

    header_tree = parser.parse("".join(lines).encode())

    header_matches = DOC_QUERY.matches(header_tree.root_node)

    apis = []

    out_lines, out = make_appender_func()

    for match in header_matches:
        if not len(match[1]):
            continue
        comment = match[1]["comment"]
        node = match[1]["node"]
        assert isinstance(comment, Node) and isinstance(node, list)
        apis.append(API(comment, node))

    all_names = sum((api.names for api in apis), [])
    assert all(all_names.count(name) == 1 for name in all_names)

    for api in apis:
        for name in api.names:
            link_names[name] = api.names[0]

    out("# API Reference")

    # Generate ToC
    out(heading("Contents", ["Contents"], 2))
    out("<ul>")
    for api in apis:
        out(f"<li>{ref(", ".join(api.names), api.names[0])}</li>")
    out("</ul>")

    for api in apis:
        out(heading(", ".join([code(name) for name in api.names]), api.names, 2))
        out(insert_references(api.header, all_names))
        out("```c")
        for node in api.node:
            assert node.text is not None
            out(node.text.decode().rstrip("\n"))
        out("```")
        out(insert_references("\n".join(api.description), all_names))

    with open(args.file, "w", encoding="utf-8") as my_file:
        my_file.writelines(out_lines)
    return 0


PATH_FUNCS = {
    "internals/AST.md": _doc_ast,
    "internals/Charclass_Compiler.md": _doc_cccomp,
    "API.md": _doc_api,
}


def main() -> int:
    """Main method."""
    ap = ArgumentParser()
    ap.add_argument("--folder", type=Path, default=Path("../docs"))
    ap.add_argument("--viz", type=Path, default=Path("build/debug/viz"))
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
    sys.exit(main())
