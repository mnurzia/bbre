"""Generate documentation files."""

from argparse import ArgumentParser, FileType
from contextlib import redirect_stdout
from logging import DEBUG, basicConfig, getLogger
from pathlib import Path
from re import match
from subprocess import run
from typing import BinaryIO

from util import extract_between_tags

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


AST_ENUM_REGEX = r"\s*([^\s,]*)\s*(?:=\s*.*)?\s*,?"


def _generate_visualization(args, regex: str, viz_type: str, output: BinaryIO):
    logger.debug("generating %s...", output.name)
    dot = run(
        [str(args.viz), viz_type],
        capture_output=True,
        input=regex,
        encoding="utf-8",
        check=True,
    ).stdout
    svg = run(
        ["dot", "-Tsvg"], capture_output=True, input=dot.encode(), check=True
    ).stdout
    output.write(svg)


def _doc_ast(args, lines: list[str]) -> int:
    my_path: Path = args.file
    ast_contents = extract_between_tags(lines, "typedef enum ast_type {", "} ast_type;")
    svgs_path = my_path.parent / "assets" / my_path.stem.lower()
    svgs_path.mkdir(parents=True, exist_ok=True)
    with redirect_stdout(open(my_path, "w", encoding="utf-8")):
        while len(ast_contents):
            comment = _pop_comment(ast_contents)
            assert (m := match(AST_ENUM_REGEX, ast_contents.pop(0))) is not None
            name = m.group(1)
            brief, example = comment[0].split(": ")
            example = _parse_regex(example)
            print(f"## {name}")
            print(f"{brief}.")
            if len(comment) > 1:
                print("### Arguments:")
                print(*[f"  - {argument}" for argument in comment[1:]], sep="\n")
            print()
            print(f"### Example: `{example}`")
            ast_path = svgs_path / f"{name.lower()}_ast.svg"
            prog_path = svgs_path / f"{name.lower()}_prog.svg"
            with open(ast_path, "wb") as svg:
                _generate_visualization(args, example, "ast", svg)
                print(f"![{name} AST example]({ast_path.relative_to(my_path.parent)})")
            with open(prog_path, "wb") as svg:
                _generate_visualization(args, example, "prog", svg)
                print(
                    f"![{name} program example]({prog_path.relative_to(my_path.parent)})"
                )
    return 0


PATH_FUNCS = {"internals/AST.md": _doc_ast}


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
