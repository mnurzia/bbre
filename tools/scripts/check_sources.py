"""Check function visibility and encoding in bbre.[ch]."""

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node, Point
from argparse import ArgumentParser, FileType
from dataclasses import dataclass
from typing import Iterator
from util import FileWarning

C_LANGUAGE = Language(tsc.language())

DEFINITION_QUERY = """
(_ (storage_class_specifier)? @storage-class 
	declarator: _ @decl) @root
"""

IDENTIFIER_QUERY = """(identifier) @id"""

EXCLUDE_PREFIX = "d_"

definition_query = C_LANGUAGE.query(DEFINITION_QUERY)
identifier_query = C_LANGUAGE.query(IDENTIFIER_QUERY)


@dataclass
class Symbol:
    location: Point
    name: str
    storage_class: str


def _node_text(node) -> str:
    assert node is not None and isinstance(node, Node)
    assert node.text is not None
    return node.text.decode()


def _find_identifier(root_node: Node) -> Node | None:
    if len(matches := identifier_query.matches(root_node)):
        assert isinstance(matches[0][1]["id"], Node)
        return matches[0][1]["id"]
    else:
        return None


def _parents(node: Node) -> Iterator[Node]:
    while node.parent is not None:
        yield node.parent
        node = node.parent


def _find_top_level_nodes(root_node: Node) -> Iterator[Symbol]:
    header_matches = definition_query.matches(root_node)
    header_match_nodes = set()
    top_level_nodes = set()
    for _, match in header_matches:
        node = match["root"]
        assert isinstance(node, Node)
        header_match_nodes.add(node)
    for node in header_match_nodes:
        parents = list(_parents(node))
        if all(parent not in header_match_nodes for parent in parents):
            top_level_nodes.add(node)
    for _, match in header_matches:
        node = match["root"]
        assert isinstance(node, Node)
        if (
            node in top_level_nodes
            and (identifier := _find_identifier(node)) is not None
            and all(
                parent.type not in ["enumerator", "field_declaration"]
                for parent in _parents(identifier)
            )
            and not (identifier_name := _node_text(identifier)).startswith(
                EXCLUDE_PREFIX
            )
        ):
            storage_class = (
                _node_text(match["storage-class"])
                if "storage-class" in match
                else "extern"
            )
            yield Symbol(node.start_point, identifier_name, storage_class)


def warn(symbol: Symbol, header_symbols: dict[str, Symbol]) -> Iterator[str]:
    if symbol.name not in header_symbols and symbol.storage_class == "extern":
        yield f"{symbol.name} marked 'extern', should be 'static'"
    if not symbol.name.startswith("bbre_"):
        yield f"{symbol.name} does not start with 'bbre_'"


if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("header", type=FileType("rb"))
    ap.add_argument("source", type=FileType("rb"))
    args = ap.parse_args()

    parser = Parser(C_LANGUAGE)

    files = {args.header.name: args.header.read(), args.source.name: args.source.read()}

    header_tree = parser.parse(args.header.read())
    source_tree = parser.parse(args.source.read())

    query = C_LANGUAGE.query(DEFINITION_QUERY)
    identifier_query = C_LANGUAGE.query(IDENTIFIER_QUERY)

    header_matches = query.matches(header_tree.root_node)
    source_matches = query.matches(source_tree.root_node)

    header_symbols = {
        symbol.name: symbol for symbol in _find_top_level_nodes(header_tree.root_node)
    }

    warnings: list[FileWarning] = []

    for symbol in _find_top_level_nodes(source_tree.root_node):
        for warning in warn(symbol, header_symbols):
            warnings.append(
                FileWarning(
                    args.source.name,
                    symbol.location.row + 1,
                    symbol.location.column,
                    warning,
                )
            )

    for name, contents in files.items():
        for row, line in enumerate(contents.decode().splitlines()):
            for col, ch in enumerate(line):
                if ord(ch) > 127 or (ord(ch) < 0x20 and ch != "\n"):
                    warnings.append(
                        FileWarning(name, row + 1, col, f"bad ordinal {ord(ch)}")
                    )

    FileWarning.exit_with(warnings)
