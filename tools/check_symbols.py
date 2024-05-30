"""Check function visibility in re.c to ensure that all internal functions are static."""

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node
from argparse import ArgumentParser, FileType

C_LANGUAGE = Language(tsc.language())

DEFINITION_QUERY = """
[
(function_definition
 (storage_class_specifier)? @storage-class
 declarator: (function_declarator
              declarator: (identifier) @name))
(declaration
 (storage_class_specifier)? @storage-class
 declarator: (function_declarator
              declarator: (identifier) @name))
]
"""

if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("header", type=FileType("rb"))
    ap.add_argument("source", type=FileType("rb"))
    args = ap.parse_args()

    parser = Parser(C_LANGUAGE)

    header_tree = parser.parse(args.header.read())
    source_tree = parser.parse(args.source.read())

    query = C_LANGUAGE.query(DEFINITION_QUERY)

    header_matches = query.matches(header_tree.root_node)
    source_matches = query.matches(source_tree.root_node)

    header_functions = set()
    for _, match in header_matches:
        assert isinstance(match["name"], Node) and match["name"].text is not None
        header_functions.add(match["name"].text.decode())

    bad_symbols = []
    for _, match in source_matches:
        name_node = match["name"]
        assert isinstance(name_node, Node) and name_node.text is not None
        name = name_node.text.decode()
        storage_class = "extern"
        if (storage_class_node := match.get("storage-class")) is not None:
            assert (
                isinstance(storage_class_node, Node)
                and storage_class_node.text is not None
            )
            storage_class = storage_class_node.text.decode()
        if (
            storage_class == "extern"
            and name not in header_functions
            and not name.startswith("d_")
        ):
            bad_symbols.append((name_node.start_point, name))

    for point, symbol in bad_symbols:
        print(f"{args.source.name}:{point.row} {symbol} marked extern")
    exit(1 if len(bad_symbols) > 0 else 0)
