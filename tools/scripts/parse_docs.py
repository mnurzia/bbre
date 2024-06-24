from argparse import ArgumentParser, FileType
from tree_sitter import Language, Parser, Node, Point
import tree_sitter_c as tsc
from re import split
import marko
import marko.block

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
    return f"`{s}`"


def link(s: str, name: str) -> str:
    return f'<a name="{name}">{s}</a>'


def ref(s: str, name: str) -> str:
    return f'<a href="#{name}">{s}</a>'


def splitwords(s: str):
    return split(r"\b", s)


def insert_references(s: str, api: list[str]):
    doc = marko.parse(s)

    def replace_text_nodes(node):
        if node.get_type() == "RawText":
            assert isinstance(node.children, str)
            next = marko.parse(
                "".join(
                    [
                        (w if w not in api else ref(w, w))
                        for w in splitwords(node.children)
                    ]
                )
            )
            assert isinstance(next.children[0], marko.block.Paragraph)
            return list(next.children[0].children)
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


if __name__ == "__main__":
    ap = ArgumentParser()
    ap.add_argument("header", type=FileType("rb"))
    args = ap.parse_args()

    parser = Parser(C_LANGUAGE)

    header_tree = parser.parse(args.header.read())

    header_matches = DOC_QUERY.matches(header_tree.root_node)

    apis = []

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
        print("## " + ", ".join([link(code(name), name) for name in api.names]))
        print(insert_references(api.header, all_names))
        print("```c")
        for node in api.node:
            assert node.text is not None
            print(node.text.decode().rstrip("\n"))
        print("```")
        print(insert_references("\n".join(api.description), all_names))
