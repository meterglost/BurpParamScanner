"""Remove all type annotation in source code to make it work with Jython."""

from __future__ import annotations

import ast
from pathlib import Path


class CustomTypeCrawler(ast.NodeVisitor):
    """Crawl custom type definition for further run FunctionCompatibleConverter."""

    def visit_Assign(self: CustomTypeCrawler, node: ast.Assign) -> None:
        """."""

        if isinstance(node.value, ast.Subscript):
            if isinstance(node.value.value, ast.Name) and node.value.value.id == "Literal":
                if isinstance(node.value.slice, ast.Tuple):
                    strlist = node.value.slice.elts
                elif isinstance(node.value.slice, ast.Constant):
                    strlist = [node.value.slice]

                if isinstance(node.targets[0], ast.Name):
                    custom_type[node.targets[0].id] = strlist


class TypeHintRemover(ast.NodeTransformer):
    """."""

    def visit_FunctionDef(self: TypeHintRemover, node: ast.FunctionDef) -> ast.FunctionDef:
        """Remove function argument type annotations."""

        # remove the return type definition
        node.returns = None
        # remove all argument annotations
        if node.args.args:
            for arg in node.args.args:
                arg.annotation = None
        return node

    def visit_Import(self: TypeHintRemover, node: ast.Import) -> ast.Import | None:
        """Remove libraries support type annotations."""

        node.names = [n for n in node.names if n.name not in ["typing", "__future__"]]
        return node if node.names else None

    def visit_ImportFrom(self: TypeHintRemover, node: ast.ImportFrom) -> ast.ImportFrom | None:
        """Remove library class support type annotations."""

        return node if node.module not in ["typing", "__future__"] else None

    def visit_AnnAssign(self: TypeHintRemover, node: ast.AnnAssign) -> ast.AnnAssign | None:
        """Remove variable type annotations and class attribute type annotations."""

        return node if node.value else None

    def visit_Assign(self: CustomTypeCrawler, node: ast.Assign) -> ast.Assign | None:
        """."""

        if isinstance(node.value, ast.Subscript):
            if isinstance(node.value.value, ast.Name) and node.value.value.id == "Literal":
                return None

        return node


class TypeConverter(ast.NodeTransformer):
    """."""

    def visit_Subscript(self: TypeConverter, node: ast.Subscript) -> ast.List:
        """."""

        if isinstance(node.value, ast.Name) and node.value.id == "Literal":
            if isinstance(node.slice, ast.Tuple):
                node = ast.List(node.slice.elts, node.ctx)
            elif isinstance(node.slice, ast.Constant):
                node = ast.List([node.slice], node.ctx)

        return node


class CompatibleConverter(ast.NodeTransformer):
    """."""

    def visit_Call(self: CompatibleConverter, node: ast.Call) -> ast.Call:  # trunk-ignore(ruff/C901)
        """."""

        if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
            if isinstance(node.func.value, ast.Call):
                if isinstance(node.func.value.func, ast.Attribute) and node.func.value.func.attr == "tobytes":
                    node.func.value.func.attr = "tostring"
                    node = node.func.value

        elif isinstance(node.func, ast.Attribute) and node.func.attr == "frombytes":
            if len(node.args) == 1 and isinstance(node.args[0], ast.Call):
                if isinstance(node.args[0].func, ast.Attribute) and node.args[0].func.attr == "encode":
                    node.func.attr = "fromunicode"
                    node.args[0] = node.args[0].func.value

        elif isinstance(node.func, ast.Name) and node.func.id == "isinstance":
            if isinstance(node.args[1], ast.Name) and node.args[1].id == "str":
                node.args[1] = ast.Name("basestring", ast.Load())

        elif isinstance(node.func, ast.Name) and node.func.id == "get_args":
            if len(node.args) == 1 and isinstance(node.args[0], ast.Name):
                if node.args[0].id in custom_type:
                    node = ast.List(custom_type[node.args[0].id], ast.Load())
                else:
                    node = node.args[0]

        self.generic_visit(node)

        return node

    def visit_ExceptHandler(self: CompatibleConverter, node: ast.ExceptHandler) -> ast.ExceptHandler:
        """."""

        if isinstance(node.type, ast.Name):
            if node.type.id == "FileNotFoundError":
                node.type.id = "IOError"
            elif node.type.id == "json.JSONDecodeError" or node.type.id == "json.decoder.JSONDecodeError":
                node.type.id = "ValueError"

        self.generic_visit(node)

        return node


visitors = [
    CustomTypeCrawler(),
]

transformers = [
    TypeHintRemover(),
    TypeConverter(),
    CompatibleConverter(),
]

custom_type = {}


for path in Path("../out/").rglob("*.py"):
    if path.is_file():
        print(path.name + " converting... ", end="")

        code = ast.parse(path.read_text())

        for visitor in visitors:
            visitor.visit(code)

        for transformer in transformers:
            code = transformer.visit(code)

        path.write_text(ast.unparse(code))

        print("done!")
