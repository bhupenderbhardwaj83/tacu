"""Semantic Python AST navigation with explicit ripgrep fallback."""

from __future__ import annotations

import ast
from typing import Any

from . import search_code
from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "inspect_symbol",
    "Find a function or class definition (Python AST, then grep fallback).",
    schema(properties={"symbol": {"type": "string"}, "path": {"type": "string"},
                       "references": {"type": "boolean"}}, required=("symbol",)),
    schema(properties={"symbol": {"type": "string"}, "definitions": {"type": "array"}, "references": {"type": "array"}}),
    when_to_use="Locate where a named function or class is defined. Prefer this over a raw content search for def/class.",
    when_not="Do not use to search arbitrary strings (search_code) or read a whole file (read_file).",
)


def execute(context: ToolContext, *, symbol: str, path: str = ".", references: bool = True) -> dict[str, Any]:
    target = context.guarded_path(path)
    candidates = [target] if target.is_file() else [item for item in target.rglob("*.py")
                                                      if ".venv" not in item.parts and "__pycache__" not in item.parts]
    definitions: list[dict[str, Any]] = []
    refs: list[dict[str, Any]] = []
    for candidate in candidates[:200]:
        try:
            tree = ast.parse(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol:
                definitions.append({"file": str(candidate), "line": node.lineno,
                                    "kind": "class" if isinstance(node, ast.ClassDef) else "function",
                                    "end_line": getattr(node, "end_lineno", node.lineno), "docstring": ast.get_docstring(node)})
            elif references and isinstance(node, ast.Name) and node.id == symbol:
                refs.append({"file": str(candidate), "line": node.lineno, "column": node.col_offset + 1})
    if definitions or refs:
        return {"symbol": symbol, "backend": "python-ast", "definitions": definitions, "references": refs[:100],
                "_truncated": len(refs) > 100}
    try:
        result = search_code.execute(context, query=symbol, path=path, max_results=50)
    except ToolFailure:
        return {"symbol": symbol, "backend": "python-ast", "definitions": [], "references": []}
    return {"symbol": symbol, "backend": "ripgrep", "definitions": [], "references": result["matches"],
            "_truncated": result.get("_truncated", False)}

