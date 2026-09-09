"""Normalize syntax and installed linter diagnostics."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "diagnostics",
    "Check a file or tree for syntax/linter diagnostics.",
    schema(properties={"path": {"type": "string"}, "checks": {"type": "array"}}, required=("path",)),
    schema(properties={"diagnostics": {"type": "array"}, "count": {"type": "integer"}}), timeout=60,
    when_to_use="Verify syntax after an edit, or when the user asked to lint/check a file.",
    when_not="Do not use to run the test suite (run_tests) or execute a program (shell).",
)


def execute(context: ToolContext, *, path: str, checks: list[str] | None = None) -> dict[str, Any]:
    target = context.guarded_path(path)
    if not target.exists(): raise ToolFailure(f"Path does not exist: {path}", code="file_not_found")
    candidates = [target] if target.is_file() else [item for item in target.rglob("*.py") if ".venv" not in item.parts]
    files = [item for item in candidates if item.suffix in {".py", ".pyi"} and not item.is_symlink()
             and context.workspace.resolve() in item.resolve().parents]
    diagnostics: list[dict[str, Any]] = []
    for candidate in files[:500]:
        try: ast.parse(candidate.read_text(encoding="utf-8"), filename=str(candidate))
        except SyntaxError as error:
            diagnostics.append({"file": str(candidate), "line": error.lineno, "column": error.offset,
                                "severity": "error", "code": "python-syntax", "message": error.msg})
        except (OSError, UnicodeError) as error:
            diagnostics.append({"file": str(candidate), "line": None, "severity": "error",
                                "code": "read-error", "message": str(error)})
    requested = checks or []
    if "ruff" in requested and shutil.which("ruff"):
        completed = subprocess.run(["ruff", "check", "--output-format", "json", str(target)],
                                   capture_output=True, text=True, timeout=SPEC.timeout, check=False)
        try:
            for item in json.loads(completed.stdout or "[]"):
                diagnostics.append({"file": item["filename"], "line": item["location"]["row"],
                                    "column": item["location"]["column"], "severity": "warning",
                                    "code": item["code"], "message": item["message"]})
        except json.JSONDecodeError:
            pass
    return {"path": str(target), "backend": ["python-ast"] + (["ruff"] if "ruff" in requested and shutil.which("ruff") else []),
            "diagnostics": diagnostics, "count": len(diagnostics), "files_checked": min(500, len(files)),
            "passed": bool(files) and not diagnostics and len(files) <= 500,
            "exit_code": 0 if files and not diagnostics and len(files) <= 500 else 1,
            "_truncated": len(files) > 500}
