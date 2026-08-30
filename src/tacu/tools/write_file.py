"""Safe, atomic workspace file creation."""

from __future__ import annotations

import os
import tempfile
from typing import Any

from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "write_file",
    "Create a new source file or overwrite a complete file atomically.",
    schema(properties={"path": {"type": "string"}, "content": {"type": "string"},
                       "overwrite": {"type": "boolean"}, "create_parents": {"type": "boolean"}},
           required=("path", "content")),
    schema(properties={"created": {"type": "boolean"}, "path": {"type": "string"}, "bytes_written": {"type": "integer"}}),
    risk_level="write", permissions=("workspace:write",), idempotent=False,
    when_to_use=(
        "Create a new .py/.sh/.js file, or rewrite an entire existing file when the full updated body is known. "
        "content must be the complete file. Set overwrite=true when replacing an existing file."
    ),
    when_not=(
        "Do not use for a small change in an existing file (edit_file). "
        "Do not use to delete (filesystem.delete), run a program (shell), or write notes/HTML (filesystem.write)."
    ),
)


def execute(context: ToolContext, *, path: str, content: str, overwrite: bool = False,
            create_parents: bool = True) -> dict[str, Any]:
    if not str(content or "").strip():
        raise ToolFailure("write_file requires non-empty content.", code="empty_content", retryable=True)
    target = context.resolved_path(path, mutate=True)
    existed = target.exists()
    if existed and not overwrite:
        raise ToolFailure(f"File exists and overwrite=false: {path}", code="file_exists")
    if create_parents: target.parent.mkdir(parents=True, exist_ok=True)
    if not target.parent.is_dir():
        raise ToolFailure(f"Parent directory does not exist: {target.parent}", code="parent_missing")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream: stream.write(content)
        os.replace(temporary_name, target)
    finally:
        if os.path.exists(temporary_name): os.unlink(temporary_name)
    return {"created": not existed, "overwritten": existed, "path": str(target),
            "bytes_written": len(content.encode()), "line_count": len(content.splitlines()),
            "preview": "\n".join(content.splitlines()[-12:])}
