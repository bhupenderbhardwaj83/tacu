"""Read bounded, numbered lines within the approved workspace."""

from __future__ import annotations

from typing import Any

from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "read_file",
    "Read one workspace file. Returns numbered lines (content) and raw source (text).",
    schema(properties={"path": {"type": "string"}, "start_line": {"type": "integer"},
                       "end_line": {"type": "integer"}, "offset": {"type": "integer"},
                       "limit": {"type": "integer"}, "max_chars": {"type": "integer"}},
           required=("path",)),
    schema(properties={"path": {"type": "string"}, "content": {"type": "string"}, "text": {"type": "string"},
                       "line_count": {"type": "integer"}}),
    when_to_use=(
        "Inspect an existing file before editing, or when the user asked to show/cat/read it. "
        "Use offset/limit (or start_line/end_line) for large files. Copy old_text from `text`, not numbered content."
    ),
    when_not=(
        "Do not use to search many files (search_code), list a directory (repo_map), "
        "create/overwrite (write_file), or apply a change (edit_file)."
    ),
)


def execute(context: ToolContext, *, path: str, start_line: int = 1,
            end_line: int | None = None, offset: int | None = None, limit: int | None = None,
            max_chars: int = 30_000) -> dict[str, Any]:
    target = context.resolved_path(path, mutate=False)
    if not target.is_file():
        raise ToolFailure(f"Not a readable file: {path}", code="file_not_found")
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, offset if offset is not None else start_line)
    if limit is not None:
        end = min(len(lines), start + max(1, limit) - 1)
    else:
        end = min(len(lines), end_line if end_line is not None else start + 199)
    numbered = "\n".join(f"{number:>5} | {lines[number-1]}" for number in range(start, end + 1))
    raw = "\n".join(lines[start - 1:end])
    truncated = len(numbered) > max_chars or len(raw) > max_chars
    if truncated:
        numbered = numbered[:max_chars]
        raw = raw[:max_chars]
    return {"path": str(target), "start_line": start, "end_line": end, "line_count": len(lines),
            "content": numbered, "text": raw, "_truncated": truncated}
