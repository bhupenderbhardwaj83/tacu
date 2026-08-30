"""Surgical exact-match editing (Claude StrReplace / Codex apply_patch hunks)."""

from __future__ import annotations

import difflib
import os
import re
import tempfile
from typing import Any

from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "edit_file",
    "Replace exact text in an existing file. One hunk or several applied atomically.",
    schema(properties={"path": {"type": "string"}, "old_text": {"type": "string"},
                       "new_text": {"type": "string"}, "expected_matches": {"type": "integer"},
                       "replace_all": {"type": "boolean"}, "edits": {"type": "array"}},
           required=("path",)),
    schema(properties={"changed": {"type": "boolean"}, "diff": {"type": "string"}}),
    risk_level="write", permissions=("workspace:read", "workspace:write"), idempotent=False,
    when_to_use=(
        "Change an existing file: replace, append, or prepend by swapping exact old_text for new_text. "
        "Prefer this over write_file for surgical edits. Use replace_all to change every occurrence. "
        "Use edits=[{old_text,new_text}, ...] for multiple hunks in one atomic write. "
        "Copy old_text from Current file or read_file.text — never numbered `12 | ` prefixes."
    ),
    when_not=(
        "Do not use to create a new file (write_file), delete a file (filesystem.delete), "
        "or dump the whole file when a unique old_text exists."
    ),
)

_NUMBERED_GUTTER = re.compile(r"(?m)^[ \t]*\d+[ \t]*\|[ \t]?")


def _plain(text: str) -> str:
    """Drop numbered-read gutters so models can paste read_file output as old_text."""

    return _NUMBERED_GUTTER.sub("", text)


def _excerpt(original: str, *, limit: int = 40) -> str:
    lines = original.splitlines()
    if len(lines) <= limit:
        return original
    head, tail = lines[: limit // 2], lines[-(limit // 2):]
    return "\n".join([*head, "…", *tail])


def _replace_nth(original: str, old: str, new: str, *, which: str) -> str:
    if which == "first":
        return original.replace(old, new, 1)
    if which == "last":
        index = original.rfind(old)
        if index < 0:
            return original
        return original[:index] + new + original[index + len(old):]
    return original.replace(old, new)


def _hunks(old_text: str, new_text: str | None, edits: list[Any] | None) -> list[tuple[str, str]]:
    if isinstance(edits, list) and edits:
        hunks: list[tuple[str, str]] = []
        for item in edits:
            if not isinstance(item, dict):
                raise ToolFailure("Each edits[] item must be an object with old_text and new_text.",
                                  code="invalid_input")
            old = str(item.get("old_text") or "")
            if not old or "new_text" not in item:
                raise ToolFailure("edits[] items need old_text and new_text.", code="invalid_input")
            hunks.append((old, str(item.get("new_text") or "")))
        return hunks
    if not old_text or new_text is None:
        raise ToolFailure("edit_file needs old_text and new_text, or edits[].", code="invalid_input")
    return [(old_text, new_text)]


def _apply_hunk(original: str, old_text: str, new_text: str, *,
                expected_matches: int, replace_all: bool) -> str:
    old = _plain(old_text)
    new = _plain(new_text)
    count = original.count(old)
    if count == 0 and old != old_text:
        count = original.count(old_text)
        if count:
            old, new = old_text, new_text
    if replace_all:
        if count == 0:
            raise ToolFailure(
                f"replace_all found 0 matches. Excerpt:\n{_excerpt(original)}",
                code="match_count", retryable=True,
            )
        return original.replace(old, new)
    if count != expected_matches:
        if expected_matches == 1 and count > 1 and old and new.startswith(old):
            return _replace_nth(original, old, new, which="last")
        if expected_matches == 1 and count > 1:
            raise ToolFailure(
                f"Expected 1 exact match, found {count}. Set replace_all=true, copy unique old_text, "
                f"or write_file the full updated file. Excerpt:\n{_excerpt(original)}",
                code="match_count", retryable=True,
            )
        raise ToolFailure(
            f"Expected {expected_matches} exact match(es), found {count}; no change made. "
            f"Excerpt:\n{_excerpt(original)}",
            code="match_count", retryable=True,
        )
    return original.replace(old, new, expected_matches)


def execute(context: ToolContext, *, path: str, old_text: str = "", new_text: str | None = None,
            expected_matches: int = 1, replace_all: bool = False,
            edits: list[Any] | None = None) -> dict[str, Any]:
    target = context.resolved_path(path, mutate=True)
    if not target.is_file():
        raise ToolFailure(f"Not a file: {path}", code="file_not_found")
    original = target.read_text(encoding="utf-8")
    hunks = _hunks(old_text, new_text, edits)
    changed = original
    for old, new in hunks:
        per = 1 if len(hunks) > 1 else expected_matches
        changed = _apply_hunk(changed, old, new, expected_matches=per, replace_all=replace_all)
    diff = "".join(difflib.unified_diff(original.splitlines(keepends=True), changed.splitlines(keepends=True),
                                         fromfile=str(target), tofile=str(target)))
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(changed)
        os.chmod(temporary_name, target.stat().st_mode)
        os.replace(temporary_name, target)
    finally:
        if os.path.exists(temporary_name): os.unlink(temporary_name)
    first_old = hunks[0][0]
    return {"changed": original != changed, "path": str(target), "matches": original.count(_plain(first_old)),
            "hunks": len(hunks), "diff": diff, "added_lines": len(changed.splitlines()) - len(original.splitlines()),
            "removed_lines": max(0, len(original.splitlines()) - len(changed.splitlines())),
            "line_count": len(changed.splitlines()), "preview": _excerpt(changed, limit=16)}
