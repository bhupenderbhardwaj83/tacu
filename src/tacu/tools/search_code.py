"""Search files for text. Prefers ripgrep; falls back to a stdlib walk."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "search_code",
    "Grep the workspace for a string or regex (ripgrep, else a bounded walk).",
    schema(properties={"query": {"type": "string"}, "path": {"type": "string"}, "regex": {"type": "boolean"},
                       "case_sensitive": {"type": "boolean"}, "max_results": {"type": "integer"},
                       "glob": {"type": "string"}}, required=("query",)),
    schema(properties={"matches": {"type": "array"}, "count": {"type": "integer"}}),
    when_to_use=(
        "Find text, symbols, TODOs, or a pattern across files. Set glob to limit by name (*.py). "
        "This is the grep tool — prefer it over shell rg/grep."
    ),
    when_not=(
        "Do not use to find files by name only (repo_map find), read one known file (read_file), "
        "or inspect a Python def/class (inspect_symbol)."
    ),
)

_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".tox", ".eggs",
}
_SKIP_SUFFIXES = {
    ".pyc", ".pyo", ".so", ".dylib", ".o", ".a", ".png", ".jpg", ".jpeg",
    ".gif", ".webp", ".pdf", ".zip", ".gz", ".tgz", ".woff", ".woff2",
}
_MAX_FILE_BYTES = 1_000_000


def execute(context: ToolContext, *, query: str, path: str = ".", regex: bool = False,
            case_sensitive: bool = False, max_results: int = 50,
            glob: str | None = None) -> dict[str, Any]:
    target = context.guarded_path(path)
    binary = shutil.which("rg")
    if binary:
        return _ripgrep(binary, target, query, regex, case_sensitive, max_results, glob)
    return _walk_search(target, query, regex, case_sensitive, max_results, glob)


def _ripgrep(binary: str, target: Path, query: str, regex: bool, case_sensitive: bool,
             max_results: int, glob: str | None) -> dict[str, Any]:
    command = [binary, "--json", "--no-heading"]
    if not regex:
        command.append("--fixed-strings")
    if not case_sensitive:
        command.append("--ignore-case")
    if glob:
        command.extend(["--glob", glob])
    command.extend(["--", query, str(target)])
    completed = subprocess.run(command, capture_output=True, text=True, timeout=SPEC.timeout, check=False)
    if completed.returncode not in {0, 1}:
        raise ToolFailure(completed.stderr.strip() or "ripgrep failed", code="search_failed")
    matches: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        event = json.loads(line)
        if event.get("type") != "match":
            continue
        data = event["data"]
        for submatch in data.get("submatches", []):
            matches.append({"file": data["path"].get("text"), "line": data.get("line_number"),
                            "column": submatch.get("start", 0) + 1,
                            "text": data["lines"].get("text", "").rstrip("\n"),
                            "match": submatch.get("match", {}).get("text", "")})
    return {"query": query, "matches": matches[:max_results], "count": len(matches),
            "engine": "ripgrep", "_truncated": len(matches) > max_results}


def _walk_search(root: Path, query: str, regex: bool, case_sensitive: bool,
                 max_results: int, glob: str | None) -> dict[str, Any]:
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        pattern = re.compile(query if regex else re.escape(query), flags)
    except re.error as error:
        raise ToolFailure(f"Invalid search pattern: {error}", code="invalid_pattern") from error
    glob_pat = (glob or "").strip()
    matches: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix.casefold() in _SKIP_SUFFIXES:
                continue
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            if glob_pat and not _glob_ok(relative, name, glob_pat):
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                sample = path.read_bytes()[:8192]
                if b"\x00" in sample:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for index, line in enumerate(text.splitlines(), 1):
                found = pattern.search(line)
                if found is None:
                    continue
                matches.append({
                    "file": str(path),
                    "line": index,
                    "column": found.start() + 1,
                    "text": line,
                    "match": found.group(0),
                })
                if len(matches) >= max_results:
                    return {"query": query, "matches": matches, "count": len(matches),
                            "engine": "walk", "_truncated": True}
    return {"query": query, "matches": matches, "count": len(matches),
            "engine": "walk", "_truncated": False}


def _glob_ok(relative: str, name: str, glob_pat: str) -> bool:
    return fnmatch(name, glob_pat) or fnmatch(relative, glob_pat)
