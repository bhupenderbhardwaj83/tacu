"""Generate a compact repository architecture map."""

from __future__ import annotations

import ast
import fnmatch
from collections import Counter
from pathlib import Path
from typing import Any

from .contracts import ToolContext, ToolSpec, schema

SPEC = ToolSpec(
    "repo_map",
    "List or glob workspace files (tree/map) without dumping file contents.",
    schema(properties={"root": {"type": "string"}, "depth": {"type": "integer"},
                       "symbols": {"type": "boolean"}, "max_files": {"type": "integer"},
                       "name": {"type": "string"}, "kind": {"type": "string", "enum": ["file", "directory", "any"]},
                       "case_sensitive": {"type": "boolean"}}),
    schema(properties={"root": {"type": "string"}, "files": {"type": "array"}, "entries": {"type": "array"},
                       "languages": {"type": "object"}, "entrypoints": {"type": "array"}}),
    when_to_use=(
        "Map a project tree, or glob files by name (name='*.py' or 'Config'). "
        "This is the glob/LS tool — prefer it over find/ls/tree in the shell."
    ),
    when_not=(
        "Do not use to search file contents (search_code), read a file (read_file), "
        "or create a directory-map script (write_file)."
    ),
)

IGNORED = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".mypy_cache", ".pytest_cache"}
LANGUAGES = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".rs": "Rust",
             ".go": "Go", ".java": "Java", ".sh": "Shell", ".rb": "Ruby"}
ENTRYPOINTS = {"pyproject.toml", "package.json", "Cargo.toml", "go.mod", "Makefile", "Dockerfile", "README.md", "main.py", "app.py"}


def _name_matches(relative: Path, name: str, case_sensitive: bool) -> bool:
    path_text = relative.as_posix()
    file_name = relative.name
    pattern = name if case_sensitive else name.casefold()
    candidates = (file_name, path_text) if case_sensitive else (file_name.casefold(), path_text.casefold())
    if any(character in name for character in "*?["):
        return any(fnmatch.fnmatchcase(candidate, pattern) for candidate in candidates)
    return any(pattern in candidate for candidate in candidates)


def execute(context: ToolContext, *, root: str = ".", depth: int = 4,
            symbols: bool = False, max_files: int = 120, name: str | None = None,
            kind: str = "file", case_sensitive: bool = False) -> dict[str, Any]:
    base = context.guarded_path(root)
    patterns: list[str] = []
    ignore = base / ".gitignore"
    if ignore.is_file():
        patterns = [line.strip().rstrip("/") for line in ignore.read_text(errors="replace").splitlines()
                    if line.strip() and not line.startswith("#")]
    files: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    languages: Counter[str] = Counter()
    for path in sorted(base.rglob("*")):
        relative = path.relative_to(base)
        if len(relative.parts) > max(1, depth):
            continue
        if any(part in IGNORED for part in relative.parts):
            continue
        if any(fnmatch.fnmatch(relative.as_posix(), pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in patterns):
            continue
        is_file = path.is_file()
        is_directory = path.is_dir()
        if not (is_file or is_directory):
            continue
        if name:
            allowed = kind == "any" or (kind == "file" and is_file) or (kind == "directory" and is_directory)
            if not allowed or not _name_matches(relative, name, case_sensitive):
                continue
            entry: dict[str, Any] = {"path": relative.as_posix(), "type": "file" if is_file else "directory"}
            if is_file:
                entry["bytes"] = path.stat().st_size
            entries.append(entry)
            if not is_file:
                continue
        elif not is_file:
            continue
        language = LANGUAGES.get(path.suffix)
        if language:
            languages[language] += 1
        item: dict[str, Any] = {"path": relative.as_posix(), "bytes": path.stat().st_size}
        if language:
            item["language"] = language
        if symbols and path.suffix == ".py":
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
                item["symbols"] = [node.name for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))][:20]
            except (OSError, SyntaxError, UnicodeError):
                item["symbols"] = []
        files.append(item)
    files.sort(key=lambda item: (Path(item["path"]).name not in ENTRYPOINTS, item["path"].count("/"), item["path"]))
    entries.sort(key=lambda item: (item["type"] != "directory", item["path"].casefold()))
    truncated = len(files) > max_files or len(entries) > max_files
    return {"root": str(base), "files": files[:max_files], "entries": entries[:max_files],
            "file_count": len(files), "match_count": len(entries), "languages": dict(languages),
            "entrypoints": [item["path"] for item in files if Path(item["path"]).name in ENTRYPOINTS],
            "_truncated": truncated}

