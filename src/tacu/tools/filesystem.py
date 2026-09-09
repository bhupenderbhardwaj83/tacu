"""Bounded filesystem find/list/open using pathlib, not invented find/grep syntax."""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from ..platform import detect, run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, require_approval, schema

SPEC = ToolSpec(
    "filesystem",
    "Host file ops: write notes/HTML, delete, find by name, serve, open. Not source CRUD.",
    schema(properties={
        "operation": {"type": "string", "enum": ["find", "list", "open", "read", "metadata", "size",
                                                 "disk_usage", "hash", "permissions", "write", "serve", "delete"]},
        "name": {"type": "string"},
        "root": {"type": "string"},
        "glob": {"type": "string"},
        "limit": {"type": "integer"},
        "depth": {"type": "integer"},
        "content": {"type": "string"},
        "overwrite": {"type": "boolean"},
        "port": {"type": "integer"},
        "open_browser": {"type": "boolean"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
    when_to_use=(
        "write: create a note/HTML page. delete: remove a named file. "
        "find: locate a file/folder by name on Desktop/Downloads. serve: local HTTP preview."
    ),
    when_not=(
        "Do not use write for .py/.sh source (write_file), delete for OS-critical paths, "
        "or find for content search (search_code)."
    ),
)

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".bmp", ".svg", ".tif", ".tiff"}
DEFAULT_WEBSITE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Simple Website</title>
</head>
<body>
  <h1>Hello World</h1>
  <p>This is a simple website served by TACU.</p>
</body>
</html>
"""


def _os_critical(path: Path) -> bool:
    from ..automation import os_critical_path
    return os_critical_path(path)


def _write_file(context: ToolContext, *, name: str | None, content: str | None, overwrite: bool) -> dict[str, Any]:
    target_name = (name or "note.txt").strip()
    if target_name.startswith("./"):
        target_name = target_name[2:]
    if not target_name:
        raise ToolFailure("A file name is required to write.", code="invalid_input")
    if content is None:
        body = DEFAULT_WEBSITE_HTML if target_name.casefold().endswith((".html", ".htm")) else ""
    else:
        body = content
    if len(body) > 100_000:
        raise ToolFailure("File content exceeds the 100 KB native write limit.", code="too_large")
    target = context.resolved_path(target_name, mutate=True)
    existed = target.exists()
    if existed and not overwrite:
        raise ToolFailure(f"File exists and overwrite=false: {target}", code="file_exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    import tempfile
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(body)
        os.replace(temporary_name, target)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return {
        "status": "success",
        "operation": "write",
        "path": str(target),
        "name": target.name,
        "created": not existed,
        "overwritten": existed,
        "bytes_written": len(body.encode()),
        "exit_code": 0,
    }


def _delete_file(context: ToolContext, *, name: str | None) -> dict[str, Any]:
    target_name = (name or "").strip()
    if not target_name:
        raise ToolFailure("A file name is required to delete.", code="invalid_input")
    target = context.resolved_path(target_name, mutate=True)
    if not target.exists():
        return {
            "status": "no_results",
            "operation": "delete",
            "path": str(target),
            "name": target.name,
            "deleted": False,
            "exit_code": 0,
        }
    if target.is_dir():
        raise ToolFailure("Directory delete is not allowed via native filesystem.delete.", code="is_directory")
    target.unlink()
    return {
        "status": "success",
        "operation": "delete",
        "path": str(target),
        "name": target.name,
        "deleted": True,
        "exit_code": 0,
    }


def _free_port(start: int) -> int:
    for port in range(max(1, start), max(1, start) + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise ToolFailure("No free local port was available for the HTTP server.", code="no_port")


def _serve(context: ToolContext, *, port: int, open_browser: bool) -> dict[str, Any]:
    require_approval(
        context, "filesystem.serve",
        f"Run it through the reviewed lane: ti do serve this folder — or yourself: "
        f"python3 -m http.server {port or 8000} --bind 127.0.0.1 (from {context.workspace}).")
    if _os_critical(context.workspace):
        raise ToolFailure("OS-critical paths cannot be served.", code="os_critical")
    chosen = _free_port(port or 8000)
    python = which("python3") or sys.executable
    process = subprocess.Popen(
        [python, "-m", "http.server", str(chosen), "--bind", "127.0.0.1"],
        cwd=str(context.workspace),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    time.sleep(0.25)
    if process.poll() is not None:
        raise ToolFailure("The local HTTP server exited immediately.", code="serve_failed")
    url = f"http://127.0.0.1:{chosen}/"
    opened = False
    browser = None
    if open_browser:
        if detect().os == "macos":
            chrome = run_argv(["open", "-a", "Google Chrome", url], timeout=8)
            if chrome.get("exit_code") == 0:
                opened, browser = True, "Google Chrome"
            else:
                fallback = run_argv(["open", url], timeout=8)
                opened, browser = fallback.get("exit_code") == 0, "default browser"
        elif which("xdg-open"):
            fallback = run_argv(["xdg-open", url], timeout=8)
            opened, browser = fallback.get("exit_code") == 0, "default browser"
    return {
        "status": "success",
        "operation": "serve",
        "url": url,
        "port": chosen,
        "pid": process.pid,
        "cwd": str(context.workspace),
        "opened": opened,
        "browser": browser,
        "exit_code": 0,
    }


def _roots(root: str | None, workspace: Path) -> list[Path]:
    if root:
        candidate = Path(root).expanduser()
        return [candidate.resolve()] if candidate.exists() else []
    seen: list[Path] = []
    for item in (Path.cwd(), workspace, Path.home() / "Downloads", Path.home() / "Desktop"):
        try:
            resolved = item.expanduser().resolve()
        except OSError:
            continue
        if resolved not in seen and resolved.is_dir():
            seen.append(resolved)
    return seen


def _walk(root: Path, *, depth: int, limit: int) -> list[Path]:
    matches: list[Path] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            relative = Path(dirpath).relative_to(root)
            parts = relative.parts
            if parts != (".",) and len(parts) >= depth:
                dirnames[:] = []
            if any(name in {".git", ".venv", "node_modules", "__pycache__", "Library"} for name in Path(dirpath).parts):
                dirnames[:] = []
                continue
            for name in filenames + dirnames:
                matches.append(Path(dirpath) / name)
                if len(matches) >= limit * 20:
                    return matches
    except OSError:
        return matches
    return matches


def execute(context: ToolContext, *, operation: str, name: str | None = None, root: str | None = None,
            glob: str | None = None, limit: int = 40, depth: int = 4, content: str | None = None,
            overwrite: bool = True, port: int | None = None, open_browser: bool = False) -> dict[str, Any]:
    if operation == "write":
        return _write_file(context, name=name, content=content, overwrite=overwrite)
    if operation == "serve":
        return _serve(context, port=int(port or 8000), open_browser=bool(open_browser))
    if operation == "delete":
        return _delete_file(context, name=name)
    cap = max(1, min(int(limit or 40), 200))
    max_depth = max(1, min(int(depth or 4), 8))
    needle = (name or "").strip().strip("'\"`")
    kind = (glob or "").casefold()
    hits: list[dict[str, Any]] = []
    scanned: list[dict[str, Any]] = []
    searched = [str(item) for item in _roots(root, context.workspace)]
    for base in _roots(root, context.workspace):
        for path in _walk(base, depth=max_depth, limit=cap):
            try:
                is_dir = path.is_dir()
            except OSError:
                continue
            label = path.name
            if kind in {"image", "images"} and path.suffix.casefold() not in IMAGE_SUFFIXES:
                continue
            item = {"path": str(path), "name": label, "kind": "directory" if is_dir else "file"}
            if len(scanned) < cap:
                scanned.append(item)
            if needle and needle.casefold() not in label.casefold() and needle.casefold() not in str(path).casefold():
                continue
            hits.append(item)
            if len(hits) >= cap:
                break
        if len(hits) >= cap:
            break
    # A name that matched nothing was derived from the question by regex, so an
    # empty result says the guess missed — never that the directory is empty.
    # Hand back what is actually there and say plainly that the name did not
    # match, rather than reporting an absence nobody established.
    widened = ""
    if needle and not hits and scanned:
        hits = scanned
        widened = (f"nothing here is named like \u201c{needle}\u201d; "
                   f"these are the files that were searched")
    files = [item for item in hits if item["kind"] == "file"]
    if operation == "open":
        target = Path((files or hits)[0]["path"]) if (files or hits) else None
        if target is None or not target.exists():
            return {"status": "no_results", "operation": operation, "query": needle, "matches": [],
                    "searched": searched, "exit_code": 1}
        opener = "open" if detect().os == "macos" else ("xdg-open" if which("xdg-open") else None)
        if not opener:
            raise ToolFailure("No native open command is available.", code="unavailable")
        raw = run_argv([opener, str(target)], timeout=SPEC.timeout)
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "path": str(target), "matches": hits[:1], "exit_code": raw["exit_code"],
                "stderr": raw.get("stderr", "")}
    if operation == "read":
        if not files:
            return {"status": "no_results", "operation": operation, "query": needle, "matches": hits,
                    "content": None, "searched": searched, "exit_code": 0}
        target = Path(files[0]["path"])
        try:
            text = target.read_text(errors="replace")
        except OSError as error:
            return {"status": "error", "operation": operation, "path": str(target),
                    "error": str(error), "matches": files[:1], "exit_code": 1}
        preview_lines = text.splitlines()[:80]
        preview = "\n".join(preview_lines)
        if len(preview) > 4_000:
            preview = preview[:4_000] + "\n…"
        return {"status": "success", "operation": operation, "path": str(target),
                "matches": files[:1], "content": preview, "line_count": len(text.splitlines()),
                "truncated": len(text.splitlines()) > 80 or len(text) > 4_000, "exit_code": 0}
    if operation in {"metadata", "size", "hash", "permissions", "disk_usage"}:
        target = None
        if needle:
            candidate = Path(needle).expanduser()
            if candidate.exists():
                target = candidate
            elif hits:
                target = Path(hits[0]["path"])
        elif root:
            candidate = Path(root).expanduser()
            if candidate.exists():
                target = candidate
        elif hits:
            target = Path(hits[0]["path"])
        else:
            target = Path.cwd()
        if target is None or not target.exists():
            return {"status": "no_results", "operation": operation, "query": needle, "matches": hits,
                    "searched": searched, "exit_code": 0}
        try:
            stat = target.stat()
        except OSError as error:
            return {"status": "error", "operation": operation, "path": str(target), "error": str(error), "exit_code": 1}
        info = {"path": str(target), "name": target.name, "kind": "directory" if target.is_dir() else "file",
                "bytes": stat.st_size, "permissions": oct(stat.st_mode)[-3:], "mtime": int(stat.st_mtime)}
        if operation == "hash" and target.is_file():
            digest = hashlib.sha256()
            with target.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    if handle.tell() > 64 * 1024 * 1024:
                        break
            info["sha256"] = digest.hexdigest()
        if operation == "disk_usage":
            if which("du") and target.is_dir():
                raw = run_argv(["du", "-hd", "1", str(target)], timeout=SPEC.timeout)
                info["usage"] = raw["stdout"].splitlines()[:30]
            elif which("df"):
                raw = run_argv(["df", "-h", str(target)], timeout=8)
                info["usage"] = raw["stdout"].splitlines()[:12]
        return {"status": "success", "operation": operation, "path": str(target), "metadata": info,
                "matches": [{"path": str(target), "name": target.name,
                             "kind": "directory" if target.is_dir() else "file"}],
                "exit_code": 0}
    status = "success" if hits else "no_results"
    return {
        "status": status, "operation": operation, "query": needle or glob, "root": root,
        "matches": hits, "count": len(hits), "searched": searched, "widened": widened,
        "exit_code": 0,
    }
