"""Git repository facts and reviewed mutations without invented flags."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..platform import run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, require_approval, require_named_target, schema

SPEC = ToolSpec(
    "git",
    "Inspect a Git work tree (status, log, diff, branch, remote) and apply reviewed "
    "add/commit/push. Prefer this over invented git flags. Force-push is never emitted.",
    schema(properties={
        "operation": {"type": "string", "enum": [
            "is_repo", "find_repos", "status", "log", "diff", "branch", "remote",
            "add", "commit", "push",
        ]},
        "root": {"type": "string"},
        "limit": {"type": "integer"},
        "depth": {"type": "integer"},
        "name": {"type": "string"},
        "message": {"type": "string"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)

_MUTATE = frozenset({"add", "commit", "push"})


def _git() -> str:
    binary = which("git")
    if not binary:
        raise ToolFailure("git is not installed or not on PATH.", code="unavailable")
    return binary


def _is_repo(path: Path) -> bool:
    git = path / ".git"
    return git.is_dir() or git.is_file()


def _repo_root(path: Path) -> Path | None:
    current = path.expanduser().resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if _is_repo(candidate):
            return candidate
    return None


def _git_run(root: Path, args: list[str], *, timeout: int | None = None) -> dict[str, Any]:
    argv = [_git(), "-C", str(root), *args]
    return run_argv(argv, timeout=timeout or SPEC.timeout)


def execute(context: ToolContext, *, operation: str, root: str | None = None,
            limit: int = 40, depth: int = 5, name: str | None = None,
            message: str | None = None) -> dict[str, Any]:
    cap = max(1, min(int(limit or 40), 100))
    max_depth = max(1, min(int(depth or 5), 6))
    base = Path(root).expanduser().resolve() if root else Path.cwd().resolve()
    if operation == "is_repo":
        found = _is_repo(base)
        return {"status": "success", "operation": operation, "root": str(base),
                "is_repo": found, "path": str(base) if found else None, "exit_code": 0}
    if operation == "find_repos":
        repos: list[str] = []
        if not base.is_dir():
            return {"status": "no_results", "operation": operation, "root": str(base),
                    "repositories": [], "count": 0, "exit_code": 0}
        try:
            for dirpath, dirnames, _filenames in os.walk(base):
                relative = Path(dirpath).relative_to(base)
                if relative.parts and len(relative.parts) >= max_depth:
                    dirnames[:] = []
                    continue
                current = Path(dirpath)
                if _is_repo(current):
                    repos.append(str(current))
                    dirnames[:] = []
                    if len(repos) >= cap:
                        break
                    continue
                dirnames[:] = [item for item in dirnames if item not in
                               {".git", "node_modules", ".venv", "Library", "__pycache__"}]
        except OSError:
            pass
        return {"status": "success" if repos else "no_results", "operation": operation,
                "root": str(base), "repositories": repos, "count": len(repos), "exit_code": 0,
                "workspace": str(context.workspace)}

    repo = _repo_root(base)
    if repo is None:
        raise ToolFailure(f"{base} is not inside a Git repository.", code="not_a_repo")

    if operation in _MUTATE:
        require_approval(context, f"git.{operation}")
        if operation == "add":
            from ..automation import os_critical_path
            target = require_named_target(name, "git.add")
            candidate = Path(target).expanduser()
            path = (candidate if candidate.is_absolute() else repo / candidate).resolve(strict=False)
            if os_critical_path(path):
                raise ToolFailure(f"OS-critical paths cannot be staged: {path}", code="os_critical")
            raw = _git_run(repo, ["add", "--", str(path)])
            return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                    "name": str(path), "root": str(repo), "exit_code": raw["exit_code"],
                    "stderr": raw.get("stderr", "")[-1000:], "recipe": raw.get("command")}
        if operation == "commit":
            text = require_named_target(message or name, "git.commit")
            raw = _git_run(repo, ["commit", "-m", text])
            return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                    "message": text, "root": str(repo), "exit_code": raw["exit_code"],
                    "stderr": raw.get("stderr", "")[-1000:], "recipe": raw.get("command")}
        remote = (name or "").strip()
        argv = ["push"] if not remote else ["push", require_named_target(remote, "git.push")]
        if any(part.startswith("-") for part in argv[1:]):
            raise ToolFailure("git.push refused a flag-like remote.", code="invalid_arguments")
        raw = _git_run(repo, argv)
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "name": remote or None, "root": str(repo), "exit_code": raw["exit_code"],
                "stderr": raw.get("stderr", "")[-1000:], "recipe": raw.get("command")}

    if operation == "status":
        raw = _git_run(repo, ["status", "--porcelain=v1", "-b"])
        lines = raw["stdout"].splitlines()
        branch = ""
        if lines and lines[0].startswith("## "):
            branch = lines[0][3:].strip()
            lines = lines[1:]
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "root": str(repo), "branch": branch, "changes": lines[:cap], "count": len(lines),
                "is_repo": True, "exit_code": raw["exit_code"], "recipe": raw.get("command")}
    if operation == "log":
        raw = _git_run(repo, ["log", "-n", str(cap), "--oneline"])
        commits = [line for line in raw["stdout"].splitlines() if line.strip()][:cap]
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "root": str(repo), "commits": commits, "count": len(commits),
                "exit_code": raw["exit_code"]}
    if operation == "diff":
        raw = _git_run(repo, ["diff", "--stat"])
        text = (raw["stdout"] or "").strip()[:8000]
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "root": str(repo), "diff": text or "No unstaged differences.",
                "exit_code": raw["exit_code"]}
    if operation == "branch":
        raw = _git_run(repo, ["branch", "-vv"])
        branches = [line.rstrip() for line in raw["stdout"].splitlines() if line.strip()][:cap]
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "root": str(repo), "branches": branches, "count": len(branches),
                "exit_code": raw["exit_code"]}
    raw = _git_run(repo, ["remote", "-v"])
    remotes = [line.rstrip() for line in raw["stdout"].splitlines() if line.strip()][:cap]
    return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
            "root": str(repo), "remotes": remotes, "count": len(remotes),
            "exit_code": raw["exit_code"]}
