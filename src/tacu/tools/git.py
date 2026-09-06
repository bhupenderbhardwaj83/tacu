"""Git repository facts and reviewed mutations without invented flags."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..platform import run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, require_approval, require_named_target, schema

SPEC = ToolSpec(
    "git",
    "Inspect a Git work tree (status, log, diff, branch, remote, show, blame, config, "
    "tags, stashes, reflog) and apply reviewed changes (add, commit, push, pull, fetch, "
    "clone, checkout, merge, reset, revert, restore, stash, tag). Prefer this over "
    "invented git flags. Force-push is never emitted.",
    schema(properties={
        "operation": {"type": "string", "enum": [
            # Reading
            "is_repo", "find_repos", "status", "log", "diff", "diff_staged", "branch",
            "remote", "show", "blame", "config", "tags", "stashes", "describe",
            "shortlog", "reflog", "files", "ahead_behind",
            # Changing — reviewed only
            # "switch" is what people say; checkout is what it does, and the
            # checkout capability answers to both.
            "add", "commit", "push", "pull", "fetch", "clone", "checkout",
            "merge", "reset", "revert", "restore", "stash", "stash_pop", "tag",
        ]},
        "root": {"type": "string"},
        "limit": {"type": "integer"},
        "depth": {"type": "integer"},
        "name": {"type": "string"},
        "message": {"type": "string"},
        "mode": {"type": "string"},
        "target": {"type": "string"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)

_MUTATE = frozenset({
    "add", "commit", "push", "pull", "fetch", "clone", "checkout", "switch",
    "merge", "reset", "revert", "restore", "stash", "stash_pop", "tag",
})
# Reset throws work away, so the mode is named rather than assumed. "hard" is
# allowed because a reviewed request for it is legitimate; it is never default.
_RESET_MODES = {"soft": "--soft", "mixed": "--mixed", "hard": "--hard", "keep": "--keep"}


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


def _text_result(operation: str, repo: Path, raw: dict[str, Any], key: str,
                 *, cap: int = 8000, empty: str = "") -> dict[str, Any]:
    """One shape for every command whose answer is its own output."""

    text = (raw["stdout"] or "").strip()[:cap]
    return {"status": "success" if raw["exit_code"] == 0 else "error",
            "operation": operation, "root": str(repo), key: text or empty,
            "exit_code": raw["exit_code"], "stderr": raw.get("stderr", "")[-1000:],
            "recipe": raw.get("command")}


def _lines_result(operation: str, repo: Path, raw: dict[str, Any], key: str,
                  cap: int) -> dict[str, Any]:
    rows = [line.rstrip() for line in raw["stdout"].splitlines() if line.strip()][:cap]
    return {"status": "success" if raw["exit_code"] == 0 else "error",
            "operation": operation, "root": str(repo), key: rows, "count": len(rows),
            "exit_code": raw["exit_code"], "stderr": raw.get("stderr", "")[-1000:],
            "recipe": raw.get("command")}


def _mutation_result(operation: str, repo: Path, raw: dict[str, Any],
                     **extra: Any) -> dict[str, Any]:
    return {"status": "success" if raw["exit_code"] == 0 else "error",
            "operation": operation, "root": str(repo), "exit_code": raw["exit_code"],
            "stdout": (raw.get("stdout") or "").strip()[-2000:],
            "stderr": raw.get("stderr", "")[-1000:], "recipe": raw.get("command"), **extra}


def _safe_ref(value: str | None, operation: str) -> str:
    """A branch, tag or commit — never a flag, never shell punctuation."""

    text = require_named_target(value, operation)
    if text.startswith("-"):
        raise ToolFailure(f"{operation} refused a flag-like reference.", code="invalid_arguments")
    return text


def execute(context: ToolContext, *, operation: str, root: str | None = None,
            limit: int = 40, depth: int = 5, name: str | None = None,
            message: str | None = None, mode: str | None = None,
            target: str | None = None) -> dict[str, Any]:
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

    if operation == "clone":
        # Cloning creates the repository, so it cannot require being inside one.
        require_approval(context, "git.clone")
        source = _safe_ref(name, "git.clone")
        destination = (target or "").strip()
        if destination.startswith("-"):
            raise ToolFailure("git.clone refused a flag-like destination.",
                              code="invalid_arguments")
        argv = ["clone", "--", source] + ([destination] if destination else [])
        raw = run_argv([_git(), "-C", str(base), *argv], timeout=300)
        return _mutation_result("clone", base, raw, name=source,
                                target=destination or None)

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
        if operation in {"pull", "fetch"}:
            remote = (name or "").strip()
            argv = [operation] + ([_safe_ref(remote, f"git.{operation}")] if remote else [])
            raw = _git_run(repo, argv, timeout=300)
            return _mutation_result(operation, repo, raw, name=remote or None)
        if operation in {"checkout", "switch"}:
            ref = _safe_ref(name, f"git.{operation}")
            # `--` separates the ref from any path, so a branch named like a file
            # cannot be read as one.
            raw = _git_run(repo, [operation, ref])
            return _mutation_result(operation, repo, raw, name=ref)
        if operation == "merge":
            ref = _safe_ref(name, "git.merge")
            raw = _git_run(repo, ["merge", "--no-edit", ref])
            return _mutation_result(operation, repo, raw, name=ref)
        if operation == "reset":
            chosen = (mode or "mixed").strip().casefold()
            if chosen not in _RESET_MODES:
                raise ToolFailure(
                    f"git.reset mode must be one of {', '.join(sorted(_RESET_MODES))}.",
                    code="invalid_arguments")
            ref = (name or "").strip()
            argv = ["reset", _RESET_MODES[chosen]]
            if ref:
                argv.append(_safe_ref(ref, "git.reset"))
            raw = _git_run(repo, argv)
            return _mutation_result(operation, repo, raw, mode=chosen, name=ref or None)
        if operation == "revert":
            ref = _safe_ref(name, "git.revert")
            raw = _git_run(repo, ["revert", "--no-edit", ref])
            return _mutation_result(operation, repo, raw, name=ref)
        if operation == "restore":
            path = _safe_ref(name, "git.restore")
            raw = _git_run(repo, ["restore", "--", path])
            return _mutation_result(operation, repo, raw, name=path)
        if operation == "stash":
            text = (message or "").strip()
            argv = ["stash", "push"] + (["-m", text] if text else [])
            raw = _git_run(repo, argv)
            return _mutation_result(operation, repo, raw, message=text or None)
        if operation == "stash_pop":
            raw = _git_run(repo, ["stash", "pop"])
            return _mutation_result(operation, repo, raw)
        if operation == "tag":
            label = _safe_ref(name, "git.tag")
            text = (message or "").strip()
            argv = ["tag", "-a", label, "-m", text or label] if text else ["tag", label]
            raw = _git_run(repo, argv)
            return _mutation_result(operation, repo, raw, name=label, message=text or None)
        remote = (name or "").strip()
        argv = ["push"] if not remote else ["push", require_named_target(remote, "git.push")]
        if any(part.startswith("-") for part in argv[1:]):
            raise ToolFailure("git.push refused a flag-like remote.", code="invalid_arguments")
        raw = _git_run(repo, argv, timeout=300)
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
    if operation == "diff_staged":
        raw = _git_run(repo, ["diff", "--staged", "--stat"])
        return _text_result(operation, repo, raw, "diff", empty="Nothing is staged.")
    if operation == "show":
        ref = (name or "HEAD").strip()
        raw = _git_run(repo, ["show", "--stat", "--no-color", _safe_ref(ref, "git.show")])
        return _text_result(operation, repo, raw, "commit", empty="No such commit.")
    if operation == "blame":
        path = _safe_ref(name, "git.blame")
        raw = _git_run(repo, ["blame", "--line-porcelain", "-L", f"1,{cap}", "--", path])
        authors: dict[str, int] = {}
        for line in raw["stdout"].splitlines():
            if line.startswith("author "):
                who = line[7:].strip()
                authors[who] = authors.get(who, 0) + 1
        ranked = sorted(authors.items(), key=lambda pair: -pair[1])
        return {"status": "success" if raw["exit_code"] == 0 else "error",
                "operation": operation, "root": str(repo), "name": path,
                "authors": [{"author": who, "lines": count} for who, count in ranked],
                "exit_code": raw["exit_code"], "stderr": raw.get("stderr", "")[-1000:],
                "recipe": raw.get("command")}
    if operation == "config":
        # Every setting in force here, which is what "show me the git settings" means.
        raw = _git_run(repo, ["config", "--list", "--show-origin"])
        settings: list[dict[str, str]] = []
        for line in raw["stdout"].splitlines():
            if "\t" not in line:
                continue
            origin, assignment = line.split("\t", 1)
            key, _, value = assignment.partition("=")
            settings.append({"key": key, "value": value, "origin": origin})
        wanted = (name or "").strip().casefold()
        if wanted:
            settings = [item for item in settings if wanted in item["key"].casefold()]
        return {"status": "success" if raw["exit_code"] == 0 else "error",
                "operation": operation, "root": str(repo), "settings": settings[:200],
                "count": len(settings), "query": wanted or None,
                "exit_code": raw["exit_code"], "recipe": raw.get("command")}
    if operation == "tags":
        raw = _git_run(repo, ["tag", "--sort=-creatordate", "-n1"])
        return _lines_result(operation, repo, raw, "tags", cap)
    if operation == "stashes":
        raw = _git_run(repo, ["stash", "list"])
        return _lines_result(operation, repo, raw, "stashes", cap)
    if operation == "describe":
        raw = _git_run(repo, ["describe", "--tags", "--always", "--dirty"])
        return _text_result(operation, repo, raw, "description", empty="No description.")
    if operation == "shortlog":
        raw = _git_run(repo, ["shortlog", "-sn", "--all", "--no-merges"])
        return _lines_result(operation, repo, raw, "contributors", cap)
    if operation == "reflog":
        raw = _git_run(repo, ["reflog", "-n", str(cap)])
        return _lines_result(operation, repo, raw, "entries", cap)
    if operation == "files":
        raw = _git_run(repo, ["ls-files"])
        return _lines_result(operation, repo, raw, "files", cap)
    if operation == "ahead_behind":
        raw = _git_run(repo, ["rev-list", "--left-right", "--count", "@{upstream}...HEAD"])
        counts = (raw["stdout"] or "").split()
        behind, ahead = (counts + ["0", "0"])[:2]
        return {"status": "success" if raw["exit_code"] == 0 else "error",
                "operation": operation, "root": str(repo),
                "ahead": int(ahead) if ahead.isdigit() else 0,
                "behind": int(behind) if behind.isdigit() else 0,
                "exit_code": raw["exit_code"], "stderr": raw.get("stderr", "")[-1000:],
                "recipe": raw.get("command")}
    raw = _git_run(repo, ["remote", "-v"])
    remotes = [line.rstrip() for line in raw["stdout"].splitlines() if line.strip()][:cap]
    return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
            "root": str(repo), "remotes": remotes, "count": len(remotes),
            "exit_code": raw["exit_code"]}
