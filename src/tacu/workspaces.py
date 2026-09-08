"""More than one project, remembered, so a long job runs where you are standing.

TACU held a single configured workspace. Run `ti code` from a project it did not
know about and the loop worked somewhere else entirely — asked to run "the flask
app in the current directory" it reported that the directory was empty, because
it was reading `~/TACU-Workspace` while the app sat in `~/Downloads/test_http`.

So workspaces are a set, not a setting. Directories you have worked in are
remembered; standing in one of them is enough to work there. A directory TACU has
not seen before is asked about rather than assumed, because these lanes write
files and running in the wrong place is worse than a question.
"""

from __future__ import annotations

import os
from pathlib import Path

from .configuration import configured_workspace, load_config, save_config, save_workspace

MAX_REMEMBERED = 24

# Directories that are never a project on their own: too broad to write into.
# Resolved, because /tmp is a symlink to /private/tmp on macOS and a plain string
# comparison lets the real path through.
_NEVER_NAMES = ("/", "/tmp", "/var", "/usr", "/etc", "/opt", "/private", "/Users", "/home")


def _never() -> set[Path]:
    resolved: set[Path] = set()
    for name in _NEVER_NAMES:
        candidate = Path(name)
        resolved.add(candidate)
        try:
            resolved.add(candidate.resolve())
        except OSError:
            continue
    return resolved
# What makes a directory look like somewhere work happens.
_MARKER_NAMES = frozenset({
    ".git", "pyproject.toml", "setup.py", "requirements.txt", "Pipfile", "package.json",
    "pom.xml", "build.gradle", "Cargo.toml", "go.mod", "composer.json", "Gemfile",
    "Makefile", "CMakeLists.txt", "Dockerfile", "docker-compose.yml", ".venv", "venv",
    "tsconfig.json", "Web.config", "appsettings.json", "manage.py", "app.py", "main.py",
    "index.html", "index.js",
})
_SOURCE_SUFFIXES = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".rb", ".java", ".kt", ".c",
    ".cpp", ".cs", ".php", ".swift", ".sh", ".html", ".css", ".sql", ".vue", ".svelte",
})


def remembered() -> list[Path]:
    """Workspaces TACU has been told about, newest first."""

    stored = load_config().get("workspaces")
    found: list[Path] = []
    if isinstance(stored, list):
        for item in stored:
            if isinstance(item, str) and item:
                found.append(Path(item))
    current = configured_workspace()
    if current is not None and current not in found:
        found.append(current)
    return found


def remember(path: Path) -> Path:
    """Add a directory to the set, and make it the one in use."""

    # Read the set before switching, so the workspace being replaced is kept
    # rather than dropped — switching should add to the set, not overwrite it.
    previous = [str(item) for item in remembered()]
    workspace = save_workspace(path)          # validates: no root, no system directory
    content = load_config()
    stored = [item for item in content.get("workspaces", []) if isinstance(item, str)]
    for item in previous:
        if item not in stored:
            stored.append(item)
    text = str(workspace)
    stored = [text] + [item for item in stored if item != text]
    content["workspaces"] = stored[:MAX_REMEMBERED]
    save_config(content)
    return workspace


class InUse(Exception):
    """Raised rather than forgetting the workspace currently being used."""


def forget(path: Path) -> bool:
    """Drop a directory from the set. The directory itself is untouched.

    Forgetting the one in use would leave TACU pointing at a workspace it no
    longer lists, so that is refused and the caller is told to switch first.
    """

    target = path.expanduser().resolve()
    current = configured_workspace()
    if current is not None and current.expanduser().resolve() == target:
        raise InUse(str(target))
    text = str(target)
    content = load_config()
    stored = [item for item in content.get("workspaces", []) if isinstance(item, str)]
    if text not in stored:
        return False
    content["workspaces"] = [item for item in stored if item != text]
    save_config(content)
    return True


def containing(path: Path) -> Path | None:
    """The remembered workspace this path sits in, if any."""

    try:
        target = path.expanduser().resolve()
    except OSError:
        return None
    best: Path | None = None
    for candidate in remembered():
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if target == resolved or resolved in target.parents:
            # Prefer the closest one, so a nested project wins over its parent.
            if best is None or len(resolved.parts) > len(best.parts):
                best = resolved
    return best


def looks_like_a_project(path: Path) -> bool:
    """Is this somewhere work happens, rather than a home or a system directory?"""

    try:
        target = path.expanduser().resolve()
    except OSError:
        return False
    if target in _never() or target == Path(target.anchor):
        return False
    if target == Path.home():
        return False
    try:
        children = list(target.iterdir())
    except OSError:
        return False
    if any(child.name in _MARKER_NAMES for child in children):
        return True
    return sum(1 for child in children
               if child.is_file() and child.suffix.casefold() in _SOURCE_SUFFIXES) >= 2


def describe_choice(cwd: Path, configured: Path) -> str:
    return (f"You are in {cwd}\n"
            f"TACU's workspace is {configured}\n"
            "Files are written to the workspace, so this job would not run where you are.")
