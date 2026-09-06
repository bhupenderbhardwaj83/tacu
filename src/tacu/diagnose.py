"""Read a failure and say what to do about it.

The harness previously knew only that an exit code was not zero, so its idea of a
correction was to run the same command again. An engineer does not do that: they
read the error, recognise the class of problem, and change something. This module
holds that reading — failure signature in, concrete next steps out.

Two rules keep it honest:

* Never propose the step that just failed. A remedy that repeats the action is not
  a remedy, and repeating it is what made the loop look broken.
* Respect the project. A lockfile already records which package manager this
  project uses; switching to a "better" one behind the user's back would produce a
  second lockfile and break reproducibility for everyone else.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

# What a missing dependency looks like, per ecosystem.
_PY_MISSING_MODULE = re.compile(r"ModuleNotFoundError: No module named '([A-Za-z0-9_.]+)'")
_PY_IMPORT_ERROR = re.compile(r"ImportError: cannot import name .* from '([A-Za-z0-9_.]+)'")
_NODE_MISSING_MODULE = re.compile(r"Cannot find module '([@A-Za-z0-9_./-]+)'")
_MISSING_COMMAND = re.compile(r"(?:command not found|not found): ?([A-Za-z0-9_.+-]+)|"
                              r"([A-Za-z0-9_.+-]+): command not found")
_PERMISSION_DENIED = re.compile(r"permission denied: (\S+)", re.I)
_EXTERNALLY_MANAGED = re.compile(r"externally-managed-environment")

# Import name differs from the distribution name often enough to be worth knowing,
# and getting this wrong installs the wrong package.
_DISTRIBUTION_NAMES = {
    "cv2": "opencv-python", "yaml": "PyYAML", "PIL": "Pillow", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "dotenv": "python-dotenv", "jwt": "PyJWT", "serial": "pyserial",
    "dateutil": "python-dateutil", "attr": "attrs", "OpenSSL": "pyOpenSSL",
}

VENV_DIRECTORIES = (".venv", "venv", "env")


def distribution_for(module: str) -> str:
    """The package to install for an import name."""

    root = module.split(".")[0]
    return _DISTRIBUTION_NAMES.get(root, root)


def existing_venv(workspace: Path) -> Path | None:
    for name in VENV_DIRECTORIES:
        candidate = workspace / name
        if (candidate / "bin" / "python").exists() or (candidate / "Scripts" / "python.exe").exists():
            return candidate
    return None


def venv_binary(venv: Path, name: str) -> str:
    """Path to a tool inside an environment, so nothing depends on shell activation.

    `activate` only edits the shell it is sourced into; a subprocess never sees it.
    Calling the environment's own binary is what actually works.
    """

    windows = venv / "Scripts" / f"{name}.exe"
    if windows.exists():
        return str(windows)
    return str(venv / "bin" / name)


def python_installer(workspace: Path, venv: Path | None) -> dict[str, Any]:
    """Which tool should install Python packages here, and why.

    A lockfile is a decision the project already made, so it wins. `uv` is only
    preferred where nothing is pinned and it is actually installed.
    """

    if (workspace / "uv.lock").exists() and shutil.which("uv"):
        return {"tool": "uv", "reason": "uv.lock pins this project to uv"}
    if (workspace / "poetry.lock").exists() and shutil.which("poetry"):
        return {"tool": "poetry", "reason": "poetry.lock pins this project to poetry"}
    if (workspace / "Pipfile.lock").exists() and shutil.which("pipenv"):
        return {"tool": "pipenv", "reason": "Pipfile.lock pins this project to pipenv"}
    if venv is None and shutil.which("uv"):
        return {"tool": "uv", "reason": "nothing pins a tool here and uv is installed"}
    return {"tool": "pip", "reason": "using the environment's own pip"}


def node_installer(workspace: Path) -> dict[str, Any]:
    """The project's lockfile decides; pnpm only when nothing is pinned."""

    if (workspace / "pnpm-lock.yaml").exists():
        return {"tool": "pnpm", "reason": "pnpm-lock.yaml pins this project to pnpm"}
    if (workspace / "yarn.lock").exists():
        return {"tool": "yarn", "reason": "yarn.lock pins this project to yarn"}
    if (workspace / "package-lock.json").exists():
        return {"tool": "npm", "reason": "package-lock.json pins this project to npm"}
    if shutil.which("pnpm"):
        return {"tool": "pnpm", "reason": "nothing pins a tool here and pnpm is installed"}
    return {"tool": "npm", "reason": "npm is the fallback"}


def _shell_step(executable: str, args: list[str], purpose: str) -> dict[str, Any]:
    return {"tool": "shell", "operation": "run",
            "inputs": {"executable": executable, "args": args, "cwd": "."},
            "purpose": purpose}


def _python_dependency_remedy(module: str, workspace: Path,
                              rerun: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Create an isolated environment if needed, install into it, then retry there."""

    package = distribution_for(module)
    venv = existing_venv(workspace)
    steps: list[dict[str, Any]] = []
    target = venv or (workspace / ".venv")
    if venv is None:
        steps.append(_shell_step("python3", ["-m", "venv", ".venv"],
                                 "Create an isolated environment for this project"))
    installer = python_installer(workspace, venv)
    if installer["tool"] == "uv":
        steps.append(_shell_step("uv", ["pip", "install", "--python", venv_binary(target, "python"),
                                        package],
                                 f"Install {package} into the project environment with uv"))
    else:
        steps.append(_shell_step(venv_binary(target, "python"), ["-m", "pip", "install", package],
                                 f"Install {package} into the project environment"))
    if rerun is not None:
        arguments = list((rerun.get("inputs") or {}).get("args") or [])
        steps.append(_shell_step(venv_binary(target, "python"), arguments,
                                 "Run it again inside the environment that now has the package"))
    return steps


def _node_dependency_remedy(module: str, workspace: Path) -> list[dict[str, Any]]:
    installer = node_installer(workspace)
    return [_shell_step(installer["tool"], ["install", module],
                        f"Install {module} with {installer['tool']} ({installer['reason']})")]


def failure_text(results: list[dict[str, Any]]) -> str:
    """Everything a failed step said, newest last."""

    parts: list[str] = []
    for item in results:
        data = ((item.get("result") or {}).get("data") or {})
        if data.get("exit_code") in (None, 0):
            continue
        for key in ("stderr", "stdout"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                parts.append(value)
            elif isinstance(value, dict) and isinstance(value.get("text"), str):
                parts.append(value["text"])
    return "\n".join(parts)


def last_failed_step(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The command that failed, so a retry can be aimed at the same target.

    A result records "step" as its position in the plan, not the step itself; the
    argv is what identifies the attempt.
    """

    for item in reversed(results):
        data = ((item.get("result") or {}).get("data") or {})
        if data.get("exit_code") in (None, 0):
            continue
        command = item.get("command") or data.get("command") or []
        command = [str(part) for part in command if isinstance(part, (str, int))]
        if command:
            return {"tool": "shell", "operation": "run",
                    "inputs": {"executable": command[0], "args": command[1:], "cwd": "."}}
    return None


def explain(text: str) -> str:
    """One line naming what went wrong, for the user rather than the planner."""

    module = _PY_MISSING_MODULE.search(text) or _PY_IMPORT_ERROR.search(text)
    if module:
        return (f"{module.group(1)} is not installed in the Python environment this ran with.")
    if _EXTERNALLY_MANAGED.search(text):
        return "This Python is managed by the OS, so packages must go in a virtual environment."
    node = _NODE_MISSING_MODULE.search(text)
    if node:
        return f"The node package {node.group(1)} is not installed here."
    denied = _PERMISSION_DENIED.search(text)
    if denied:
        return f"{denied.group(1)} is not executable."
    missing = _MISSING_COMMAND.search(text)
    if missing:
        return f"{missing.group(1) or missing.group(2)} is not on PATH."
    return ""


def remedy(text: str, workspace: Path,
           failed_step: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Concrete steps that change something, or nothing when we cannot tell."""

    module = _PY_MISSING_MODULE.search(text) or _PY_IMPORT_ERROR.search(text)
    if module:
        return _python_dependency_remedy(module.group(1), workspace, failed_step)
    if _EXTERNALLY_MANAGED.search(text):
        return _python_dependency_remedy("pip", workspace, failed_step)[:1] or []
    node = _NODE_MISSING_MODULE.search(text)
    if node:
        return _node_dependency_remedy(node.group(1), workspace)

    denied = _PERMISSION_DENIED.search(text)
    if denied:
        target = denied.group(1).lstrip("./")
        if target.endswith((".sh", ".bash", ".zsh")):
            # Running it through a shell needs no permission change at all.
            return [_shell_step("sh", [target], f"Run {target} through a shell instead")]
        return [_shell_step("chmod", ["+x", target], f"Make {target} executable")]

    missing = _MISSING_COMMAND.search(text)
    if missing:
        name = missing.group(1) or missing.group(2)
        if name in {"pip", "pip3"}:
            venv = existing_venv(workspace)
            python = venv_binary(venv, "python") if venv else "python3"
            return [_shell_step(python, ["-m", "pip", "--version"],
                                "Use the interpreter's own pip rather than a bare pip")]
    return []
