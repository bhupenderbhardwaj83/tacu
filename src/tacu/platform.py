"""OS detection, capability probing, and deterministic host command recipes."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PlatformContext:
    os: str
    kernel: str
    architecture: str
    shell: str
    package_manager: str
    ps_flavour: str


_CACHED: PlatformContext | None = None
_LAUNCH_CWD = Path.cwd()


def launch_cwd() -> Path:
    """Directory where this TACU process started (the user's shell cwd)."""

    try:
        return _LAUNCH_CWD.resolve()
    except OSError:
        return Path.cwd()


def detect() -> PlatformContext:
    global _CACHED
    if _CACHED is not None:
        return _CACHED
    system = platform.system()
    if system == "Darwin":
        os_name, flavour, pkg = "macos", "bsd", "brew"
    elif system == "Windows":
        os_name, flavour, pkg = "windows", "windows", "winget"
    else:
        os_name, flavour, pkg = "linux", "gnu", "apt"
    _CACHED = PlatformContext(
        os_name, system, platform.machine() or "unknown",
        Path(os.environ.get("SHELL", "")).name or ("powershell" if system == "Windows" else "sh"),
        pkg, flavour,
    )
    return _CACHED


def which(name: str) -> str | None:
    return shutil.which(name)


def capabilities() -> dict[str, str | None]:
    names = (
        "ps", "lsof", "netstat", "ss", "ifconfig", "route", "launchctl", "defaults",
        "mdls", "codesign", "system_profiler", "docker", "ollama", "rg", "brew",
        "tasklist", "sw_vers", "sysctl",
    )
    return {name: which(name) for name in names}


def run_argv(argv: list[str], *, timeout: int = 20) -> dict[str, Any]:
    """Run an argument vector with no shell interpolation."""

    if not argv:
        return {"exit_code": 127, "stdout": "", "stderr": "empty command", "command": []}
    binary = argv[0]
    resolved = binary if (os.path.isabs(binary) and Path(binary).exists()) else which(Path(binary).name)
    if not resolved:
        return {"exit_code": 127, "stdout": "", "stderr": f"Command not found: {Path(binary).name}",
                "command": argv}
    try:
        completed = subprocess.run([resolved, *argv[1:]], capture_output=True, timeout=max(1, timeout), check=False)
    except PermissionError as error:
        return {"exit_code": 126, "stdout": "", "stderr": str(error), "command": [resolved, *argv[1:]]}
    except OSError as error:
        return {"exit_code": 127, "stdout": "", "stderr": str(error), "command": [resolved, *argv[1:]]}
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, bytes) else b""
        stderr = error.stderr if isinstance(error.stderr, bytes) else b""
        return {"exit_code": 124, "stdout": stdout.decode(errors="replace"),
                "stderr": (stderr.decode(errors="replace") + f"\nTimed out after {timeout}s.").strip(),
                "command": [resolved, *argv[1:]]}
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode(errors="replace"),
        "stderr": completed.stderr.decode(errors="replace"),
        "command": [resolved, *argv[1:]],
    }


def process_list_argv() -> list[str]:
    flavour = detect().ps_flavour
    if flavour == "bsd":
        return ["/bin/ps", "-Ao", "pid,ppid,user,%cpu,%mem,rss,command"]
    if flavour == "windows":
        return ["tasklist", "/FO", "CSV", "/V"]
    return ["ps", "-eo", "pid,ppid,user,%cpu,%mem,rss,args", "--no-headers"]


def process_list_argv_with_header() -> list[str]:
    flavour = detect().ps_flavour
    if flavour == "bsd":
        return ["/bin/ps", "-Ao", "pid,ppid,user,%cpu,%mem,rss,command"]
    if flavour == "windows":
        return ["tasklist", "/FO", "CSV", "/V"]
    return ["ps", "-eo", "pid,ppid,user,%cpu,%mem,rss,args"]


def listening_tcp_argv() -> list[str]:
    if which("lsof"):
        return [which("lsof") or "lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]
    if detect().os == "linux" and which("ss"):
        return ["ss", "-lntH"]
    return [which("netstat") or "netstat", "-an"]


def tcp_connections_argv(port: int | None = None, state: str | None = None) -> list[str]:
    lsof = which("lsof")
    if lsof:
        spec = f"-iTCP:{port}" if port else "-iTCP"
        argv = [lsof, "-nP", spec]
        if state:
            argv.append(f"-sTCP:{state.upper()}")
        return argv
    if detect().os == "linux" and which("ss"):
        argv = ["ss", "-ntH"]
        if state and state.upper() == "LISTEN":
            argv = ["ss", "-lntH"]
        return argv
    return [which("netstat") or "netstat", "-an"]


def ollama_argv(operation: str) -> list[str]:
    binary = which("ollama") or "ollama"
    if operation in {"running", "running_models"}:
        return [binary, "ps"]
    if operation in {"model_info", "show"}:
        return [binary, "show"]
    if operation == "pull":
        return [binary, "pull"]
    if operation == "rm":
        return [binary, "rm"]
    if operation == "stop":
        return [binary, "stop"]
    return [binary, "list"]
