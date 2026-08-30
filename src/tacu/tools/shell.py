"""Argument-safe command execution behind deterministic policy and timeouts."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "shell",
    "Run one argv-safe executable (no bash -c, no pipes). Policy still gates danger.",
    schema(properties={"executable": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}},
                       "cwd": {"type": "string"}, "timeout": {"type": "integer"}}, required=("executable",)),
    schema(properties={"exit_code": {"type": "integer"}, "stdout": {"type": "string"},
                       "stderr": {"type": "string"}, "duration_ms": {"type": "integer"}}),
    timeout=120, risk_level="execute", permissions=("workspace:read", "command:execute"), idempotent=False,
    when_to_use=(
        "Run a workspace program: python3 app.py, bash script.sh, or a build/test binary. "
        "Pass executable + args only."
    ),
    when_not=(
        "Never a substitute for specialized tools: not cat/head (read_file), not rg/grep (search_code), "
        "not echo/tee (write_file), not find/ls (repo_map), not bash -c or python -c."
    ),
)

DANGEROUS = {"rm", "rmdir", "sudo", "su", "shutdown", "reboot", "halt", "poweroff", "mkfs", "fdisk",
             "diskutil", "dd", "chmod", "chown", "kill", "killall", "launchctl", "systemctl"}
SHELLS = {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}


def risk(executable: str, args: list[str]) -> tuple[str, str | None]:
    name = Path(executable).name.lower()
    if name in DANGEROUS or any(name.startswith(prefix) for prefix in ("mkfs.",)):
        return "dangerous", f"{name} changes system or process state"
    if name in SHELLS and any(arg.lower() in {"-c", "-lc", "/c"} for arg in args):
        return "dangerous", "nested shell code bypasses argument-safe execution"
    if name in {"python", "python3", "node", "ruby", "perl"} and any(arg in {"-c", "-e"} for arg in args):
        return "elevated", "inline interpreter code can perform arbitrary actions"
    return "normal", None


def _change_snapshot(executable: str, arguments: list[str], working: Path,
                     context: ToolContext) -> list[dict[str, Any]]:
    if context.policy_level != "log":
        return []
    from ..automation import CommandStep, _argument_paths

    step = CommandStep(executable, tuple(arguments), str(working), "audited execution")
    snapshots: list[dict[str, Any]] = []
    for target in _argument_paths(step, context.workspace)[:20]:
        try:
            resolved = target.resolve(strict=False)
            root = context.workspace.resolve()
            if resolved != root and root not in resolved.parents:
                continue
            item: dict[str, Any] = {"path": str(resolved), "exists": resolved.exists()}
            if resolved.is_file():
                stat = resolved.stat()
                item.update({"kind": "file", "size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
                if stat.st_size <= 5_000_000:
                    item["sha256"] = hashlib.sha256(resolved.read_bytes()).hexdigest()
            elif resolved.is_dir():
                item.update({"kind": "directory", "entry_count": sum(1 for _ in resolved.iterdir())})
            snapshots.append(item)
        except OSError as error:
            snapshots.append({"path": str(target), "error": str(error)})
    return snapshots


def execute(context: ToolContext, *, executable: str, args: list[str] | None = None,
            cwd: str = ".", timeout: int = 120) -> dict[str, Any]:
    arguments = [str(item) for item in (args or [])]
    level, reason = risk(executable, arguments)
    if level == "dangerous" and not context.approve_dangerous:
        raise ToolFailure(f"Command requires explicit --approve: {reason}", code="approval_required")
    binary = executable if ("/" in executable or "\\" in executable) else shutil.which(executable)
    if not binary:
        raise ToolFailure(f"Command not found: {executable}", code="command_not_found")
    working = context.guarded_path(cwd)
    before = _change_snapshot(executable, arguments, working, context)
    started = time.monotonic()
    try:
        completed = subprocess.run([binary, *arguments], cwd=working, capture_output=True, timeout=max(1, timeout), check=False)
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, bytes) else (error.stdout or "").encode()
        stderr = error.stderr if isinstance(error.stderr, bytes) else (error.stderr or "").encode()
        artifacts = context.save_artifacts(stdout=stdout, stderr=stderr)
        out, out_cut = context.bounded_text(stdout.decode(errors="replace"))
        err, err_cut = context.bounded_text(stderr.decode(errors="replace"))
        after = _change_snapshot(executable, arguments, working, context)
        change_audit = ({"before": before, "after": after,
                         "rollback": "Restore from version control or the recorded pre-change hash."}
                        if context.policy_level == "log" else None)
        return {"exit_code": 124, "stdout": out, "stderr": err + f"\nTimed out after {timeout}s.",
                "duration_ms": round((time.monotonic()-started)*1000), "risk": level,
                "raw_artifacts": artifacts, "change_audit": change_audit,
                "_truncated": out_cut or err_cut}
    artifacts = context.save_artifacts(stdout=completed.stdout, stderr=completed.stderr)
    after = _change_snapshot(executable, arguments, working, context)
    change_audit = ({"before": before, "after": after,
                     "rollback": "Restore from version control or the recorded pre-change hash."}
                    if context.policy_level == "log" else None)
    stdout, out_cut = context.bounded_text(completed.stdout.decode(errors="replace"))
    stderr, err_cut = context.bounded_text(completed.stderr.decode(errors="replace"))
    return {"exit_code": completed.returncode, "stdout": stdout.rstrip(), "stderr": stderr.rstrip(),
            "duration_ms": round((time.monotonic()-started)*1000), "risk": level,
            "command": [str(binary), *arguments], "raw_artifacts": artifacts,
            "change_audit": change_audit, "_truncated": out_cut or err_cut}

