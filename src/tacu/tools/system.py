"""Local operating-system facts using Python first, then a short native recipe."""

from __future__ import annotations

import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..platform import detect, launch_cwd, run_argv, which
from .contracts import ToolContext, ToolSpec, schema

SPEC = ToolSpec(
    "system",
    "Report local OS, hardware, CPU, memory, storage, uptime, cwd, directory counts, and the "
    "current local date and time. Prefer this over shell for host inventory questions.",
    schema(properties={"operation": {"type": "string",
                                     "enum": ["os_version", "hardware", "cpu", "memory", "uptime",
                                              "environment", "cwd", "listing", "storage", "power",
                                              "system_profile", "hostname", "datetime"]}},
           required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=15, risk_level="read", permissions=("host:read",),
)


def _bytes_to_gib(value: int | None) -> float | None:
    return round(value / (1024 ** 3), 2) if value else None


def _memory_bytes() -> int | None:
    ctx = detect()
    if ctx.os == "macos" and which("sysctl"):
        raw = run_argv(["sysctl", "-n", "hw.memsize"], timeout=5)
        try:
            return int(raw["stdout"].strip())
        except ValueError:
            return None
    if ctx.os == "linux":
        try:
            for line in open("/proc/meminfo", encoding="utf-8"):
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
        except OSError:
            return None
    return None


def _uptime_seconds() -> float | None:
    if detect().os == "linux":
        try:
            return float(open("/proc/uptime", encoding="utf-8").read().split()[0])
        except (OSError, ValueError, IndexError):
            return None
    if detect().os == "macos" and which("sysctl"):
        raw = run_argv(["sysctl", "-n", "kern.boottime"], timeout=5)
        match = __import__("re").search(r"sec\s*=\s*(\d+)", raw["stdout"])
        if match:
            return max(0, time.time() - int(match.group(1)))
    return None


def execute(context: ToolContext, *, operation: str) -> dict[str, Any]:
    ctx = detect()
    facts: dict[str, Any] = {
        "os": ctx.os, "kernel": ctx.kernel, "architecture": ctx.architecture,
        "python": platform.python_version(), "hostname": platform.node(),
        "platform": platform.platform(),
        "cwd": str(Path.cwd()),
        "workspace": str(context.workspace.resolve()),
        "launch_cwd": str(launch_cwd()),
    }
    if operation == "hostname":
        return {"status": "success", "operation": operation, "system": facts, "exit_code": 0}
    if operation in {"cwd", "listing"}:
        root = Path.cwd()
        facts["cwd"] = str(root)
        if operation == "listing":
            file_count = 0
            dir_count = 0
            entries: list[dict[str, Any]] = []
            try:
                names = sorted(os.listdir(root), key=str.casefold)
            except OSError as error:
                facts["error"] = str(error)
                return {"status": "error", "operation": operation, "system": facts, "exit_code": 1}
            for name in names:
                path = root / name
                try:
                    is_dir = path.is_dir()
                except OSError:
                    is_dir = False
                if is_dir:
                    dir_count += 1
                else:
                    file_count += 1
                if len(entries) < 80:
                    entries.append({"name": name, "kind": "directory" if is_dir else "file"})
            facts["file_count"] = file_count
            facts["dir_count"] = dir_count
            facts["entry_count"] = file_count + dir_count
            facts["entries"] = entries
        return {"status": "success", "operation": operation, "system": facts, "exit_code": 0}
    if operation == "os_version":
        if ctx.os == "macos":
            facts["mac_ver"] = platform.mac_ver()[0]
            if which("sw_vers"):
                raw = run_argv(["sw_vers"], timeout=5)
                facts["sw_vers"] = raw["stdout"].strip()
        elif ctx.os == "linux":
            facts["release"] = platform.release()
        else:
            facts["win_ver"] = platform.win32_ver()
        return {"status": "success", "operation": operation, "system": facts, "exit_code": 0}
    if operation == "datetime":
        current = datetime.now().astimezone()
        offset = current.strftime("%z")
        facts["local_datetime"] = current.isoformat(timespec="seconds")
        facts["local_date"] = current.strftime("%Y-%m-%d")
        facts["local_time"] = current.strftime("%H:%M:%S")
        facts["day_of_week"] = current.strftime("%A")
        facts["timezone"] = current.strftime("%Z") or None
        facts["utc_offset"] = f"UTC{offset[:3]}:{offset[3:]}" if offset else None
        facts["utc_datetime"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        facts["readable"] = current.strftime("%A, %d %B %Y at %H:%M")
        return {"status": "success", "operation": operation, "system": facts, "exit_code": 0}
    if operation == "cpu":
        facts["cpu_count"] = os.cpu_count()
        facts["processor"] = platform.processor()
        return {"status": "success", "operation": operation, "system": facts, "exit_code": 0}
    if operation == "memory":
        total = _memory_bytes()
        facts["memory_bytes"] = total
        facts["memory_gib"] = _bytes_to_gib(total)
        return {"status": "success" if total else "partial", "operation": operation, "system": facts, "exit_code": 0}
    if operation == "uptime":
        seconds = _uptime_seconds()
        facts["uptime_seconds"] = round(seconds, 1) if seconds is not None else None
        return {"status": "success" if seconds is not None else "partial", "operation": operation,
                "system": facts, "exit_code": 0}
    if operation == "hardware":
        facts["cpu_count"] = os.cpu_count()
        facts["memory_gib"] = _bytes_to_gib(_memory_bytes())
        facts["machine"] = platform.machine()
        return {"status": "success", "operation": operation, "system": facts, "exit_code": 0}
    if operation == "storage":
        raw = run_argv(["df", "-h"] if detect().os != "windows" else ["wmic", "logicaldisk", "get", "size,freespace,caption"],
                       timeout=8)
        facts["volumes"] = [line.strip() for line in raw["stdout"].splitlines() if line.strip()][:20]
        return {"status": "success" if raw["exit_code"] == 0 else "partial", "operation": operation,
                "system": facts, "exit_code": 0}
    if operation == "power":
        if ctx.os == "macos" and which("pmset"):
            raw = run_argv(["pmset", "-g", "batt"], timeout=5)
            facts["power"] = raw["stdout"].strip()[:2000]
        else:
            facts["power"] = None
        return {"status": "success" if facts.get("power") else "partial", "operation": operation,
                "system": facts, "exit_code": 0}
    if operation == "system_profile":
        if ctx.os == "macos" and which("system_profiler"):
            raw = run_argv(["system_profiler", "SPHardwareDataType", "-detailLevel", "mini"], timeout=15)
            facts["hardware_profile"] = raw["stdout"].strip()[:4000]
        else:
            facts["cpu_count"] = os.cpu_count()
            facts["machine"] = platform.machine()
        return {"status": "success", "operation": operation, "system": facts, "exit_code": 0}
    facts["environment_keys"] = sorted(os.environ)[:80]
    return {"status": "success", "operation": operation, "system": facts, "exit_code": 0}
