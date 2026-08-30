"""macOS trust, signature, quarantine, and hash inspection."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ..host_parsers import parse_ps
from ..platform import detect, process_list_argv_with_header, run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "security",
    "Inspect code signatures, Gatekeeper, quarantine attributes, permissions, and file hashes. "
    "Prefer this over invented codesign/spctl/xattr flags.",
    schema(properties={
        "operation": {"type": "string", "enum": ["codesign", "gatekeeper", "quarantine", "hash",
                                                 "permissions", "process_signature"]},
        "path": {"type": "string"},
        "pid": {"type": "integer"},
        "name": {"type": "string"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)


def _resolve(path: str | None, name: str | None) -> Path:
    candidate = Path(path or name or "").expanduser()
    if not str(candidate):
        raise ToolFailure("security inspect requires path or name.", code="invalid_arguments")
    if not candidate.exists():
        raise ToolFailure(f"Path does not exist: {candidate}", code="not_found")
    return candidate


def _codesign(path: Path) -> dict[str, Any]:
    binary = which("codesign") or "codesign"
    raw = run_argv([binary, "-dv", "--verbose=2", str(path)], timeout=SPEC.timeout)
    text = (raw["stderr"] or raw["stdout"]).strip()
    info = {"path": str(path), "output": text[:4000], "exit_code": raw["exit_code"]}
    for line in text.splitlines():
        if line.startswith("Identifier="):
            info["identifier"] = line.split("=", 1)[1]
        if line.startswith("TeamIdentifier="):
            info["team"] = line.split("=", 1)[1]
        if "Signature=" in line or line.startswith("Authority="):
            info.setdefault("authority", [])
            if isinstance(info["authority"], list):
                info["authority"].append(line.split("=", 1)[-1])
    return info


def execute(context: ToolContext, *, operation: str, path: str | None = None, pid: int | None = None,
            name: str | None = None) -> dict[str, Any]:
    del context
    if operation == "gatekeeper":
        if detect().os != "macos" or not which("spctl"):
            raise ToolFailure("Gatekeeper status is only available on macOS.", code="unavailable")
        raw = run_argv(["spctl", "--status"], timeout=SPEC.timeout)
        return {"status": "success", "operation": operation, "gatekeeper": raw["stdout"].strip() or raw["stderr"].strip(),
                "exit_code": raw["exit_code"], "recipe": raw.get("command")}
    if operation == "process_signature":
        if pid is None:
            raise ToolFailure("process_signature requires pid.", code="invalid_arguments")
        raw = run_argv(process_list_argv_with_header(), timeout=SPEC.timeout)
        processes = parse_ps(raw["stdout"])
        match = next((item for item in processes if item.get("pid") == pid), None)
        if not match:
            return {"status": "no_results", "operation": operation, "pid": pid, "exit_code": 0}
        command = str(match.get("command") or "")
        target = Path(command.split()[0]) if command else None
        if target is None or not target.exists():
            return {"status": "no_results", "operation": operation, "pid": pid, "command": command, "exit_code": 0}
        info = _codesign(target)
        info["pid"] = pid
        return {"status": "success", "operation": operation, "signature": info, "exit_code": info.get("exit_code", 0)}
    target = _resolve(path, name)
    if operation == "codesign":
        info = _codesign(target)
        return {"status": "success" if info.get("exit_code") in {0, 1} else "error", "operation": operation,
                "signature": info, "exit_code": info.get("exit_code", 1)}
    if operation == "quarantine":
        raw = run_argv(["xattr", "-p", "com.apple.quarantine", str(target)], timeout=SPEC.timeout)
        present = raw["exit_code"] == 0 and bool(raw["stdout"].strip())
        return {"status": "success", "operation": operation, "path": str(target), "quarantined": present,
                "value": raw["stdout"].strip()[:500] if present else None, "exit_code": 0}
    if operation == "hash":
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                if digest.digest_size and handle.tell() > 64 * 1024 * 1024:
                    break
        return {"status": "success", "operation": operation, "path": str(target),
                "sha256": digest.hexdigest(), "bytes": target.stat().st_size, "exit_code": 0}
    stat = target.stat()
    return {"status": "success", "operation": operation, "path": str(target),
            "permissions": oct(stat.st_mode)[-3:], "mode": stat.st_mode, "uid": stat.st_uid,
            "gid": stat.st_gid, "bytes": stat.st_size, "exit_code": 0}
