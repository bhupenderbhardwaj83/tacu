"""Inspect macOS launchd (and Linux systemd) services without invented CLI flags."""

from __future__ import annotations

import os
from typing import Any

from ..platform import detect, run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, require_approval, schema

SPEC = ToolSpec(
    "service",
    "List and inspect local services (launchd on macOS). Prefer this over launchctl/systemctl flags.",
    schema(properties={
        "operation": {"type": "string", "enum": ["list", "find", "status", "inspect", "start", "stop", "restart"]},
        "name": {"type": "string"},
        "limit": {"type": "integer"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)


def _parse_launchctl(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid = None if parts[0] == "-" else (int(parts[0]) if parts[0].isdigit() else None)
        rows.append({"pid": pid, "exit_status": parts[1], "label": parts[2], "running": pid is not None})
    return rows


def _filter(rows: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    needle = name.casefold()
    return [item for item in rows if needle in (item.get("label") or "").casefold()]


def execute(context: ToolContext, *, operation: str, name: str | None = None, limit: int = 40) -> dict[str, Any]:
    cap = max(1, min(int(limit or 40), 80))
    needle = (name or "").strip()
    if detect().os == "macos":
        if not which("launchctl"):
            raise ToolFailure("launchctl is unavailable.", code="unavailable")
        raw = run_argv(["launchctl", "list"], timeout=SPEC.timeout)
        rows = _parse_launchctl(raw["stdout"])
        if operation == "list":
            selected = rows[:cap]
            return {"status": "success", "operation": operation, "services": selected,
                    "count": len(selected), "total": len(rows), "exit_code": 0, "recipe": raw.get("command")}
        if not needle:
            raise ToolFailure("service find/status/inspect require name.", code="invalid_arguments")
        matches = _filter(rows, needle)[:cap]
        if operation == "find":
            return {"status": "success" if matches else "no_results", "operation": operation, "query": needle,
                    "services": matches, "count": len(matches), "exit_code": 0}
        label = matches[0]["label"] if matches else needle
        if operation in {"start", "stop", "restart"}:
            require_approval(context, f"service.{operation}")
            uid = os.getuid()
            target = f"gui/{uid}/{label}"
            if operation == "stop":
                argv = ["launchctl", "kill", "SIGTERM", target]
            else:
                argv = ["launchctl", "kickstart", "-k", target]
            acted = run_argv(argv, timeout=SPEC.timeout)
            return {"status": "success" if acted["exit_code"] == 0 else "error", "operation": operation,
                    "label": label, "exit_code": acted["exit_code"], "stderr": acted.get("stderr", ""),
                    "recipe": acted.get("command")}
        detail = run_argv(["launchctl", "list", label], timeout=SPEC.timeout)
        return {"status": "success" if detail["exit_code"] == 0 else "error", "operation": operation,
                "query": needle, "label": label, "services": matches[:1],
                "detail": (detail["stdout"] or detail["stderr"])[:4000],
                "exit_code": detail["exit_code"], "recipe": detail.get("command")}
    if which("systemctl"):
        raw = run_argv(["systemctl", "list-units", "--type=service", "--no-pager", "--no-legend"], timeout=SPEC.timeout)
        rows = []
        for line in raw["stdout"].splitlines()[:cap]:
            parts = line.split(None, 4)
            if len(parts) >= 4:
                rows.append({"label": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3],
                             "running": parts[2] == "active"})
        if needle:
            rows = [item for item in rows if needle.casefold() in item["label"].casefold()]
        return {"status": "success" if rows else "no_results", "operation": operation, "services": rows,
                "count": len(rows), "exit_code": 0}
    raise ToolFailure("No native service manager is available.", code="unavailable")
