"""Inspect Homebrew (or winget) packages without invented CLI flags."""

from __future__ import annotations

import json
from typing import Any

from ..platform import detect, run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, require_approval, schema

SPEC = ToolSpec(
    "package",
    "List, search, and inspect packages via the native package manager (brew on macOS).",
    schema(properties={
        "operation": {"type": "string", "enum": ["list", "info", "search", "outdated", "install", "upgrade", "remove"]},
        "name": {"type": "string"},
        "limit": {"type": "integer"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=40, risk_level="read", permissions=("host:read",),
)


def _brew() -> str:
    binary = which("brew")
    if not binary:
        raise ToolFailure("Homebrew is not installed or not on PATH.", code="unavailable")
    return binary


def execute(context: ToolContext, *, operation: str, name: str | None = None, limit: int = 40) -> dict[str, Any]:
    cap = max(1, min(int(limit or 40), 80))
    needle = (name or "").strip()
    if detect().os != "macos" and not which("brew"):
        raise ToolFailure("package tool currently supports Homebrew on this host.", code="unavailable")
    brew = _brew()
    if operation in {"install", "upgrade", "remove"}:
        verb = {"remove": "uninstall"}.get(operation, operation)
        named = f" {needle}" if needle else ""
        require_approval(
            context, f"package.{operation}",
            f"Run it through the reviewed lane: ti do {operation}{named} — "
            f"or yourself: brew {verb}{named}.")
        if not needle:
            raise ToolFailure(f"package.{operation} requires name.", code="invalid_arguments")
        raw = run_argv([brew, verb, needle], timeout=SPEC.timeout)
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "name": needle, "stdout": raw["stdout"][-2000:], "stderr": raw["stderr"][-2000:],
                "exit_code": raw["exit_code"], "recipe": raw.get("command")}
    if operation == "list":
        raw = run_argv([brew, "list", "--versions"], timeout=SPEC.timeout)
        packages = []
        for line in raw["stdout"].splitlines():
            parts = line.split(None, 1)
            if not parts:
                continue
            packages.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else None})
            if len(packages) >= cap:
                break
        return {"status": "success", "operation": operation, "packages": packages, "count": len(packages),
                "exit_code": 0, "recipe": raw.get("command")}
    if operation == "outdated":
        raw = run_argv([brew, "outdated", "--verbose"], timeout=SPEC.timeout)
        packages = []
        for line in raw["stdout"].splitlines()[:cap]:
            if line.strip():
                packages.append({"line": line.strip()})
        return {"status": "success" if packages else "no_results", "operation": operation,
                "packages": packages, "count": len(packages), "exit_code": 0, "recipe": raw.get("command")}
    if operation == "search":
        if not needle:
            raise ToolFailure("package.search requires name.", code="invalid_arguments")
        raw = run_argv([brew, "search", needle], timeout=SPEC.timeout)
        names = [line.strip() for line in raw["stdout"].splitlines() if line.strip() and not line.startswith("=")][:cap]
        return {"status": "success" if names else "no_results", "operation": operation, "query": needle,
                "packages": [{"name": item} for item in names], "count": len(names), "exit_code": 0}
    if not needle:
        raise ToolFailure("package.info requires name.", code="invalid_arguments")
    raw = run_argv([brew, "info", "--json=v2", needle], timeout=SPEC.timeout)
    info: dict[str, Any] = {"name": needle, "raw": raw["stdout"][:2000]}
    try:
        payload = json.loads(raw["stdout"])
        formulae = (payload.get("formulae") or payload.get("casks") or [])
        if formulae and isinstance(formulae[0], dict):
            item = formulae[0]
            info = {"name": item.get("name") or item.get("token") or needle,
                    "desc": item.get("desc"), "homepage": item.get("homepage"),
                    "versions": item.get("versions"), "installed": item.get("installed")}
    except json.JSONDecodeError:
        pass
    return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
            "packages": [info], "count": 1 if info else 0, "exit_code": raw["exit_code"]}
