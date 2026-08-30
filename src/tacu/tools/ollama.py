"""Inspect local Ollama models without inventing CLI flags."""

from __future__ import annotations

from typing import Any

from ..host_parsers import parse_ollama_table
from ..platform import ollama_argv, run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, require_approval, require_named_target, schema

SPEC = ToolSpec(
    "ollama",
    "Inspect locally installed and currently loaded Ollama models. "
    "Use running_models for what is loaded now (includes size), and installed_models for downloads. "
    "pull, rm, and stop require review. Prefer this over shell for Ollama questions.",
    schema(properties={
        "operation": {"type": "string", "enum": [
            "installed_models", "running_models", "model_info", "pull", "rm", "stop",
        ]},
        "name": {"type": "string"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)

_MUTATE = frozenset({"pull", "rm", "stop"})


def execute(context: ToolContext, *, operation: str, name: str | None = None) -> dict[str, Any]:
    if not which("ollama"):
        raise ToolFailure("ollama is not installed on this computer.", code="unavailable")
    if operation in _MUTATE:
        require_approval(context, f"ollama.{operation}")
        needle = require_named_target(name, f"ollama.{operation}")
        argv = ollama_argv(operation) + [needle]
        timeout = 600 if operation == "pull" else SPEC.timeout
        raw = run_argv(argv, timeout=timeout)
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "name": needle, "exit_code": raw["exit_code"], "stderr": (raw.get("stderr") or "")[-2000:],
                "recipe": argv}
    if operation == "model_info":
        needle = require_named_target(name, "ollama.model_info")
        argv = [ollama_argv("show")[0], "show", needle]
        raw = run_argv(argv, timeout=SPEC.timeout)
        if raw["exit_code"] not in {0, 1}:
            raise ToolFailure(raw["stderr"] or "ollama failed", code="failed")
        return {"status": "success" if raw["stdout"].strip() else "no_results", "operation": operation,
                "name": needle, "info": raw["stdout"].strip()[:8000], "recipe": raw.get("command"), "exit_code": 0}
    argv = ollama_argv(operation)
    raw = run_argv(argv, timeout=SPEC.timeout)
    if raw["exit_code"] not in {0, 1}:
        raise ToolFailure(raw["stderr"] or "ollama failed", code="failed")
    models = parse_ollama_table(raw["stdout"])
    status = "success" if models or raw["exit_code"] == 0 else "no_results"
    if not models and raw["exit_code"] == 0:
        status = "no_results"
    return {
        "status": status,
        "operation": operation,
        "models": models,
        "count": len(models),
        "recipe": raw.get("command"),
        "exit_code": 0,
    }
