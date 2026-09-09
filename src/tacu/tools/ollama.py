"""Inspect local Ollama models without inventing CLI flags."""

from __future__ import annotations

from typing import Any

from ..host_parsers import parse_ollama_table
from ..platform import ollama_argv, run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, require_approval, require_named_target, schema

SPEC = ToolSpec(
    "ollama",
    "Inspect locally installed and currently loaded Ollama models, the server version, "
    "and every setting in force — environment variables, TACU's own request options, and "
    "which of the two actually applies. Use running_models for what is loaded now, "
    "installed_models for downloads, settings for configuration. pull, rm, and stop "
    "require review. Prefer this over shell for Ollama questions.",
    schema(properties={
        "operation": {"type": "string", "enum": [
            "installed_models", "running_models", "model_info", "settings", "version",
            "pull", "rm", "stop",
        ]},
        "name": {"type": "string"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)

_MUTATE = frozenset({"pull", "rm", "stop"})


# The environment variables Ollama reads. Reported whether or not they are set,
# because "it is not set, so the default applies" is an answer too.
_OLLAMA_ENV = (
    ("OLLAMA_HOST", "where the server listens", "127.0.0.1:11434"),
    ("OLLAMA_KEEP_ALIVE", "how long a model stays loaded", "5m"),
    ("OLLAMA_MODELS", "where model blobs are stored", "~/.ollama/models"),
    ("OLLAMA_CONTEXT_LENGTH", "default context window", "4096"),
    ("OLLAMA_MAX_LOADED_MODELS", "how many models may be resident at once", "per GPU"),
    ("OLLAMA_NUM_PARALLEL", "concurrent requests per model", "auto"),
    ("OLLAMA_MAX_QUEUE", "queued requests before rejection", "512"),
    ("OLLAMA_FLASH_ATTENTION", "flash attention", "off"),
    ("OLLAMA_KV_CACHE_TYPE", "KV cache quantisation", "f16"),
    ("OLLAMA_LOAD_TIMEOUT", "how long a load may take", "5m"),
    ("OLLAMA_GPU_OVERHEAD", "reserved VRAM", "0"),
    ("OLLAMA_DEBUG", "verbose server logging", "off"),
)


def _settings() -> dict[str, Any]:
    """Every Ollama setting in force, and which layer actually decides it.

    A setting can be stated in three places — the environment, TACU's own request
    options, and Ollama's built-in default — and they disagree. Reporting only the
    environment variable is how someone ends up believing a value that never
    reaches the server: a `keep_alive` sent with the request overrides
    `OLLAMA_KEEP_ALIVE` every time.
    """

    import os

    from ..configuration import configured_model
    from ..core import DEFAULT_KEEP_ALIVE, DEFAULT_MODEL

    environment = []
    for key, purpose, fallback in _OLLAMA_ENV:
        value = os.environ.get(key)
        environment.append({
            "variable": key, "value": value, "purpose": purpose,
            "in_effect": value if value else f"{fallback} (Ollama default; not set)",
            "set": bool(value),
        })

    sent = {
        "keep_alive": os.environ.get("TACU_KEEP_ALIVE", DEFAULT_KEEP_ALIVE),
        "num_ctx": os.environ.get("TACU_NUM_CTX", "8192"),
        "num_predict": os.environ.get("TACU_NUM_PREDICT", "1024 (escalates to 4096)"),
        "temperature": "0.1",
    }
    conflicts = []
    env_keep_alive = os.environ.get("OLLAMA_KEEP_ALIVE")
    if env_keep_alive and env_keep_alive != sent["keep_alive"]:
        conflicts.append({
            "setting": "keep_alive",
            "environment": env_keep_alive,
            "tacu_sends": sent["keep_alive"],
            "wins": sent["keep_alive"],
            "why": ("a keep_alive sent with the request overrides OLLAMA_KEEP_ALIVE, so the "
                    "environment value never applies to TACU's own calls"),
        })
    return {
        "environment": environment,
        "tacu_request_options": sent,
        "active_model": os.environ.get("TACU_MODEL") or configured_model() or DEFAULT_MODEL,
        "conflicts": conflicts,
    }


def execute(context: ToolContext, *, operation: str, name: str | None = None) -> dict[str, Any]:
    if not which("ollama"):
        raise ToolFailure("ollama is not installed on this computer.", code="unavailable")
    if operation in _MUTATE:
        require_approval(
            context, f"ollama.{operation}",
            f"Run it through the reviewed lane: ti do ollama {operation}"
            + (f" {name}" if name else "")
            + f" — or yourself: ollama {operation}" + (f" {name}" if name else "") + ".")
        needle = require_named_target(name, f"ollama.{operation}")
        argv = ollama_argv(operation) + [needle]
        timeout = 600 if operation == "pull" else SPEC.timeout
        raw = run_argv(argv, timeout=timeout)
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "name": needle, "exit_code": raw["exit_code"], "stderr": (raw.get("stderr") or "")[-2000:],
                "recipe": argv}
    if operation == "settings":
        payload = _settings()
        return {"status": "success", "operation": operation, "exit_code": 0, **payload}
    if operation == "version":
        argv = [ollama_argv("list")[0], "--version"]
        raw = run_argv(argv, timeout=SPEC.timeout)
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "version": (raw["stdout"] or raw.get("stderr") or "").strip()[:200],
                "exit_code": raw["exit_code"], "recipe": argv}
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
