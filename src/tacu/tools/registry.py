"""Registry, validation, timing, error normalization, and audit coordination."""

from __future__ import annotations

import time
import uuid
from types import ModuleType
from typing import Any

from . import (
    application, diagnostics, docker, edit_file, filesystem, forensics, git, inspect_symbol, network, ollama,
    package, process, read_file, repo_map, run_tests, search_code, security, service, shell, system,
    task_state, write_file, verify, service_process,
)
from .contracts import ToolContext, ToolFailure, ToolResult, ToolSpec, validate_inputs

CORE_MODULES: tuple[ModuleType, ...] = (repo_map, search_code, read_file, inspect_symbol, edit_file,
                                        write_file, shell, diagnostics, run_tests, task_state)
HOST_MODULES: tuple[ModuleType, ...] = (
    process, network, system, application, ollama, filesystem, git, docker, service, package, security,
    forensics,
)
MODULES: tuple[ModuleType, ...] = CORE_MODULES + HOST_MODULES + (verify, service_process)
REGISTRY = {module.SPEC.name: module for module in MODULES}


def specs() -> list[ToolSpec]:
    return [module.SPEC for module in MODULES]


def invoke(name: str, inputs: dict[str, Any], context: ToolContext) -> ToolResult:
    call_id = uuid.uuid4().hex
    started = time.monotonic()
    module = REGISTRY.get(name)
    data: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    truncated = False
    try:
        if module is None: raise ToolFailure(f"Unknown tool: {name}", code="tool_not_found")
        validate_inputs(module.SPEC, inputs)
        data = module.execute(context, **inputs)
        truncated = bool(data.pop("_truncated", False))
        ok = True
    except ToolFailure as failure:
        ok = False; error = {"code": failure.code, "message": str(failure), "retryable": failure.retryable}
    except Exception as failure:
        ok = False; error = {"code": "internal_error", "message": f"{type(failure).__name__}: {failure}", "retryable": False}
    duration = round((time.monotonic()-started)*1000)
    result = ToolResult(call_id, name, ok, data, error, duration, truncated,
                        {"workspace": str(context.workspace.resolve()), "schema": "tacu.tool-call/v1"})
    context.audit(call_id=call_id, tool=name, ok=ok, duration_ms=duration, inputs=inputs, error=error)
    return result
