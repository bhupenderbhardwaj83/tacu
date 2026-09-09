"""An explicit acceptance check: custom scripts do not depend on filename heuristics."""

from __future__ import annotations

from typing import Any

from . import shell
from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "verify", "Run an explicit acceptance check. Exit zero means its assertions passed.",
    schema(properties={"executable": {"type": "string"}, "args": {"type": "array"},
                       "cwd": {"type": "string"}, "timeout": {"type": "integer"},
                       "purpose": {"type": "string"}}, required=("executable", "purpose")),
    schema(properties={"passed": {"type": "boolean"}, "exit_code": {"type": "integer"}}),
    timeout=300, risk_level="execute", permissions=("workspace:read", "command:execute"),
    idempotent=False,
    when_to_use="Run a custom check such as .venv/bin/python _verify.py. State what it proves; use assertions that fail on errors.",
    when_not="Not for installs, servers, echo, or commands that merely print a success claim. Use run_tests for test suites.",
)


def execute(context: ToolContext, *, executable: str, purpose: str,
            args: list[str] | None = None, cwd: str = ".", timeout: int = 300) -> dict[str, Any]:
    if not purpose.strip():
        raise ToolFailure("Describe the behavior this check proves.", code="invalid_input")
    result = shell.execute(context, executable=executable, args=args, cwd=cwd, timeout=timeout)
    result.update(passed=result["exit_code"] == 0, verification=purpose[:500])
    return result
