"""Typed, dependency-free contracts shared by TACU's harness tools."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ToolFailure(RuntimeError):
    """Expected failure represented as structured data instead of a traceback."""

    def __init__(self, message: str, *, code: str = "tool_error", retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


def require_approval(context: "ToolContext", operation: str) -> None:
    if not context.approve_dangerous:
        raise ToolFailure(f"{operation} requires explicit review.", code="approval_required")


_UNSAFE_NAME = re.compile(r"[;|&`$(){}[\]\n\r]")


def require_named_target(value: str | None, operation: str) -> str:
    """Reject empty, flag-like, or shell-metacharacter names for mutate recipes."""

    text = (value or "").strip()
    if not text:
        raise ToolFailure(f"{operation} requires an explicit name.", code="invalid_arguments")
    if text.startswith("-") or _UNSAFE_NAME.search(text):
        raise ToolFailure(f"{operation} refused an unsafe name.", code="invalid_arguments")
    return text


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    version: str = "1.0.0"
    timeout: int = 30
    risk_level: str = "read"
    permissions: tuple[str, ...] = ("workspace:read",)
    idempotent: bool = True
    when_to_use: str = ""
    when_not: str = ""

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["permissions"] = list(self.permissions)
        return value


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    tool: str
    ok: bool
    data: dict[str, Any] | None
    error: dict[str, Any] | None
    duration_ms: int
    truncated: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ToolContext:
    workspace: Path
    state_dir: Path
    approve_dangerous: bool = False
    max_output_chars: int = 100_000
    policy_level: str = "unspecified"
    policy_reasons: tuple[str, ...] = ()

    def guarded_path(self, value: str | os.PathLike[str] = ".") -> Path:
        """Resolve a path that must stay inside the declared workspace."""

        return self.resolved_path(value, mutate=False, allow_outside=False)

    def resolved_path(self, value: str | os.PathLike[str] = ".", *,
                      mutate: bool = False, allow_outside: bool = True) -> Path:
        """Resolve a path. OS-critical targets never mutate. Outside the workspace
        requires an approved prompt unless allow_outside is false (workspace-only tools).
        """

        from ..automation import os_critical_path

        root = self.workspace.expanduser().resolve()
        path = Path(value).expanduser()
        candidate = (path if path.is_absolute() else root / path).resolve(strict=False)
        inside = candidate == root or root in candidate.parents
        if mutate and os_critical_path(candidate):
            raise ToolFailure(f"OS-critical paths cannot be created, edited, or deleted: {candidate}",
                              code="os_critical")
        if inside:
            return candidate
        if not allow_outside or not self.approve_dangerous:
            raise ToolFailure(f"Path escapes workspace: {value}", code="path_outside_workspace")
        if mutate and os_critical_path(candidate):
            raise ToolFailure(f"OS-critical paths cannot be created, edited, or deleted: {candidate}",
                              code="os_critical")
        return candidate

    def bounded_text(self, text: str) -> tuple[str, bool]:
        if len(text) <= self.max_output_chars:
            return text, False
        half = self.max_output_chars // 2
        return text[:half] + "\n[... middle omitted by tacu; truncated=true ...]\n" + text[-half:], True

    def save_artifacts(self, *, stdout: bytes = b"", stderr: bytes = b"") -> dict[str, Any] | None:
        from ..artifacts import save_raw_artifacts
        return save_raw_artifacts(self.state_dir, stdout=stdout, stderr=stderr)

    def database(self) -> sqlite3.Connection:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.state_dir / "harness.db"
        connection = sqlite3.connect(path)
        if os.name != "nt":
            self.state_dir.chmod(0o700)
            path.chmod(0o600)
        return connection

    def audit(self, *, call_id: str, tool: str, ok: bool, duration_ms: int,
              inputs: dict[str, Any], error: dict[str, Any] | None) -> None:
        """Persist safe invocation metadata; never log file content or credentials."""

        raw_inputs = inputs if isinstance(inputs, dict) else {}
        safe_inputs = {key: value for key, value in raw_inputs.items()
                       if key in {"path", "root", "cwd", "symbol", "target", "operation", "task_id", "executable"}}
        arguments = raw_inputs.get("args")
        if isinstance(arguments, list):
            safe_arguments: list[str] = []
            redact_next = False
            secret_option = re.compile(r"(?i)^--?(?:password|passwd|token|secret|api[-_]?key|authorization)$")
            secret_assignment = re.compile(r"(?i)^([^=]*(?:password|passwd|token|secret|api[-_]?key|authorization)[^=]*)=(.*)$")
            for raw in arguments[:100]:
                value = str(raw)
                if redact_next:
                    safe_arguments.append("[REDACTED]")
                    redact_next = False
                    continue
                assignment = secret_assignment.match(value)
                if assignment:
                    safe_arguments.append(assignment.group(1) + "=[REDACTED]")
                    continue
                safe_arguments.append(value[:500])
                redact_next = bool(secret_option.match(value))
            safe_inputs["args"] = safe_arguments
        safe_inputs["policy_level"] = self.policy_level
        safe_inputs["policy_reasons"] = list(self.policy_reasons)
        with self.database() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS tool_audit (
                    call_id TEXT PRIMARY KEY, tool TEXT NOT NULL, ok INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL, created_at TEXT NOT NULL,
                    input_metadata_json TEXT NOT NULL, error_json TEXT
                )"""
            )
            connection.execute(
                "INSERT INTO tool_audit VALUES (?,?,?,?,?,?,?)",
                (call_id, tool, int(ok), duration_ms, datetime.now(timezone.utc).isoformat(),
                 json.dumps(safe_inputs, default=str), json.dumps(error) if error else None),
            )


def schema(*, properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


def validate_inputs(spec: ToolSpec, inputs: dict[str, Any]) -> None:
    if not isinstance(inputs, dict):
        raise ToolFailure("Tool inputs must be a JSON object.", code="invalid_input")
    expected = spec.input_schema.get("properties", {})
    missing = [key for key in spec.input_schema.get("required", []) if key not in inputs]
    if missing:
        raise ToolFailure("Missing required inputs: " + ", ".join(missing), code="invalid_input")
    unknown = sorted(set(inputs) - set(expected))
    if unknown:
        raise ToolFailure("Unknown inputs: " + ", ".join(unknown), code="invalid_input")
    types = {"string": str, "integer": int, "boolean": bool, "array": list, "object": dict}
    for key, value in list(inputs.items()):
        kind = expected[key].get("type")
        value = _coerce_input(kind, value)
        inputs[key] = value
        if kind in types and (not isinstance(value, types[kind]) or (kind == "integer" and isinstance(value, bool))):
            raise ToolFailure(f"Input {key!r} must be {kind}.", code="invalid_input")
        allowed = expected[key].get("enum")
        if allowed and value not in allowed:
            raise ToolFailure(f"Input {key!r} must be one of {allowed}.", code="invalid_input")


def _coerce_input(kind: str | None, value: Any) -> Any:
    """Small local models often emit JSON numbers as strings; coerce safely."""

    if kind == "integer":
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
            return int(value.strip())
    if kind == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().casefold() in {"true", "false", "1", "0", "yes", "no"}:
            return value.strip().casefold() in {"true", "1", "yes"}
    return value
