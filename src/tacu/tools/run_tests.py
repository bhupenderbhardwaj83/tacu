"""Detect a project's test runner and normalize its result."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "run_tests",
    "Run the workspace test suite (pytest/unittest) and normalize the result.",
    schema(properties={"target": {"type": "string"}, "framework": {"type": "string"},
                       "timeout": {"type": "integer"}, "fail_fast": {"type": "boolean"}}),
    schema(properties={"passed": {"type": "boolean"}, "total": {"type": "integer"}, "failures": {"type": "array"}}),
    timeout=300, risk_level="execute", permissions=("workspace:read", "command:execute"), idempotent=False,
    when_to_use="Run tests after a code change, or when the user asked to run pytest/unittest.",
    when_not="Do not use to run an arbitrary script (shell) or check syntax only (diagnostics).",
)


def execute(context: ToolContext, *, target: str = ".", framework: str = "auto",
            timeout: int = 300, fail_fast: bool = False) -> dict[str, Any]:
    selected = context.guarded_path(target)
    root = context.workspace.resolve()
    if framework == "auto":
        if (root / "tests").exists() and shutil.which("pytest"): framework = "pytest"
        elif (root / "tests").exists(): framework = "unittest"
        elif (root / "Cargo.toml").exists(): framework = "cargo"
        elif (root / "package.json").exists(): framework = "npm"
        elif (root / "go.mod").exists(): framework = "go"
        else: raise ToolFailure("Could not detect a supported test framework.", code="framework_not_found")
    if framework == "pytest": command = [shutil.which("pytest") or "pytest", "-q", str(selected)] + (["-x"] if fail_fast else [])
    elif framework == "unittest": command = [sys.executable, "-m", "unittest", "discover", "-s", str(selected if selected != root else root / "tests"), "-v"]
    elif framework == "cargo": command = ["cargo", "test"] + (["--", "--fail-fast"] if fail_fast else [])
    elif framework == "npm": command = ["npm", "test", "--", "--runInBand"]
    elif framework == "go": command = ["go", "test", "./..."] + (["-failfast"] if fail_fast else [])
    else: raise ToolFailure(f"Unsupported framework: {framework}", code="unsupported_framework")
    started = time.monotonic()
    try: completed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=max(1, timeout), check=False)
    except FileNotFoundError as error: raise ToolFailure(f"Test runner not found: {command[0]}", code="missing_dependency") from error
    except subprocess.TimeoutExpired as error: raise ToolFailure(f"Tests timed out after {timeout}s.", code="timeout", retryable=True) from error
    output = (completed.stdout + "\n" + completed.stderr).strip()
    bounded, truncated = context.bounded_text(output)
    total = 0
    for pattern in (r"Ran (\d+) tests?", r"(\d+) passed", r"ok\s+.+\s+(\d+(?:\.\d+)?)s"):
        match = re.search(pattern, output)
        if match:
            try: total = int(match.group(1))
            except ValueError: pass
            break
    failures = [line.strip() for line in output.splitlines() if re.search(r"\b(?:FAIL|ERROR|failed)\b", line, re.I)][:50]
    return {"framework": framework, "command": command, "passed": completed.returncode == 0, "exit_code": completed.returncode,
            "total": total, "failures": failures, "output": bounded,
            "duration_ms": round((time.monotonic()-started)*1000), "_truncated": truncated or len(failures) == 50}

