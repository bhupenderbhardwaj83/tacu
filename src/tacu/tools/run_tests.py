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
from ..execution import run_captured

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
    venv = root / ".venv" / ("Scripts" if sys.platform == "win32" else "bin")
    python = next((str(path) for path in (venv / "python.exe", venv / "python", venv / "python3") if path.is_file()), sys.executable)
    pytest = next((str(path) for path in (venv / "pytest.exe", venv / "pytest") if path.is_file()), None)
    if python == sys.executable:
        pytest = pytest or shutil.which("pytest")
    if framework == "auto":
        # Tests are not always in a tests/ directory. A project with test_x.py
        # beside the code had no detectable framework at all, so a coding run
        # could never prove itself.
        has_dir = (root / "tests").exists()
        beside_code = any(root.glob("test_*.py")) or any(root.glob("*_test.py"))
        if (has_dir or beside_code) and pytest: framework = "pytest"
        # unittest ships with Python, so it is always available to fall back on.
        elif has_dir or beside_code: framework = "unittest"
        elif (root / "Cargo.toml").exists(): framework = "cargo"
        elif (root / "package.json").exists(): framework = "npm"
        elif (root / "go.mod").exists(): framework = "go"
        else: raise ToolFailure("Could not detect a supported test framework.", code="framework_not_found")
    if framework == "pytest": command = ([pytest] if pytest else [python, "-m", "pytest"]) + ["-q", str(selected)] + (["-x"] if fail_fast else [])
    elif framework == "unittest":
        start = selected if selected != root else (root / "tests" if (root / "tests").is_dir() else root)
        command = [python, "-m", "unittest", "discover", "-s", str(start),
                   "-p", "test*.py", "-v"]
        if start == root:
            # Tests beside the code import the modules they test, so the workspace
            # has to be importable. A tests/ package resolves itself and passing
            # -t there breaks discovery when it has no __init__.py.
            command[-1:-1] = ["-t", str(root)]
    elif framework == "cargo": command = ["cargo", "test"] + (["--", "--fail-fast"] if fail_fast else [])
    elif framework == "npm": command = ["npm", "test", "--", "--runInBand"]
    elif framework == "go": command = ["go", "test", "./..."] + (["-failfast"] if fail_fast else [])
    else: raise ToolFailure(f"Unsupported framework: {framework}", code="unsupported_framework")
    started = time.monotonic()
    try: exit_code, stdout, stderr, cut = run_captured(command, cwd=root, timeout=timeout)
    except FileNotFoundError as error: raise ToolFailure(f"Test runner not found: {command[0]}", code="missing_dependency") from error
    except subprocess.TimeoutExpired as error: raise ToolFailure(f"Tests timed out after {timeout}s.", code="timeout", retryable=True) from error
    output = (stdout.decode(errors="replace") + "\n" + stderr.decode(errors="replace")).strip()
    bounded, truncated = context.bounded_text(output)
    total = 0
    for pattern in (r"Ran (\d+) tests?", r"(\d+) passed", r"ok\s+.+\s+(\d+(?:\.\d+)?)s"):
        match = re.search(pattern, output)
        if match:
            try: total = int(match.group(1))
            except ValueError: pass
            break
    failures = [line.strip() for line in output.splitlines() if re.search(r"\b(?:FAIL|ERROR|failed)\b", line, re.I)][:50]
    advice = ""
    if framework == "unittest" and "NO TESTS RAN" in output.upper():
        # unittest discovers TestCase classes. A file of bare `def test_x()`
        # functions is pytest's shape, so say that rather than reporting a
        # mysterious empty run the caller cannot act on.
        pytest_style = any("def test_" in path.read_text(encoding="utf-8", errors="replace")
                           for path in list(root.glob("test*.py"))[:20]
                           if path.is_file())
        advice = ("unittest found no TestCase classes. These tests are written as plain "
                  "functions, which is pytest's style; install pytest to run them, or "
                  "use diagnostics to check the code instead."
                  if pytest_style else
                  "No tests were discovered. Check the file names match test*.py.")
    passed = exit_code == 0 and not (framework in {"unittest", "pytest"} and total == 0)
    return {"framework": framework, "command": command, "passed": passed,
            "advice": advice, "exit_code": exit_code,
            "total": total, "failures": failures, "output": bounded,
            "duration_ms": round((time.monotonic()-started)*1000), "_truncated": cut or truncated or len(failures) == 50}
