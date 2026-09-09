"""Apply deterministic policy to the actual invocation, not just to the prompt.

One gate for every lane that lets a model choose its own arguments. What differs
between lanes is the tool surface it may choose from and who is asked before a
change is made — not whether anything is checked. A lane that skipped this
because "its tools only read" was relying on a hand-written tuple staying right.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from .automation import CommandStep, evaluate_policy
from .coding import CODING_TOOL_SURFACE
from .tools.contracts import ToolContext


def dispatch_coding(name: str, payload: dict[str, Any], workspace: Path, state_dir: Path,
                    invoke: Callable, approve: Callable[[str], bool]) -> dict[str, Any]:
    return dispatch_tool(name, payload, workspace, state_dir, invoke, approve,
                         surface=CODING_TOOL_SURFACE, lane="coding")


def dispatch_tool(name: str, payload: dict[str, Any], workspace: Path, state_dir: Path,
                  invoke: Callable, approve: Callable[[str], bool], *,
                  surface: tuple[str, ...] = CODING_TOOL_SURFACE,
                  lane: str = "this lane") -> dict[str, Any]:
    """Run one model-chosen tool call, after policy has seen the call itself.

    The surface is the primary containment: a model cannot ask for a tool it was
    never offered, so a lane that only reads is one whose surface only reads.
    Policy is the second gate, and it judges the invocation rather than a plan
    that may since have drifted from it.
    """

    if name not in surface:
        return {"status": "error", "error": f"Tool {name!r} is not available in {lane}."}
    # All paths stay in this workspace, even if an operation is reviewed.
    context = ToolContext(workspace, state_dir)
    for field in ("path", "root", "cwd", "target"):
        if payload.get(field):
            context.guarded_path(str(payload[field]))
    runs = name in {"shell", "verify"} or (name == "service_process" and payload.get("operation") == "start")
    if runs:
        executable = str(payload.get("executable") or "")
        checked = executable
        # A venv interpreter is a normal workspace runner, but -c remains blocked.
        path = Path(executable)
        local = (workspace / path).absolute() if not path.is_absolute() else path.absolute()
        if workspace.resolve() in local.parents and re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", path.name):
            checked = "python3"
        step = CommandStep(checked, tuple(str(arg) for arg in payload.get("args", [])),
                           str(payload.get("cwd") or "."), str(payload.get("purpose") or name))
    else:
        operation = {"write_file": "write", "edit_file": "edit", "read_file": "read"}.get(name, "inspect")
        step = CommandStep(name, (), ".", name, name, operation, json.dumps(payload))
    decision = evaluate_policy(step, workspace)
    if decision.level == "block":
        return {"status": "error", "error": "Blocked: " + "; ".join(decision.reasons)}
    reviewed = False
    if decision.requires_permission:
        display = (str(payload.get("executable")) + " " + " ".join(str(arg) for arg in payload.get("args", []))) if runs else step.display
        reviewed = approve(display + "\n" + "; ".join(decision.reasons))
        if not reviewed:
            return {"status": "error", "error": "Approval required; command was not run.", "approval_required": True}
    context = ToolContext(workspace, state_dir, approve_dangerous=reviewed,
                          policy_level=decision.level, policy_reasons=decision.reasons)
    result = invoke(name, payload, context)
    data = dict(result.data or {})
    data.setdefault("status", "success" if result.ok else "error")
    if not result.ok:
        data["error"] = result.error
    return data
