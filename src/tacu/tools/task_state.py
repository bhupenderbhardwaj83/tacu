"""SQLite task state for long-running harness objectives."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "task_state", "Persist objectives, plans, progress, blockers, and checkpoints.",
    schema(properties={"operation": {"type": "string", "enum": ["get", "plan", "add", "update", "block", "complete", "checkpoint"]},
                       "task_id": {"type": "string"}, "objective": {"type": "string"},
                       "status": {"type": "string"}, "note": {"type": "string"},
                       "items": {"type": "array"}}, required=("operation",)),
    schema(properties={"task": {"type": "object"}}), risk_level="write", permissions=("state:write",), idempotent=False,
)


def _tables(connection) -> None:
    connection.executescript("""
      CREATE TABLE IF NOT EXISTS harness_tasks (
        task_id TEXT PRIMARY KEY, objective TEXT NOT NULL, status TEXT NOT NULL,
        plan_json TEXT NOT NULL, progress_json TEXT NOT NULL, blocker TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS harness_checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
        note TEXT NOT NULL, created_at TEXT NOT NULL
      );
    """)


def _get(connection, task_id: str | None) -> dict[str, Any] | None:
    if task_id:
        row = connection.execute("SELECT * FROM harness_tasks WHERE task_id=?", (task_id,)).fetchone()
    else:
        row = connection.execute("SELECT * FROM harness_tasks ORDER BY updated_at DESC LIMIT 1").fetchone()
    if not row: return None
    return {"task_id": row[0], "objective": row[1], "status": row[2], "plan": json.loads(row[3]),
            "progress": json.loads(row[4]), "blocker": row[5], "created_at": row[6], "updated_at": row[7]}


def execute(context: ToolContext, *, operation: str, task_id: str | None = None,
            objective: str | None = None, status: str | None = None,
            note: str | None = None, items: list[Any] | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    with context.database() as connection:
        _tables(connection)
        if operation == "add":
            if not objective: raise ToolFailure("objective is required for add", code="invalid_input")
            task_id = task_id or uuid.uuid4().hex[:12]
            connection.execute("INSERT INTO harness_tasks VALUES (?,?,?,?,?,?,?,?)",
                               (task_id, objective, "active", "[]", "[]", None, now, now))
        elif operation == "get":
            return {"task": _get(connection, task_id)}
        else:
            current = _get(connection, task_id)
            if not current: raise ToolFailure("No matching task state.", code="task_not_found")
            task_id = current["task_id"]
            if operation == "plan": current["plan"] = items or []
            elif operation == "update":
                current["progress"].append(note or "updated")
                if status: current["status"] = status
            elif operation == "block": current["status"], current["blocker"] = "blocked", note or "blocked"
            elif operation == "complete": current["status"], current["blocker"] = "complete", None
            elif operation == "checkpoint":
                connection.execute("INSERT INTO harness_checkpoints(task_id,note,created_at) VALUES (?,?,?)",
                                   (task_id, note or "checkpoint", now))
            connection.execute("UPDATE harness_tasks SET status=?,plan_json=?,progress_json=?,blocker=?,updated_at=? WHERE task_id=?",
                               (current["status"], json.dumps(current["plan"]), json.dumps(current["progress"]),
                                current["blocker"], now, task_id))
        return {"task": _get(connection, task_id)}

