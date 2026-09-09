"""The standing task list: what the agent is doing, kept where it can see it.

A long task drifts because the goal leaves the context window while the work is
still going on. Keeping a short checklist in the prompt — rewritten by the agent
itself as it goes — is what holds a multi-step job together, and it gives the
verification gate something concrete to refuse: marking everything done.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PENDING = "pending"
IN_PROGRESS = "in_progress"
COMPLETED = "completed"
STATUSES = (PENDING, IN_PROGRESS, COMPLETED)
MAX_ITEMS = 8


@dataclass(frozen=True)
class TodoItem:
    identifier: str
    task: str
    status: str = PENDING


@dataclass
class TodoList:
    """The checklist as it stands, rendered into every turn's prompt."""

    items: list[TodoItem] = field(default_factory=list)

    def replace(self, payload: list[dict[str, Any]]) -> None:
        """Take the agent's rewritten list, keeping only what is well formed."""

        rebuilt: list[TodoItem] = []
        for index, raw in enumerate(payload or [], 1):
            if not isinstance(raw, dict):
                continue
            task = str(raw.get("task") or "").strip()[:500]
            if not task:
                continue
            status = str(raw.get("status") or PENDING).strip().casefold()
            rebuilt.append(TodoItem(str(raw.get("id") or index)[:32], task,
                                    status if status in STATUSES else PENDING))
            if len(rebuilt) >= MAX_ITEMS:
                break
        self.items = rebuilt

    def all_complete(self) -> bool:
        return bool(self.items) and all(item.status == COMPLETED for item in self.items)

    def render(self) -> str:
        if not self.items:
            return "Task list: not started. Call todo_write with 3 to 6 steps before you begin."
        marks = {COMPLETED: "[x]", IN_PROGRESS: "[>]", PENDING: "[ ]"}
        lines = ["Task list:"]
        for item in self.items:
            suffix = "  <- doing this now" if item.status == IN_PROGRESS else ""
            lines.append(f"  {marks[item.status]} {item.identifier}. {item.task}{suffix}")
        return "\n".join(lines)


TODO_WRITE_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "todo_write",
        "description": (
            "Write or rewrite the standing task list for this job. Call it first with "
            "3 to 6 steps, then again after each step to mark progress. Exactly one "
            "task should be in_progress at a time."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "todos": {
                    "type": "array",
                    "description": "The full list, rewritten each time.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "description": "Step number, e.g. '1'"},
                            "task": {"type": "string", "description": "What this step does"},
                            "status": {"type": "string", "enum": list(STATUSES)},
                        },
                        "required": ["id", "task", "status"],
                    },
                }
            },
            "required": ["todos"],
        },
    },
}
