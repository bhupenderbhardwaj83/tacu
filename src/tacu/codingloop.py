"""One step at a time, with the workspace answering back.

Batch planning asks a model to name the arguments of step four before step one
has run. It cannot know the indentation in a file it has not read, so the edit
misses, and every later step builds on the miss. This loop asks for one action,
runs it, shows the result, and asks again — the model adapts to what is actually
there instead of to what it guessed would be.

Three things hold it together over a long job: a task list the model rewrites as
it goes and sees on every turn, a guard that will not let it call the work
finished while the code is unproven, and a copy of the source taken before the
first change so a bad run can be undone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .codingguard import CodingGuard
from .snapshot import Snapshot
from .todo import TODO_WRITE_SCHEMA, TodoList

# Byte-identical on every turn. Anything that varies here — a timestamp, a step
# number — throws away the model's cached prefix and pays to recompute it.
SYSTEM_PREFIX = """You are TACU's coding agent, working directly in a real codebase.

How you work:
1. Look before you touch. Read the file, or search for the symbol, before editing it.
2. Edit precisely. Use edit_file with enough surrounding text that the match is unique.
   Never replace a working file with a stub or a placeholder.
3. Prove it. After changing code, run the tests, or diagnostics when there are none,
   and get a clean result. Changing files is not finishing the job.
4. Keep the list current. Call todo_write first with 3 to 6 steps, then again after
   each step. Exactly one step is in_progress at a time.
5. One action per turn. Call a single tool and wait for the result.

The shell runs tests, linters and builds. It does not write to source files —
edit_file and write_file do that, so the change is recorded and can be undone.

When every step is done and a check has passed, reply in plain words with what you
changed and what proves it. Do not call a tool in that final message."""

MAX_TOOL_RESULT_CHARS = 4_000
HISTORY_EXCHANGES = 6


def prune(text: str, limit: int = MAX_TOOL_RESULT_CHARS) -> str:
    """Keep both ends of a long result and say what was dropped."""

    if len(text) <= limit:
        return text
    half = limit // 2
    dropped = len(text) - limit
    return f"{text[:half]}\n… [{dropped} characters omitted] …\n{text[-half:]}"


@dataclass
class LoopOutcome:
    completed: bool
    answer: str
    steps: int
    changed: list[str] = field(default_factory=list)
    verified: bool = False
    stopped: str = ""


@dataclass
class CodingLoop:
    """Runs one coding job to a verified finish, or stops and says why."""

    workspace: Path
    goal: str
    client: Any
    tools: list[dict[str, Any]]
    dispatch: Callable[[str, dict[str, Any]], dict[str, Any]]
    max_steps: int = 12
    on_event: Callable[[str, str], None] | None = None

    def __post_init__(self) -> None:
        self.workspace = self.workspace.resolve()
        self.todos = TodoList()
        self.guard = CodingGuard(workspace=self.workspace)
        self.snapshot = Snapshot(workspace=self.workspace)
        self.history: list[dict[str, Any]] = []
        self.schemas = list(self.tools) + [TODO_WRITE_SCHEMA]

    def _say(self, kind: str, message: str) -> None:
        if self.on_event is not None:
            self.on_event(kind, message)

    def _messages(self) -> list[dict[str, Any]]:
        """Stable prefix, then the standing state, then a window of recent work."""

        standing = (f"Workspace: {self.workspace}\n"
                    f"Goal: {self.goal}\n\n{self.todos.render()}")
        window = self.history[-(HISTORY_EXCHANGES * 2):]
        return [{"role": "system", "content": SYSTEM_PREFIX},
                {"role": "user", "content": standing},
                *window]

    def _record_call(self, name: str, arguments: dict[str, Any]) -> None:
        self.history.append({"role": "assistant", "content": "",
                             "tool_calls": [{"function": {"name": name,
                                                          "arguments": arguments}}]})

    def _record_result(self, name: str, payload: Any) -> None:
        body = payload if isinstance(payload, str) else json.dumps(payload, default=str)
        self.history.append({"role": "tool", "name": name, "content": prune(body)})

    def _run_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "todo_write":
            refusal = None
            if self.todos.items or arguments.get("todos"):
                candidate = TodoList()
                candidate.replace(arguments.get("todos") or [])
                if candidate.all_complete():
                    refusal = self.guard.refuse_completion()
            if refusal:
                self._say("refused", refusal)
                return {"status": "error", "error": refusal}
            self.todos.replace(arguments.get("todos") or [])
            return {"status": "success", "task_list": self.todos.render()}

        refusal = self.guard.refuse_before(name, arguments)
        if refusal:
            self._say("refused", refusal)
            return {"status": "error", "error": refusal}
        if name in {"edit_file", "write_file"}:
            # Taken once, and only when something is about to change.
            self.snapshot.take()
        try:
            result = self.dispatch(name, arguments)
        except Exception as error:                     # a tool failing is data, not a crash
            result = {"status": "error", "error": f"{name} failed: {error}"}
        self.guard.observe(name, arguments, result if isinstance(result, dict) else {})
        return result if isinstance(result, dict) else {"status": "success", "result": result}

    def run(self) -> LoopOutcome:
        self.history.append({"role": "user", "content": self.goal})
        actions = 0
        # Turns are capped separately so bookkeeping cannot loop forever, but the
        # budget the user sets counts work: four of eight steps once went on
        # rewriting the task list, and the job ran out before it could be proved.
        for turn in range(1, self.max_steps * 3 + 1):
            if actions >= self.max_steps:
                break
            try:
                reply = self.client.chat_tools(self._messages(), self.schemas)
            except Exception as error:
                return LoopOutcome(False, str(error), actions, self.snapshot.changed(),
                                   self.guard.verified, stopped="model error")
            calls = reply.get("tool_calls") or []

            if not calls:
                answer = reply.get("content") or ""
                refusal = self.guard.refuse_completion()
                if refusal:
                    self._say("refused", refusal)
                    self.history.append({"role": "assistant", "content": answer})
                    self.history.append({"role": "user", "content": refusal})
                    continue
                self._say("done", f"finished after {actions} action(s)")
                return LoopOutcome(True, answer.strip(), actions, self.snapshot.changed(),
                                   self.guard.verified)

            for call in calls[:1]:                     # one action per turn, by design
                name, arguments = call["name"], call["arguments"]
                if name != "todo_write":
                    actions += 1
                self._say("call", f"{name}({', '.join(sorted(arguments))})")
                self._record_call(name, arguments)
                self._record_result(name, self._run_tool(name, arguments))

        return LoopOutcome(False, "", actions, self.snapshot.changed(),
                           self.guard.verified, stopped="step budget")
