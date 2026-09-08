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
from .escalation import RunSignals, escalation_reason, make_room_for
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
    # Given a model name, hand back a client for it. Absent means no escalation:
    # the run finishes with the model it started with, or says it could not.
    escalate_to: str = ""
    make_client: Callable[[str], Any] | None = None
    # A run that only reads: no task list to keep, and nothing that could ever
    # change, so "nothing has changed yet" is not evidence of being stuck.
    read_only: bool = False

    def __post_init__(self) -> None:
        self.workspace = self.workspace.resolve()
        self.todos = TodoList()
        self.guard = CodingGuard(workspace=self.workspace)
        self.snapshot = Snapshot(workspace=self.workspace)
        self.history: list[dict[str, Any]] = []
        self.schemas = list(self.tools) if self.read_only else list(self.tools) + [TODO_WRITE_SCHEMA]
        self.signals = RunSignals(budget=self.max_steps)
        self.known = {schema["function"]["name"] for schema in self.schemas}
        self.escalated = False

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


    def _maybe_escalate(self) -> None:
        """Move up to the stronger model once the run has shown it is stuck.

        Once only. A second model that cannot finish the job is a job that needs
        a person, not a third attempt, and the run says so rather than churning.
        """

        if self.escalated or not self.escalate_to or self.make_client is None:
            return
        reason = escalation_reason(self.signals)
        if reason is None:
            return
        self.escalated = True
        released = make_room_for(self.escalate_to)
        if released:
            self._say("models", f"unloaded {', '.join(released)} to make room")
        try:
            self.client = self.make_client(self.escalate_to)
        except Exception as error:                     # keep going with what works
            self._say("refused", f"could not switch to {self.escalate_to}: {error}")
            return
        self._say("escalate", f"{reason} — continuing with {self.escalate_to}")
        # The stronger model starts from the same state, so nothing already done
        # is repeated; only the reasoning that was going nowhere is dropped.
        self.signals = RunSignals(budget=self.max_steps)

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
            self.signals.note_turn(calls=len(calls), content=reply.get("content") or "",
                                   done_reason=reply.get("done_reason") or "")
            self.signals.changed_anything = bool(self.guard.mutated) or self.read_only
            self.signals.verified = self.guard.verified or self.read_only
            self._maybe_escalate()

            if not calls:
                answer = reply.get("content") or ""
                refusal = self.guard.refuse_completion()
                if refusal:
                    self._say("refused", refusal)
                    self.signals.note_refusal()
                    self.history.append({"role": "assistant", "content": answer})
                    self.history.append({"role": "user", "content": refusal})
                    continue
                self._say("done", f"finished after {actions} action(s)")
                return LoopOutcome(True, answer.strip(), actions, self.snapshot.changed(),
                                   self.guard.verified)

            for call in calls[:1]:                     # one action per turn, by design
                name, arguments = call["name"], call["arguments"]
                self.signals.note_call(name, json.dumps(arguments, sort_keys=True, default=str),
                                       name in self.known)
                if name != "todo_write":
                    actions += 1
                self._say("call", f"{name}({', '.join(sorted(arguments))})")
                self._record_call(name, arguments)
                self._record_result(name, self._run_tool(name, arguments))

        return LoopOutcome(False, "", actions, self.snapshot.changed(),
                           self.guard.verified, stopped="step budget")
