"""When to hand the job to the bigger model, and how to make room for it.

The small model does most of the work: it is quick, it fits in memory beside
everything else, and it answers ordinary questions well. It is not good at
holding a job together over many steps.

Deciding which is which up front does not work. Both models answer a single
turn of "refactor the auth module" identically — with one tool call — so
nothing about the wording tells you that one of them will still be going in
circles six steps later. What does tell you is watching: a turn that produced
nothing, the same call made twice, a guard refusing the same thing again, half
the budget spent with nothing changed and nothing proved.

So escalation is a reaction to evidence, never a prediction. And because
Ollama keeps a model resident for its keep-alive after the last request, the
model being left behind is unloaded rather than left holding memory the bigger
one needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# How much repetition or emptiness is a stall rather than a bad turn.
DEAD_TURNS_BEFORE_ESCALATING = 2
REPEATS_BEFORE_ESCALATING = 2
REFUSALS_BEFORE_ESCALATING = 3


@dataclass
class RunSignals:
    """What the run has shown about whether the model is getting anywhere."""

    dead_turns: int = 0            # a turn that produced neither a call nor an answer
    truncated_turns: int = 0       # the reply budget ran out mid-thought
    repeated_calls: int = 0        # the same tool with the same arguments, again
    refusals: int = 0              # the guard sent the same thing back
    unknown_tools: int = 0         # a call for a tool that does not exist
    actions: int = 0
    budget: int = 0
    changed_anything: bool = False
    verified: bool = False
    _seen: set[tuple[str, str]] = field(default_factory=set)

    def note_turn(self, *, calls: int, content: str, done_reason: str) -> None:
        if calls == 0 and not content.strip():
            self.dead_turns += 1
        if done_reason == "length" and not content.strip():
            self.truncated_turns += 1

    def note_call(self, name: str, signature: str, known: bool) -> None:
        self.actions += 1
        if not known:
            self.unknown_tools += 1
            return
        if (name, signature) in self._seen:
            self.repeated_calls += 1
        self._seen.add((name, signature))

    def note_refusal(self) -> None:
        self.refusals += 1


def escalation_reason(signals: RunSignals) -> str | None:
    """Why this run should move up to the bigger model, or None to carry on.

    Each of these is a way of not getting anywhere, phrased so the user can see
    what TACU saw rather than being told the model was "struggling".
    """

    # Truncation first: it is the same silence, but with a cause worth naming.
    if signals.truncated_turns >= DEAD_TURNS_BEFORE_ESCALATING:
        return f"{signals.truncated_turns} replies ran out of room before answering"
    if signals.dead_turns >= DEAD_TURNS_BEFORE_ESCALATING:
        return f"{signals.dead_turns} turns produced neither an action nor an answer"
    if signals.unknown_tools >= 1:
        return "a tool was called that does not exist"
    if signals.repeated_calls >= REPEATS_BEFORE_ESCALATING:
        return f"the same call was made {signals.repeated_calls + 1} times without progress"
    if signals.refusals >= REFUSALS_BEFORE_ESCALATING:
        return f"the same work was sent back {signals.refusals} times"
    # Half the allowance gone with nothing touched and nothing proved.
    if (signals.budget and signals.actions >= max(3, signals.budget // 2)
            and not signals.changed_anything and not signals.verified):
        return (f"{signals.actions} actions in and nothing has changed or been checked")
    return None


def make_room_for(model: str) -> list[str]:
    """Unload every other model so the incoming one has the memory.

    Ollama evicts under pressure by itself, but a long keep-alive means it holds
    a model nothing is asking for until that timer expires — and the bigger model
    wants the memory now, not in fifteen minutes.
    """

    from .coding import release_other_models

    return release_other_models(model)
