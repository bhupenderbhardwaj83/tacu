"""Bounded cognitive retries and language-answer refine helpers.

Host auto/do: observe → execute → critique → replan, up to MAX_COGNITIVE_TURNS.
Language / ask answer-writer: at most MAX_AI_TURNS model refine attempts.
"""

from __future__ import annotations

import re
from typing import Any

from .answer_format import leaked_reasoning, strip_leaked_reasoning
from .routing import native_steps_for_intent

# Observe → act → critique → replan. Bounded so a small local model can recover.
MAX_COGNITIVE_TURNS = 3
MAX_AI_TURNS = 2

_LANGUAGE_TASK = re.compile(
    r"\b(translate|translation|rephrase|paraphrase|rewrite|"
    r"(?:into|in) (?:polite|humble|softer|kinder) language|"
    r"polite language|make this (?:more )?(?:polite|humble)|"
    r"correct the grammar|spell[- ]?check|"
    r"summarize (?:this|the|my)\b|"
    r"explain (?:why|how|what|this|the)\b)",
    flags=re.I,
)
_SAFETY_REFUSAL = re.compile(
    r"\b(i cannot|i can't|i will not|i won't|i am not able to|i'm not able to|"
    r"abusive|violent content|"
    r"cannot (?:translate|help with|assist with) (?:that|this|abusive))\b",
    flags=re.I,
)
_VALIDATION_TASK = re.compile(
    r"\b(validate|two runs?|run twice|double[- ]check|verify (the )?(result|output)|"
    r"refine the output)\b",
    flags=re.I,
)


def is_language_question(intent: str) -> bool:
    return bool(_LANGUAGE_TASK.search(intent))


def is_language_fast_path(intent: str) -> bool:
    """Language-only work should skip host tools. The model may still refine once."""

    if not is_language_question(intent):
        return False
    return not native_steps_for_intent(intent)


def wants_validation_loop(intent: str) -> bool:
    return bool(_VALIDATION_TASK.search(intent))


def should_buffer_ai_answer(query: str, tool_result: dict[str, Any] | None) -> bool:
    """Buffer the first model attempt so a bad language/evidence answer can be refined."""

    if tool_result is not None:
        return True
    return is_language_question(query)


def core_answer_body(text: str) -> str:
    return re.sub(r"(?ms)(?:^|\n\n)Next:\s*.*$", "", (text or "").strip()).strip()


def is_safety_refusal(text: str) -> bool:
    return bool(_SAFETY_REFUSAL.search(text or ""))


def answer_needs_refine(query: str, response: str,
                        tool_result: dict[str, Any] | None = None) -> str | None:
    """Why the model answer is unusable. None means keep it, including genuine refusals."""

    body = strip_leaked_reasoning(core_answer_body(response))
    if not body:
        return "empty answer"
    if leaked_reasoning(body):
        return "showed planning instead of the answer"
    if is_safety_refusal(body):
        return None
    if len(body) < 8:
        return "too short"
    folded = body.casefold()
    if tool_result is not None and re.search(r"did not inspect( the disk)?", folded):
        return "claimed no inspection despite tool evidence"
    if is_language_question(query):
        if folded.startswith(("translate this", "rephrase this", "rewrite this",
                              "i am a language model", "as an ai")):
            return "did not complete the language task"
        if folded == query.casefold().strip():
            return "echoed the request"
    return None


def refine_user_message(query: str, reason: str) -> str:
    return (
        f"{query}\n\nYour previous answer was not usable ({reason}). "
        "Write only the completed core answer. Do not repeat these instructions."
    )


def mismatch_reason(intent: str, results: list[dict[str, Any]]) -> str | None:
    """Compatibility wrapper — host critic lives in harness.critique_goal."""

    from .harness import critique_goal
    return critique_goal(intent, results)


def correction_steps(intent: str, results: list[dict[str, Any]], reason: str) -> list[dict[str, Any]]:
    """Compatibility wrapper — corrections live in harness.correction_from_failure."""

    from .harness import correction_from_failure
    return correction_from_failure(intent, reason)


def merge_results(previous: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Later native retries replace earlier results for the same command."""

    def _exit_code(item: dict[str, Any]) -> int:
        data = ((item.get("result") or {}).get("data")) or {}
        if "exit_code" in data:
            try:
                return int(data.get("exit_code") or 0)
            except (TypeError, ValueError):
                return 1
        result = item.get("result") or {}
        if result.get("ok") is False:
            return 1
        return 0

    extra_keys = {tuple(item.get("command") or []) for item in extra}
    kept = []
    for item in previous:
        command = tuple(item.get("command") or [])
        if command in extra_keys:
            continue
        if _exit_code(item) != 0:
            continue
        kept.append(item)
    return kept + list(extra)
