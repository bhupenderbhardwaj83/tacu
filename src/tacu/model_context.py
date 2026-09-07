"""Question-aware evidence pruning before terminal output reaches a model."""

from __future__ import annotations

import copy
import json
import re
from typing import Any

from .core import redact_sensitive_text

MODEL_EVIDENCE_CHAR_LIMIT = 32_000
STDERR_CHAR_LIMIT = 8_000
STOP_WORDS = {"about", "after", "again", "from", "have", "into", "just", "please", "show", "that",
              "the", "then", "there", "these", "this", "those", "what", "when", "where", "which", "with",
              "would", "your", "output", "command", "result", "give", "tell"}
SIGNAL = re.compile(r"(?i)\b(?:error|failed?|failure|fatal|warning|critical|denied|timeout|status|running|stopped|"
                    r"open|closed|listening|vulnerab|credential|password|token|secret|image|interface|address|ip)\b")


def _keywords(question: str) -> set[str]:
    return {word.casefold() for word in re.findall(r"[A-Za-z0-9_.:/-]{3,}", question)
            if word.casefold() not in STOP_WORDS}


def prune_text(text: str, question: str, budget: int) -> tuple[str, dict[str, Any]]:
    """Keep relevant signals plus bounded head/tail samples, removing duplicate noise."""

    original_lines = text.splitlines()
    if not original_lines:
        return "", {"original_lines": 0, "kept_lines": 0, "duplicates_removed": 0,
                    "original_chars": len(text), "kept_chars": 0}
    unique: list[tuple[int, str]] = []
    seen: set[str] = set()
    duplicates = 0
    for index, line in enumerate(original_lines):
        normalized = " ".join(line.split())
        if normalized and normalized in seen:
            duplicates += 1; continue
        if normalized: seen.add(normalized)
        unique.append((index, line[:2_000]))
    # Everything that fits, goes. Head-and-tail sampling is for input too large to
    # send, not for input that merely has more than 24 lines: a 34-line `ls -la`
    # was cut to its first 24 and the model then listed 20 of 31 files and stopped,
    # confidently, because the rest was never shown to it.
    whole = "\n".join(line for _, line in unique)
    if len(whole) <= budget:
        metadata = {"original_lines": len(original_lines), "kept_lines": len(unique),
                    "duplicates_removed": duplicates, "original_chars": len(text),
                    "kept_chars": len(whole), "complete": True}
        return whole, metadata

    words = _keywords(question)
    relevant_indexes: set[int] = set()
    for index, line in unique:
        lowered = line.casefold()
        if SIGNAL.search(line) or any(word in lowered for word in words):
            relevant_indexes.update({index - 1, index, index + 1})
    relevant = [line for index, line in unique if index in relevant_indexes]
    head = [line for _, line in unique[:24]]
    tail = [line for _, line in unique[-24:]]
    sections: list[str] = []
    if relevant:
        sections.extend(("[TACU relevant lines]", *relevant[:160]))
    sections.extend(("[TACU output start]", *head))
    # Whenever lines are dropped the end is shown too, and the gap is named, so a
    # partial view is never mistaken for the whole thing.
    if len(unique) > len(head):
        sections.extend((f"[TACU omitted {len(unique) - len(head) - len(tail)} middle line(s) "
                         f"of {len(unique)}]", *tail))
    compact = "\n".join(sections)
    if len(compact) > budget:
        half = max(1, (budget - 80) // 2)
        compact = compact[:half] + "\n[... TACU context budget applied ...]\n" + compact[-half:]
    metadata = {"original_lines": len(original_lines), "kept_lines": len(compact.splitlines()),
                "duplicates_removed": duplicates, "original_chars": len(text), "kept_chars": len(compact)}
    return compact, metadata


def _bounded_json(value: Any, *, depth: int = 0) -> Any:
    if depth >= 8: return "[depth limit]"
    if isinstance(value, dict):
        items = list(value.items())
        result = {str(key): _bounded_json(item, depth=depth + 1) for key, item in items[:100]}
        if len(items) > 100: result["_tacu_omitted_keys"] = len(items) - 100
        return result
    if isinstance(value, list):
        result = [_bounded_json(item, depth=depth + 1) for item in value[:50]]
        if len(value) > 50: result.append({"_tacu_omitted_items": len(value) - 50})
        return result
    if isinstance(value, str) and len(value) > 2_000:
        return value[:1_000] + "\n[... truncated ...]\n" + value[-1_000:]
    return value


def _compact_block(block: dict[str, Any], question: str, budget: int) -> tuple[dict[str, Any], dict[str, Any]]:
    kind = block.get("type")
    if kind == "text":
        text, metadata = prune_text(str(block.get("text", "")), question, budget)
        return {"type": "text", "text": text, "line_count": len(text.splitlines())}, metadata
    compact = _bounded_json(block)
    encoded = json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
    original_chars = len(json.dumps(block, ensure_ascii=False, default=str))
    if len(encoded) > budget:
        half = max(1, (budget - 100) // 2)
        compact = {"type": kind or "structured", "serialized_sample": encoded[:half] +
                   "[... TACU structured context budget applied ...]" + encoded[-half:]}
    kept_chars = len(json.dumps(compact, ensure_ascii=False, default=str))
    return compact, {"original_chars": original_chars, "kept_chars": kept_chars,
                     "original_lines": block.get("line_count"), "kept_lines": None, "duplicates_removed": 0}


def _compact_facts(facts: dict[str, Any], question: str, budget: int) -> dict[str, Any]:
    """Keep the requested deterministic facts while bounding large inventories."""

    selected = _bounded_json(facts)
    words = _keywords(question)
    if selected.get("kind") == "network_interfaces" and isinstance(facts.get("interfaces"), list):
        interfaces = facts["interfaces"]
        primary = selected.get("primary") or {}
        primary_name = primary.get("name") if isinstance(primary, dict) else None

        def interface_score(indexed_item: tuple[int, Any]) -> tuple[int, int]:
            index, item = indexed_item
            if not isinstance(item, dict):
                return (0, 0)
            name = str(item.get("name", "")).casefold()
            return (int(name == str(primary_name).casefold()) * 8 +
                    int(any(word in name for word in words)) * 4 +
                    int(item.get("status") == "active") * 2 + int(bool(item.get("ipv4"))),
                    -index)

        kept = sorted(((index, item) for index, item in enumerate(interfaces) if isinstance(item, dict)),
                      key=interface_score, reverse=True)[:12]
        selected["interfaces"] = [_bounded_json(item) for _, item in kept]
        if len(interfaces) > len(kept):
            selected["_tacu_omitted_interfaces"] = len(interfaces) - len(kept)
    for key in ("ports", "networks", "mounts"):
        values = selected.get(key)
        if isinstance(values, list) and len(values) > 24:
            selected[key] = values[:24]
            selected[f"_tacu_omitted_{key}"] = len(values) - 24
    if len(json.dumps(selected, ensure_ascii=False, default=str)) <= budget:
        return selected
    essentials = {key: value for key, value in selected.items()
                  if key in {"kind", "name", "id", "image", "image_digest", "status", "running", "primary",
                             "interface_count", "method", "source", "image_title", "image_version", "platform"}
                  or not isinstance(value, (dict, list))}
    essentials["_tacu_omitted_fact_fields"] = sorted(set(selected) - set(essentials))
    for key, value in list(essentials.items()):
        if isinstance(value, str) and len(value) > 500:
            essentials[key] = value[:500] + " [... truncated ...]"
    return essentials


def _redact_value(value: Any) -> tuple[Any, int]:
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        output, count = [], 0
        for item in value:
            redacted, found = _redact_value(item)
            output.append(redacted); count += found
        return output, count
    if isinstance(value, dict):
        output, count = {}, 0
        for key, item in value.items():
            redacted, found = _redact_value(item)
            output[key] = redacted; count += found
        return output, count
    return value, 0


def compact_evidence(evidence: dict[str, Any], question: str,
                     limit: int = MODEL_EVIDENCE_CHAR_LIMIT,
                     redact_sensitive: bool = False) -> dict[str, Any]:
    """Create a transparent model-only view while leaving stored capture untouched."""

    if not isinstance(evidence, dict): return evidence
    compact: dict[str, Any] = {key: copy.deepcopy(evidence[key]) for key in
                               ("schema", "tool", "status", "invocation", "profile", "juicy") if key in evidence}
    facts = evidence.get("facts")
    if facts:
        model_facts = _compact_facts(facts, question, max(2_000, limit // 3))
        compact["facts"] = model_facts
        stdout = {"type": "companion_facts", "data": copy.deepcopy(model_facts),
                  "note": "Verbose stdout omitted because TACU extracted deterministic facts."}
        stdout_meta = {"original_chars": len(json.dumps(evidence.get("result", {}).get("stdout", {}), default=str)),
                       "kept_chars": len(json.dumps(stdout, default=str)), "strategy": "native-facts"}
    else:
        stdout, stdout_meta = _compact_block(evidence.get("result", {}).get("stdout", {}), question,
                                             max(2_000, limit - STDERR_CHAR_LIMIT - 4_000))
        stdout_meta["strategy"] = "relevance-dedupe-head-tail"
    stderr, stderr_meta = _compact_block(evidence.get("result", {}).get("stderr", {}), question, STDERR_CHAR_LIMIT)
    compact["result"] = {"exit_code": evidence.get("result", {}).get("exit_code"),
                         "duration_ms": evidence.get("result", {}).get("duration_ms"),
                         "stdout": stdout, "stderr": stderr}
    capture = copy.deepcopy(evidence.get("capture", {}))
    capture["model_view"] = {"budget_chars": limit, "pruned": True, "stdout": stdout_meta, "stderr": stderr_meta,
                             "stored_capture_unchanged": True}
    compact["capture"] = capture
    encoded = json.dumps(compact, ensure_ascii=False, default=str)
    if len(encoded) > limit:
        # Metadata and deterministic facts win; trim the two model-facing streams again.
        remaining = max(2_000, limit - len(encoded) + len(json.dumps(stdout)) + len(json.dumps(stderr)))
        stdout, _ = _compact_block(stdout, question, remaining * 3 // 4)
        stderr, _ = _compact_block(stderr, question, remaining // 4)
        compact["result"]["stdout"], compact["result"]["stderr"] = stdout, stderr
    if redact_sensitive:
        compact, redacted_count = _redact_value(compact)
        compact.setdefault("information_policy", {}).update({
            "provider_scope": "non-local",
            "sensitive_values_redacted": redacted_count,
        })
    else:
        compact.setdefault("information_policy", {}).update({
            "provider_scope": "local-or-unspecified",
            "sensitive_values_redacted": 0,
        })
    return compact
