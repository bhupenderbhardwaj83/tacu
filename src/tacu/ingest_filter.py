"""Deterministic pipe ingest → filter before any model call.

Runs after classify_stdout / extract_facts packaging. Projects JSON, JSONL,
CSV/tables, and text logs so the model sees a filtered slice — or so
exact_answer can skip the model for schema / column / key lookups.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .model_context import prune_text

FILTER_ROW_LIMIT = 80
FILTER_TEXT_LINE_LIMIT = 200


@dataclass
class FilterOptions:
    keys: list[str] = field(default_factory=list)
    cols: list[str] = field(default_factory=list)
    path: str = ""
    grep: str = ""
    head: int | None = None
    tail: int | None = None
    limit: int | None = None
    no_ai: bool = False

    @property
    def active(self) -> bool:
        return bool(
            self.keys or self.cols or self.path or self.grep
            or self.head is not None or self.tail is not None
            or self.limit is not None or self.no_ai
        )


def filter_options_from_namespace(arguments: Any) -> FilterOptions:
    keys = _split_csv(getattr(arguments, "keys", None) or getattr(arguments, "filter_keys", None))
    cols = _split_csv(getattr(arguments, "cols", None) or getattr(arguments, "columns", None))
    return FilterOptions(
        keys=keys,
        cols=cols,
        path=str(getattr(arguments, "path", "") or getattr(arguments, "filter_path", "") or "").strip(),
        grep=str(getattr(arguments, "grep", "") or "").strip(),
        head=_positive_int(getattr(arguments, "head", None)),
        tail=_positive_int(getattr(arguments, "tail", None)),
        limit=_positive_int(getattr(arguments, "limit", None) or getattr(arguments, "filter_limit", None)),
        no_ai=bool(getattr(arguments, "no_ai", False)),
    )


def _split_csv(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        parts: list[str] = []
        for item in value:
            parts.extend(_split_csv(item))
        return [part for part in parts if part]
    text = str(value).strip()
    if not text:
        return []
    return [part.strip() for part in re.split(r"[,|\s]+", text) if part.strip()]


def _positive_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _question_wants_schema(question: str) -> bool:
    query = (question or "").casefold()
    return any(phrase in query for phrase in (
        "what keys", "which keys", "list keys", "key names",
        "what columns", "which columns", "list columns", "column names",
        "schema", "structure", "fields", "headers",
    ))


def _infer_grep(question: str) -> str:
    query = (question or "").strip()
    if not query:
        return ""
    match = re.search(
        r"(?i)\b(?:grep|filter(?: for)?|matching|containing)\s+[\"']([^\"'\n]{1,80})[\"']",
        query,
    )
    if match:
        return match.group(1).strip()
    match = re.search(
        r"(?i)\b(?:grep|filter(?: for)?|matching|containing)\s+(\S{2,80})",
        query,
    )
    if match:
        token = match.group(1).strip(".,;:!?")
        if token.casefold() not in {"the", "a", "an", "for", "lines", "rows"}:
            return token
    match = re.search(r"(?i)\blines?\s+(?:with|containing)\s+[\"']?([^\"'\n]{2,80})[\"']?", query)
    if match:
        return match.group(1).strip()
    return ""


def _json_path(data: Any, path: str) -> Any:
    current = data
    for part in path.replace("[", ".").replace("]", "").split("."):
        if not part:
            continue
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            elif part.isdigit() and part in {str(key) for key in current}:
                current = current[part]
            else:
                return None
        elif isinstance(current, list):
            if not part.isdigit():
                return None
            index = int(part)
            if index < 0 or index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current


def _project_mapping(row: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    if not keys:
        return row
    wanted = {key.casefold(): key for key in keys}
    projected: dict[str, Any] = {}
    for key, value in row.items():
        if str(key).casefold() in wanted:
            projected[str(key)] = value
    return projected


def _schema_for_json(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        keys = []
        for key, value in list(data.items())[:80]:
            keys.append({"key": str(key), "type": type(value).__name__})
        return {"kind": "object", "key_count": len(data), "keys": keys}
    if isinstance(data, list):
        sample = data[0] if data else None
        item_keys: list[str] = []
        if isinstance(sample, dict):
            item_keys = [str(key) for key in list(sample.keys())[:80]]
        return {
            "kind": "array",
            "length": len(data),
            "item_type": type(sample).__name__ if sample is not None else "empty",
            "item_keys": item_keys,
        }
    return {"kind": type(data).__name__, "preview": str(data)[:200]}


def _format_schema_answer(facts: dict[str, Any]) -> str:
    schema = facts.get("schema") or {}
    kind = facts.get("source_type") or schema.get("kind") or "unknown"
    lines = [f"Ingest type: {kind}"]
    if schema.get("kind") == "object":
        lines.append(f"Top-level keys ({schema.get('key_count', 0)}):")
        for item in schema.get("keys") or []:
            lines.append(f"- {item.get('key')}: {item.get('type')}")
    elif schema.get("kind") == "array":
        lines.append(f"Array length: {schema.get('length', 0)}")
        lines.append(f"Item type: {schema.get('item_type')}")
        if schema.get("item_keys"):
            lines.append("Item keys: " + ", ".join(schema["item_keys"]))
    elif facts.get("columns"):
        lines.append("Columns: " + ", ".join(str(col) for col in facts["columns"]))
        if facts.get("row_count") is not None:
            lines.append(f"Rows: {facts['row_count']}")
    if facts.get("filter"):
        lines.append(f"Filter: {facts['filter']}")
    return "\n".join(lines)


def _slice_rows(rows: list[Any], opts: FilterOptions) -> list[Any]:
    selected = list(rows)
    if opts.head is not None:
        selected = selected[: opts.head]
    if opts.tail is not None and opts.head is None:
        selected = selected[-opts.tail :]
    elif opts.tail is not None and opts.head is not None:
        # head already applied; ignore conflicting tail unless head unused
        pass
    limit = opts.limit or FILTER_ROW_LIMIT
    if len(selected) > limit:
        selected = selected[:limit]
    return selected


def _filter_text_lines(text: str, question: str, opts: FilterOptions) -> tuple[str, dict[str, Any]]:
    lines = text.splitlines()
    original = len(lines)
    needle = opts.grep or _infer_grep(question)
    matched: list[str] = []
    if needle:
        pattern = re.compile(re.escape(needle), re.I)
        matched = [line for line in lines if pattern.search(line)]
        working = matched
        mode = f"grep:{needle}"
    else:
        working = lines
        mode = "prune"
    if opts.head is not None:
        working = working[: opts.head]
        mode += f"+head:{opts.head}"
    if opts.tail is not None and opts.head is None:
        working = working[-opts.tail :]
        mode += f"+tail:{opts.tail}"
    limit = opts.limit or FILTER_TEXT_LINE_LIMIT
    truncated = len(working) > limit
    working = working[:limit]
    if not needle and not opts.active:
        compact, meta = prune_text(text, question, 24_000)
        meta = dict(meta)
        meta["filter"] = "auto-prune"
        return compact, meta
    body = "\n".join(working)
    meta = {
        "original_lines": original,
        "kept_lines": len(working),
        "matched_lines": len(matched) if needle else len(working),
        "truncated": truncated,
        "filter": mode,
        "duplicates_removed": 0,
        "original_chars": len(text),
        "kept_chars": len(body),
    }
    return body, meta


def apply_pipe_filter(
    evidence: dict[str, Any] | None,
    question: str,
    opts: FilterOptions | None = None,
) -> dict[str, Any] | None:
    """Project piped evidence. Mutates a shallow copy; returns None unchanged if no evidence."""

    if not evidence:
        return evidence
    options = opts or FilterOptions()
    result = copy.deepcopy(evidence)
    block = ((result.get("result") or {}).get("stdout") or {})
    kind = str(block.get("type") or "text")
    wants_schema = _question_wants_schema(question)
    filter_note: dict[str, Any] = {"applied": False, "source_type": kind}

    if kind == "json":
        data = block.get("data")
        if options.path:
            data = _json_path(data, options.path)
            filter_note["path"] = options.path
        if isinstance(data, dict) and options.keys:
            data = _project_mapping(data, options.keys)
            filter_note["keys"] = options.keys
        if isinstance(data, list):
            if options.keys:
                data = [
                    _project_mapping(row, options.keys) if isinstance(row, dict) else row
                    for row in data
                ]
                filter_note["keys"] = options.keys
            before = len(data)
            data = _slice_rows(data, options)
            filter_note["rows_before"] = before
            filter_note["rows_after"] = len(data)
        schema = _schema_for_json(block.get("data") if options.path or options.keys else data)
        if wants_schema and not options.keys and not options.path:
            result["facts"] = {
                "kind": "json_schema",
                "source_type": "json",
                "schema": _schema_for_json(block.get("data")),
                "method": "deterministic-ingest-filter",
            }
            filter_note["applied"] = True
            filter_note["mode"] = "schema"
        else:
            result["result"]["stdout"] = {
                "type": "json",
                "data": data,
                "filtered": True,
            }
            if wants_schema:
                result["facts"] = {
                    "kind": "json_schema",
                    "source_type": "json",
                    "schema": schema,
                    "filter": filter_note,
                    "method": "deterministic-ingest-filter",
                }
            elif options.keys or options.path or options.limit or options.head:
                result["facts"] = {
                    "kind": "filtered_projection",
                    "source_type": "json",
                    "preview": data if not isinstance(data, (dict, list)) else _bounded_preview(data),
                    "filter": filter_note,
                    "method": "deterministic-ingest-filter",
                }
            filter_note["applied"] = True
            filter_note["mode"] = "project"

    elif kind == "jsonl":
        rows = list(block.get("rows") or [])
        if options.keys:
            rows = [
                _project_mapping(row, options.keys) if isinstance(row, dict) else row
                for row in rows
            ]
            filter_note["keys"] = options.keys
        if options.grep:
            pattern = re.compile(re.escape(options.grep), re.I)
            rows = [row for row in rows if pattern.search(json.dumps(row, ensure_ascii=False))]
            filter_note["grep"] = options.grep
        before = len(rows)
        rows = _slice_rows(rows, options)
        filter_note.update({"rows_before": before, "rows_after": len(rows), "applied": True})
        sample_keys: list[str] = []
        for row in rows:
            if isinstance(row, dict):
                sample_keys = [str(key) for key in row.keys()]
                break
        result["result"]["stdout"] = {
            "type": "jsonl",
            "rows": rows,
            "row_count": len(rows),
            "filtered": True,
        }
        if wants_schema:
            result["facts"] = {
                "kind": "json_schema",
                "source_type": "jsonl",
                "schema": {"kind": "array", "length": before, "item_keys": sample_keys,
                           "item_type": "object" if sample_keys else "unknown"},
                "method": "deterministic-ingest-filter",
            }
        else:
            result["facts"] = {
                "kind": "filtered_projection",
                "source_type": "jsonl",
                "row_count": len(rows),
                "preview": rows[:12],
                "filter": filter_note,
                "method": "deterministic-ingest-filter",
            }

    elif kind == "table":
        columns = [str(col) for col in (block.get("columns") or [])]
        rows = [list(row) for row in (block.get("rows") or [])]
        selected_cols = options.cols or options.keys
        indexes = list(range(len(columns)))
        if selected_cols:
            wanted = {name.casefold() for name in selected_cols}
            indexes = [index for index, name in enumerate(columns) if name.casefold() in wanted]
            if not indexes:
                # keep all if no match — still report
                indexes = list(range(len(columns)))
            else:
                columns = [columns[index] for index in indexes]
                rows = [[row[index] for index in indexes if index < len(row)] for row in rows]
            filter_note["cols"] = selected_cols
        if options.grep:
            pattern = re.compile(re.escape(options.grep), re.I)
            rows = [row for row in rows if any(pattern.search(str(cell)) for cell in row)]
            filter_note["grep"] = options.grep
        before = len(rows)
        rows = _slice_rows(rows, options)
        filter_note.update({"rows_before": before, "rows_after": len(rows), "applied": True})
        result["result"]["stdout"] = {
            "type": "table",
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "filtered": True,
        }
        if wants_schema and not selected_cols and not options.grep:
            result["facts"] = {
                "kind": "table_schema",
                "source_type": "table",
                "columns": [str(col) for col in (block.get("columns") or [])],
                "row_count": int(block.get("row_count") or before),
                "method": "deterministic-ingest-filter",
            }
        elif selected_cols or options.grep or options.head or options.limit or options.tail:
            preview_rows = [dict(zip(columns, row)) for row in rows[:12]]
            result["facts"] = {
                "kind": "filtered_projection",
                "source_type": "table",
                "columns": columns,
                "row_count": len(rows),
                "preview": preview_rows,
                "filter": filter_note,
                "method": "deterministic-ingest-filter",
            }

    else:
        text = str(block.get("text") or "")
        body, meta = _filter_text_lines(text, question, options)
        filter_note.update(meta)
        filter_note["applied"] = True
        result["result"]["stdout"] = {
            "type": "text",
            "text": body,
            "line_count": len(body.splitlines()),
            "filtered": True,
        }
        # Preserve companion facts (ifconfig/dns/…) unless the user asked for an explicit text filter.
        if options.grep or options.head or options.tail or options.limit or _infer_grep(question):
            result["facts"] = {
                "kind": "filtered_projection",
                "source_type": "text",
                "preview": body[:4_000],
                "filter": filter_note,
                "matched_lines": meta.get("matched_lines"),
                "method": "deterministic-ingest-filter",
            }
        else:
            # Still prune the stdout text for the model path; keep extract_facts.
            pass

    result["ingest_filter"] = filter_note
    return result


def _bounded_preview(data: Any) -> Any:
    if isinstance(data, dict):
        return {str(key): data[key] for key in list(data)[:40]}
    if isinstance(data, list):
        return data[:20]
    return data


def exact_filter_answer(question: str, evidence: dict[str, Any] | None) -> str | None:
    """Deterministic answers for ingest-filter facts (schema / small projections)."""

    if not evidence:
        return None
    facts = evidence.get("facts")
    if not isinstance(facts, dict):
        return None
    kind = facts.get("kind")
    query = (question or "").casefold()
    if kind in {"json_schema", "table_schema"}:
        if _question_wants_schema(question) or "schema" in query or "column" in query or "key" in query:
            return _format_schema_answer(facts)
        if facts.get("kind") == "table_schema" and facts.get("columns"):
            return _format_schema_answer(facts)
    if kind == "filtered_projection":
        # Skip model for tiny explicit projections / grep hits when user asked for filter-like work.
        filter_meta = facts.get("filter") or {}
        preview = facts.get("preview")
        matched = facts.get("matched_lines")
        explicit = bool(filter_meta.get("keys") or filter_meta.get("cols") or filter_meta.get("path")
                        or filter_meta.get("grep") or str(filter_meta.get("filter", "")).startswith("grep"))
        if not explicit and not _infer_grep(question) and not _question_wants_schema(question):
            return None
        lines = [f"Ingest type: {facts.get('source_type', 'unknown')} (filtered)"]
        if matched is not None:
            lines.append(f"Matched lines: {matched}")
        if facts.get("row_count") is not None:
            lines.append(f"Rows: {facts['row_count']}")
        if facts.get("columns"):
            lines.append("Columns: " + ", ".join(str(col) for col in facts["columns"]))
        if isinstance(preview, str):
            body = preview.strip()
            if len(body) > 6_000:
                body = body[:3_000] + "\n[... truncated ...]\n" + body[-2_000:]
            lines.append("")
            lines.append(body or "(no matching lines)")
        elif preview is not None:
            lines.append("")
            lines.append(json.dumps(preview, ensure_ascii=False, indent=2, default=str)[:8_000])
        return "\n".join(lines)
    return None


def render_filter_only(evidence: dict[str, Any], question: str) -> str:
    """Human-readable --no-ai output from filtered evidence."""

    native = exact_filter_answer(question, evidence)
    if native:
        return native
    block = ((evidence.get("result") or {}).get("stdout") or {})
    kind = block.get("type")
    if kind == "json":
        return json.dumps(block.get("data"), ensure_ascii=False, indent=2, default=str)[:12_000]
    if kind == "jsonl":
        rows = block.get("rows") or []
        return "\n".join(json.dumps(row, ensure_ascii=False, default=str) for row in rows[:FILTER_ROW_LIMIT])
    if kind == "table":
        columns = block.get("columns") or []
        rows = block.get("rows") or []
        lines = ["\t".join(str(col) for col in columns)]
        for row in rows[:FILTER_ROW_LIMIT]:
            lines.append("\t".join(str(cell) for cell in row))
        return "\n".join(lines)
    return str(block.get("text") or "")
