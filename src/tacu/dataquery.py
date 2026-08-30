"""Natural-language questions over a loaded dataset.

The model never reads the data. It reads a compact schema briefing, writes one
SQLite SELECT, sees a small result, and decides whether that answers the
question — looping until it can answer or the budget runs out.

Every statement the model writes is validated by `dataset.guard_sql` and run on a
read-only connection, so a wrong or hostile query can fail but never mutate.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence
from pathlib import Path

from .core import TacuError
from .dataset import (
    DatasetInfo, DatasetProfile, format_table, guard_sql, profile_dataset, run_query,
)
from .providers import ModelProvider
from .wsfilters import CORE_FILTERS, lookup_filters, wants_filter_help

MAX_STEPS = 5
# Rows handed back to the model per query. Enough to reason over, small enough
# that a runaway SELECT * cannot flood the context window.
MODEL_ROW_LIMIT = 30
MODEL_RESULT_CHARS = 2_000
MAX_SQL_FAILURES = 3
ACTION_SCHEMA = "tacu.dataset-action/v1"


@dataclass
class QueryStep:
    """One statement the model asked for, and what came back."""

    sql: str
    why: str = ""
    columns: list[str] = field(default_factory=list)
    rows: list[tuple[Any, ...]] = field(default_factory=list)
    truncated: bool = False
    error: str = ""
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class QueryOutcome:
    """Result of a full natural-language question."""

    question: str
    dataset: str
    answer: str
    steps: list[QueryStep] = field(default_factory=list)
    stopped_reason: str = ""

    @property
    def successful_steps(self) -> list[QueryStep]:
        return [step for step in self.steps if step.ok]

    def transcript(self) -> str:
        """Plain-text record of what ran, for evidence and `ti evidence`."""

        lines = [f"question: {self.question}", f"dataset: {self.dataset}", ""]
        for index, step in enumerate(self.steps, 1):
            lines.append(f"[{index}] {step.sql}")
            if step.why:
                lines.append(f"    why: {step.why}")
            if step.error:
                lines.append(f"    error: {step.error}")
            else:
                lines.append(f"    {len(step.rows)} row(s) in {step.duration_ms}ms")
                if step.rows:
                    lines.append(_indent(format_table(step.columns, step.rows[:MODEL_ROW_LIMIT],
                                                      color=False)))
            lines.append("")
        if self.stopped_reason:
            lines.append(f"stopped: {self.stopped_reason}")
        lines.append("answer:")
        lines.append(self.answer)
        return "\n".join(lines)


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def briefing(profile: DatasetProfile, question: str = "") -> str:
    """Describe the table compactly enough to fit in a small context window.

    Distinct counts matter more than sample values here: they tell the model
    which columns are worth grouping by and which are effectively unique.
    """

    info = profile.info
    lines = [
        f'Table "data" holds {info.row_count:,} rows loaded from {info.name}.',
        "Columns (name, type, distinct values, examples):",
    ]
    json_columns: list[str] = []
    for column in profile.columns:
        examples = ", ".join(value[:24] for value in column.samples[:3])
        nulls = info.row_count - column.non_null
        note = f", {nulls:,} empty" if nulls else ""
        # A renamed column keeps its original key, which the question may use.
        origin = ""
        if column.source_name and column.source_name != column.name:
            origin = f' (from "{column.source_name}")'
        if _holds_json(column.samples):
            json_columns.append(column.name)
            note += ", JSON text"
        lines.append(
            f'  "{column.name}"{origin} {column.affinity}, {column.distinct:,} distinct{note}'
            f"{f' — e.g. {examples}' if examples else ''}"
        )
    present = {column.name for column in profile.columns}
    if "src_name" in present or "dst_name" in present:
        lines.append(
            "src_name and dst_name are hostnames learned from DNS answers (including CNAME), "
            "TLS SNI, and HTTP Host inside this capture — not live DNS. To see all traffic "
            "with a website after the lookup (TCP to a WAF or CDN IP), filter dst_name or "
            "src_name (for example dst_name LIKE '%example.com%'), not only info. sni and "
            "http_host are the name seen on that packet itself."
        )
    if "src_port" in present or "dst_port" in present:
        extra = [Path(info.source_path)] if info.source_path else []
        lines.extend(_pcap_ask_notes(question, extra_roots=extra))
    if "req_headers" in present or "form" in present:
        lines.extend(_burp_ask_notes())
    if json_columns:
        names = ", ".join(f'"{name}"' for name in json_columns)
        lines.append(
            f"{names} hold JSON. Read inside them with json_extract(column, '$.key'), "
            "and expand arrays with json_each(column)."
        )
    return "\n".join(lines)


def _pcap_ask_notes(question: str, *, extra_roots: Sequence[Path] | None = None) -> list[str]:
    """How to list packets, and Wireshark display-filter names the model may quote."""

    lines = [
        "When listing packet rows, SELECT packet, time, src, dst, src_name, dst_name, "
        "protocol, src_port, dst_port, info — not SELECT * — unless other columns are required.",
    ]
    if not wants_filter_help(question):
        return lines
    lines.append(
        "Wireshark display-filter field names (prefer these over remembered names; paste in Wireshark):"
    )
    lines.extend(f"  {name} — {hint}" for name, hint in CORE_FILTERS)
    hits = lookup_filters(question, extra_roots=extra_roots)
    if hits:
        lines.append(
            "Catalog matches for this question (utils/wireshark_filters.csv is authoritative):"
        )
        for item in hits:
            label = item.field_name or item.description
            extra = f" — {label}" if label and label != item.filter_string else ""
            lines.append(f"  {item.filter_string}{extra}")
    lines.append(
        "If the answer includes a Wireshark display filter, use only field names from this "
        "briefing. Combine with ==, contains, and &&. Example: "
        'dns.qry.name contains "example.com" || tls.handshake.extensions_server_name == "example.com".'
    )
    return lines


def _burp_ask_notes() -> list[str]:
    return [
        "This is Burp HTTP history. request and response were base64-decoded on load.",
        "host is the request Host; location is the HTTP redirect target (301/302). "
        "Answer only from this table — do not reuse hosts from earlier questions.",
        "form holds URL-decoded POST fields with ASP.NET viewstate stripped; cookie, "
        "authorization, and juicy are extracted from the decoded traffic. "
        "Cookie values stay in cookie; juicy is not the raw Cookie header.",
        "When listing items, SELECT item, time, method, url, status, host, location, form, "
        "juicy — not SELECT * — unless a header or body is required. item is 1-based "
        "export order (Burp Save items); burp_id is the id from the dump when present.",
        "Logins and credentials live in form (field names such as tbUsername, password, "
        "user). Search form and juicy, not only req_body.",
    ]


def _holds_json(samples: Sequence[str]) -> bool:
    """Columns that kept nested structure as text, so the model can index into them."""

    seen = [value.strip() for value in samples if value and value.strip()]
    if not seen:
        return False
    return all(value[0] in "[{" and value[-1] in "]}" for value in seen)


_SYSTEM_PROMPT = f"""You answer questions about a SQLite table by writing queries.

Reply with ONE JSON object and nothing else. Two forms are allowed:
{{"schema":"{ACTION_SCHEMA}","action":"sql","sql":"SELECT ...","why":"what this checks"}}
{{"schema":"{ACTION_SCHEMA}","action":"answer","answer":"the answer in plain sentences"}}

Rules:
- The table is always named data. Use only the column names given to you.
- SELECT only. No INSERT, UPDATE, DELETE, DROP, ATTACH, PRAGMA or semicolons.
- Prefer aggregates (COUNT, SUM, AVG, MIN, MAX, GROUP BY) over selecting raw rows.
- Always add a LIMIT when you are not aggregating.
- Use "sql" to gather facts. When the results are enough, use "answer".
- Round averages with ROUND(x, 1) so results stay readable.
- Answer with the actual numbers you saw. Never invent a value you did not query.
- If a query failed, read the error and write a corrected query.
- If the briefing lists Wireshark display-filter fields, you may include a pasteable filter in the answer. Use only those field names.
- Use only values returned by your SQL. Do not reuse hosts or findings from earlier questions."""


def _user_prompt(question: str, schema_text: str) -> str:
    return (
        f"{schema_text}\n\n"
        f"Question: {question}\n\n"
        "Write the first query, or answer if no query is needed. JSON only."
    )


def _action_from_text(text: str) -> dict[str, Any]:
    """Pull one JSON action out of a small model's chatty reply."""

    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    candidates = [cleaned]
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start >= 0 and end > start:
        candidates.append(cleaned[start:end + 1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    # Last resort: the model wrote bare SQL instead of JSON.
    match = re.search(r"\b(?:SELECT|WITH)\b.+", cleaned, re.IGNORECASE | re.S)
    if match:
        return {"action": "sql", "sql": match.group(0).strip().rstrip(";")}
    raise TacuError("The model did not return a usable JSON action.")


def _render_for_model(step: QueryStep, info: DatasetInfo) -> str:
    if step.error:
        return f"That query failed: {step.error}\nWrite a corrected query, or answer if you can."
    if not step.rows:
        return "That query returned no rows. Try a different query, or answer that nothing matched."
    table = format_table(step.columns, step.rows[:MODEL_ROW_LIMIT], width=28, color=False)
    if len(table) > MODEL_RESULT_CHARS:
        table = table[:MODEL_RESULT_CHARS] + "\n[... truncated ...]"
    note = f"{len(step.rows)} row(s)"
    if step.truncated:
        note += f" (stopped at {MODEL_ROW_LIMIT}; there may be more)"
    return f"Result — {note}:\n{table}\n\nAnswer now if this is enough, otherwise query again."


def answer_question(
    info: DatasetInfo,
    question: str,
    *,
    client: ModelProvider,
    chat: Callable[[list[dict[str, str]]], str],
    max_steps: int = MAX_STEPS,
    on_step: Callable[[QueryStep], None] | None = None,
    home: Any = None,
) -> QueryOutcome:
    """Run the question-to-SQL loop until the model can answer.

    `chat` takes the message list and returns the model's raw text, so the caller
    controls streaming, progress display, and history.
    """

    text = (question or "").strip()
    if not text:
        raise TacuError('Ask something. Example: ti data ask sales "which region sold most?"')

    profile = profile_dataset(info, home=home)
    schema_text = briefing(profile, text)
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": _user_prompt(text, schema_text)},
    ]

    outcome = QueryOutcome(question=text, dataset=info.name, answer="")
    failures = 0
    attempted: set[str] = set()
    budget = max(1, int(max_steps))

    for remaining in range(budget, 0, -1):
        try:
            reply = chat(messages)
        except TacuError:
            raise
        messages.append({"role": "assistant", "content": reply})

        try:
            action = _action_from_text(reply)
        except TacuError:
            failures += 1
            if failures >= MAX_SQL_FAILURES:
                outcome.stopped_reason = "the model never produced a usable action"
                break
            messages.append({
                "role": "user",
                "content": 'Reply with one JSON object only, e.g. {"action":"answer","answer":"..."}.',
            })
            continue

        kind = str(action.get("action") or "").strip().casefold()
        if kind == "answer" or (not kind and action.get("answer")):
            outcome.answer = str(action.get("answer") or "").strip()
            if outcome.answer:
                return outcome
            messages.append({"role": "user", "content": "The answer was empty. Answer in plain sentences."})
            continue

        statement = str(action.get("sql") or "").strip()
        if not statement:
            messages.append({"role": "user", "content": 'Include a "sql" string, or answer.'})
            continue

        normalised = " ".join(statement.split()).casefold()
        if normalised in attempted:
            outcome.stopped_reason = "the model repeated the same query"
            messages.append({
                "role": "user",
                "content": "You already ran that exact query. Answer from the results you have.",
            })
            attempted.add(normalised)
            continue
        attempted.add(normalised)

        step = QueryStep(sql=statement, why=str(action.get("why") or "").strip())
        started = time.monotonic()
        try:
            guard_sql(statement)
            columns, rows, truncated = run_query(
                info, statement, limit=MODEL_ROW_LIMIT, home=home)
            step.columns, step.rows, step.truncated = columns, rows, truncated
        except TacuError as error:
            step.error = str(error)
            failures += 1
        step.duration_ms = int((time.monotonic() - started) * 1000)
        outcome.steps.append(step)
        if on_step:
            on_step(step)

        if failures >= MAX_SQL_FAILURES and not outcome.successful_steps:
            outcome.stopped_reason = f"{failures} queries failed in a row"
            break

        messages.append({"role": "user", "content": _render_for_model(step, info)})
        if remaining == 1:
            outcome.stopped_reason = outcome.stopped_reason or f"reached the {budget}-step budget"

    if not outcome.answer:
        outcome.answer = _forced_answer(messages, chat, outcome)
    return outcome


def _forced_answer(messages: list[dict[str, str]], chat: Callable[[list[dict[str, str]]], str],
                   outcome: QueryOutcome) -> str:
    """Ask once for prose when the loop ended without an answer."""

    if not outcome.successful_steps:
        return ("I could not gather the facts needed to answer that. "
                "Check the column names with ti data show, or ask a narrower question.")
    messages.append({
        "role": "user",
        "content": ("Stop querying. Using only the results above, answer the question in plain "
                    "sentences with the actual numbers. Reply with prose, not JSON."),
    })
    try:
        reply = chat(messages).strip()
    except TacuError:
        return "I gathered results but could not summarise them. The queries and rows are shown above."
    try:
        action = _action_from_text(reply)
        if action.get("answer"):
            return str(action["answer"]).strip()
    except TacuError:
        pass
    return reply or "The queries above ran, but no summary was produced."


def first_sql_only(
    info: DatasetInfo,
    question: str,
    *,
    chat: Callable[[list[dict[str, str]]], str],
    home: Any = None,
) -> str:
    """Return the SQL the model would run first, without executing it."""

    profile = profile_dataset(info, home=home)
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": _user_prompt(question.strip(), briefing(profile, question.strip()))},
    ]
    action = _action_from_text(chat(messages))
    statement = str(action.get("sql") or "").strip()
    if not statement:
        raise TacuError("The model answered without writing a query; run without --sql-only to see it.")
    return guard_sql(statement)
