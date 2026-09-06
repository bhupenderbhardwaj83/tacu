"""Capability-first harness spine for small local models.

Flow (ti auto / ti do after execution):
  intent → tool family (read/write/edit/search/…) → native hit? → else shortlist
  with Claude/Codex-style when/avoid guidance → model picks specialized tool
  → validate → policy → execute → critique → replan with file evidence
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .core import TacuError
from .routing import (
    CAPABILITIES, Capability, connection_state_from_intent,
    extract_file_delete, extract_file_write, file_edit_target, intent_content_needles,
    intent_is_application_query, intent_is_delete, intent_is_file_edit,
    intent_is_site_create, intent_tool_family, TOOL_FAMILIES,
    intent_host_domain, intent_wants_host_mutate, intent_writes_or_serves, native_steps_for_intent, prefers_coding_write,
    score_capability, script_body_for_intent, workspace_run_from_intent,
    SHORTLIST_LIMIT_PLANNER, SHORTLIST_MIN_SCORE, _CODE_SUFFIXES, _port_from_intent,
)

CAPABILITY_PLAN_SCHEMA = "tacu.capability-plan/v1"
SHELL_PLAN_SCHEMA = "tacu.command-plan/v1"

# Stable failure codes — single critic vocabulary for mutations and host evidence.
WRONG_OPERATION = "wrong_operation"
DELETE_MISSING = "delete_missing"
WRITE_MISSING = "write_missing"
WRITE_WRONG_NAME = "write_wrong_name"
WRITE_CONTENT_MISMATCH = "write_content_mismatch"
EDIT_MISSING = "edit_missing"
EDIT_CONTENT_MISMATCH = "edit_content_mismatch"
EDIT_DESTRUCTIVE = "edit_destructive"
SERVE_NOT_STARTED = "serve_not_started"
EXIT_NONZERO = "exit_nonzero"
NO_RESULTS = "no_results"
CONNECTIONS_WRONG_STATE = "connections_wrong_state"
MISSING_PUBLIC_IP = "missing_public_ip"
MISSING_IP = "missing_ip"
MISSING_HOSTNAME = "missing_hostname"
MISSING_INSTALL_DATE = "missing_install_date"


def _known_ops() -> set[tuple[str, str]]:
    return {(item.tool, item.operation) for item in CAPABILITIES}


def planner_shortlist(intent: str, *, limit: int = SHORTLIST_LIMIT_PLANNER,
                      include_host_mutate: bool = False) -> list[dict[str, Any]]:
    """Top capabilities for the model — same min score as native hits, wider limit.

    When nothing clears the confidence bar, soft-expand to the next-best cards so the
    model still sees tools (timing gap fix). Host mutations only when allowed.
    """

    ranked = sorted(
        ((score_capability(intent, item), item) for item in CAPABILITIES),
        key=lambda pair: pair[0],
        reverse=True,
    )
    cards: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(cap: Capability, score: int) -> None:
        key = (cap.tool, cap.operation)
        if key in seen:
            return
        if cap.risk == "host_mutate" and not include_host_mutate:
            return
        seen.add(key)
        cards.append({
            "tool": cap.tool,
            "operation": cap.operation,
            "purpose": cap.purpose,
            "risk": cap.risk,
            "score": score,
        })

    # Pin the specialized family for this intent (Claude/Codex: one tool per job).
    family = intent_tool_family(intent)
    wanted = set(TOOL_FAMILIES.get(family, ()))
    if wanted:
        for cap in CAPABILITIES:
            if (cap.tool, cap.operation) in wanted:
                add(cap, max(SHORTLIST_MIN_SCORE + 15, score_capability(intent, cap) + 25))
    # Always surface mutation ops when the ask is create/serve/delete — model picks among them.
    if intent_is_delete(intent) or extract_file_delete(intent):
        for cap in CAPABILITIES:
            if cap.operation == "delete":
                add(cap, max(SHORTLIST_MIN_SCORE, score_capability(intent, cap)))
    if intent_writes_or_serves(intent) or extract_file_write(intent) or intent_is_file_edit(intent):
        for cap in CAPABILITIES:
            if cap.operation in {"write", "serve"} or cap.tool == "edit_file":
                add(cap, max(SHORTLIST_MIN_SCORE, score_capability(intent, cap)))
    if include_host_mutate and intent_wants_host_mutate(intent):
        for score, cap in ranked:
            if cap.risk == "host_mutate" and score >= 20:
                add(cap, max(SHORTLIST_MIN_SCORE, score))
    if workspace_run_from_intent(intent):
        for cap in CAPABILITIES:
            if cap.tool == "shell":
                add(cap, max(SHORTLIST_MIN_SCORE, score_capability(intent, cap)))
    for score, cap in ranked:
        if len(cards) >= limit:
            break
        if score < SHORTLIST_MIN_SCORE:
            continue
        add(cap, score)
    # Soft expand when the confidence bar yields nothing usable.
    if not cards:
        for score, cap in ranked:
            if len(cards) >= min(3, limit):
                break
            if score < 1:
                continue
            add(cap, score)
    return cards[:limit]


def _tool_input_keys(tool: str) -> list[str]:
    try:
        from .tools.registry import REGISTRY
        module = REGISTRY.get(tool)
        if not module:
            return ["operation"]
        props = (module.SPEC.input_schema or {}).get("properties") or {}
        return list(props.keys())
    except Exception:
        return ["operation"]


def _tool_required_keys(tool: str) -> list[str]:
    try:
        from .tools.registry import REGISTRY
        module = REGISTRY.get(tool)
        if not module:
            return []
        required = (module.SPEC.input_schema or {}).get("required") or []
        return [str(item) for item in required]
    except Exception:
        return []


def shortlist_prompt_block(intent: str, *, include_host_mutate: bool = False) -> str:
    cards = planner_shortlist(intent, include_host_mutate=include_host_mutate)
    family = intent_tool_family(intent)
    compact = []
    try:
        from .tools.registry import REGISTRY
    except Exception:
        REGISTRY = {}
    for card in cards:
        keys = _tool_input_keys(card["tool"])
        required = _tool_required_keys(card["tool"])
        module = REGISTRY.get(card["tool"]) if REGISTRY else None
        spec = getattr(module, "SPEC", None)
        item = {
            "tool": card["tool"],
            "operation": card["operation"],
            "purpose": card["purpose"],
            "risk": card["risk"],
            "score": card["score"],
            "inputs": keys[:12],
            "required": required,
        }
        if spec is not None:
            if spec.when_to_use:
                item["when"] = spec.when_to_use
            if spec.when_not:
                item["avoid"] = spec.when_not
        compact.append(item)
    return json.dumps({"family": family, "tools": compact}, separators=(",", ":"))


def capability_planner_prompt(intent: str, workspace: Path, max_steps: int, *,
                              failure_code: str | None = None,
                              include_host_mutate: bool = False,
                              critic_evidence: str | None = None) -> list[dict[str, str]]:
    shortlist = shortlist_prompt_block(intent, include_host_mutate=include_host_mutate)
    mutate_rule = (
        "- Host mutations (kill/start/stop/restart/install/upgrade/remove) require reviewed ti do; "
        "only pick them when they appear in the shortlist."
        if include_host_mutate else
        "- Do not pick kill/start/stop/restart/install/upgrade/remove — those need ti do."
    )
    system = f"""You are TACU's capability planner — same job as Claude Code / Codex tool use. Return ONLY one JSON object:
{{"schema":"{CAPABILITY_PLAN_SCHEMA}","summary":"short","steps":[{{"tool":"write_file","operation":"write","inputs":{{"path":"program.py","content":"a=int(input())\\nb=int(input())\\nprint(a+b)\\n"}},"purpose":"create python file"}}]}}
Rules:
- Produce 1 to {max_steps} steps from the shortlist. Prefer the highest-score card; the shortlist family is already ranked for this intent.
- Each shortlist card is a specialized tool (when/avoid). Pick that tool — do not improvise cat/echo/tee/find/rg.
- read_file: inspect one file. write_file: create or fully rewrite source. edit_file: surgical StrReplace (old_text from Current file/`text`; replace_all; edits[] for multi-hunk).
- search_code: grep contents. repo_map: glob/tree by name. filesystem.delete: remove. filesystem.write: notes/HTML only.
- shell: run python3/bash/node on a workspace script. Never bash -c, python -c, or shell as a CRUD substitute.
- Put arguments in inputs. Fill every required key. Do not copy this example's path or content.
- Workspace: {workspace}. Paths relative (program.py). Never OS-critical paths.
- New source file (.py/.sh/.js): write_file with a complete non-empty program. Never empty. Never note.txt unless they asked for a note.
- Edit existing file: MUST mutate with edit_file or write_file. Preserve every existing line unless asked to replace it. Do not duplicate blocks. Do not stop at read_file.
- If old_text is not unique: replace_all, unique context, or write_file the FULL updated file.
- If you cannot emit the schema, return {{"path":"script.sh","content":"complete file"}}.
- {mutate_rule}
- JSON only. Do not claim commands ran."""
    user = f"Shortlist: {shortlist}\nUser intent: {intent}"
    slots = extract_file_delete(intent) or extract_file_write(intent)
    if slots:
        user += f"\nExtracted slots: {json.dumps(slots, ensure_ascii=False, default=str)}"
        if isinstance(slots, dict) and not str(slots.get("content") or "").strip() and not extract_file_delete(intent):
            user += (
                "\nContent is missing: put a complete small program or file body in inputs.content. "
                "Do not write an empty file."
            )
    edit_path = file_edit_target(intent)
    if edit_path:
        target = workspace / edit_path
        try:
            if target.is_file():
                body = target.read_text(encoding="utf-8", errors="replace")[:8_000]
                user += (
                    f"\nCurrent file {edit_path}:\n{body}\n"
                    "Mutate this file with edit_file (old_text copied from this body) or write_file "
                    "with the FULL updated file. Keep every existing line unless the user asked to replace it. "
                    "Do not only read it."
                )
        except OSError:
            pass
    if critic_evidence:
        user += f"\nCritic evidence from the last attempt:\n{critic_evidence}"
    if failure_code:
        user += (
            f"\nPrevious attempt failed with code: {failure_code}. "
            "Pick a corrected capability step from the shortlist. "
            "For write_file, use a language-matching filename (.py for python) and non-empty complete source. "
            "For edit_missing / edit_content_mismatch / edit_destructive: write_file the FULL current file "
            "plus only the requested change. Never drop existing lines. Never duplicate whole blocks. "
            "read_file is not enough. Never note.txt unless the user asked for a note. JSON only."
        )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _strip_json_noise(text: str) -> str:
    cleaned = text.strip()
    fenced = re.search(r"```json\s*([\s\S]*?)```", cleaned, flags=re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def _without_trailing_commas(text: str) -> str:
    return re.sub(r",\s*([}\]])", r"\1", text)


def loads_json_value(text: str) -> Any:
    """Parse JSON from a model reply; tolerate fences, prose wrappers, trailing commas."""

    cleaned = _strip_json_noise(text)
    candidates = [cleaned, _without_trailing_commas(cleaned)]
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start >= 0 and end > start:
        snippet = cleaned[start:end + 1]
        candidates.extend([snippet, _without_trailing_commas(snippet)])
    astart, aend = cleaned.find("["), cleaned.rfind("]")
    if astart >= 0 and aend > astart and (start < 0 or astart < start):
        snippet = cleaned[astart:aend + 1]
        candidates.extend([snippet, _without_trailing_commas(snippet)])
    seen: set[str] = set()
    last_error: json.JSONDecodeError | None = None
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError as error:
            last_error = error
    raise TacuError("The model returned malformed capability-plan JSON.") from last_error


def _json_object(text: str) -> dict[str, Any]:
    value = loads_json_value(text)
    if isinstance(value, list):
        return {"steps": value}
    if not isinstance(value, dict):
        raise TacuError("The model returned an invalid capability plan.")
    if "steps" not in value and value.get("tool") and value.get("operation"):
        return {"steps": [value], "summary": str(value.get("purpose") or "")}
    path = value.get("path") or value.get("name")
    content = value.get("content")
    if "steps" not in value and isinstance(path, str) and path.strip() and isinstance(content, str) and content.strip():
        return {
            "summary": f"Create `{path}`",
            "steps": [{
                "tool": "write_file",
                "operation": "write",
                "inputs": {
                    "path": path,
                    "content": content,
                    "overwrite": True,
                    "create_parents": True,
                },
                "purpose": f"Create `{path}`",
            }],
        }
    return value


def parse_file_body(raw: str, *, default_name: str) -> dict[str, str] | None:
    """Extract a workspace path + file body from messy model output."""

    value: Any = None
    try:
        value = loads_json_value(raw)
    except TacuError:
        value = None
    if isinstance(value, list) and value:
        value = {"steps": value}
    if isinstance(value, dict):
        steps = value.get("steps")
        first = steps[0] if isinstance(steps, list) and steps and isinstance(steps[0], dict) else None
        blob = (first.get("inputs") if isinstance((first or {}).get("inputs"), dict) else first) or value
        path = str(blob.get("path") or blob.get("name") or default_name).strip() or default_name
        content = blob.get("content")
        if isinstance(content, str) and content.strip():
            return {"path": path, "content": content}
    fence = re.search(r"```(?!json)(\w+)?\n([\s\S]*?)```", raw, flags=re.IGNORECASE)
    if fence and fence.group(2).strip():
        return {"path": default_name, "content": fence.group(2)}
    return None


def file_write_body_prompt(intent: str, workspace: Path, name: str) -> list[dict[str, str]]:
    system = (
        "You write one workspace file for TACU. Return ONLY JSON: "
        '{"path":"file.name","content":"complete file body"}. '
        "path is relative to the workspace. content is the full runnable file. "
        "If Current file is provided, keep every existing line and apply only the requested change. "
        "No markdown, no shell argv, no empty content."
    )
    user = (
        f"Workspace: {workspace}\nFilename: {name}\nUser intent: {intent}\n"
        "Write the complete file body now."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def write_file_step_from_body(path: str, content: str, *, workspace: Path | None = None,
                              purpose: str | None = None) -> dict[str, Any]:
    return validate_capability_step({
        "tool": "write_file",
        "operation": "write",
        "inputs": {
            "path": path,
            "content": content,
            "overwrite": True,
            "create_parents": True,
        },
        "purpose": purpose or f"Create `{path}`",
    }, index=1, workspace=workspace)


def steps_look_like_capabilities(steps: list[Any]) -> bool:
    if not steps or not isinstance(steps[0], dict):
        return False
    first = steps[0]
    return bool(first.get("tool") and first.get("operation")) and not first.get("executable")


def steps_look_like_shell(steps: list[Any]) -> bool:
    if not steps or not isinstance(steps[0], dict):
        return False
    return bool(steps[0].get("executable"))


def _normalize_tool_path(path: str, *, workspace: Path | None, index: int, kind: str) -> str:
    """Keep in-workspace files relative; never accept OS-critical mutate targets.

    Absolute paths that sit inside the workspace are rewritten to a relative
    path so a local model copying the workspace directory still works.
    Paths outside the workspace are kept for the permission gate to prompt on.
    """

    raw = str(path or "").strip()
    if not raw or raw in {".", "./"}:
        raise TacuError(f"Capability step {index} needs a {kind} path.")
    candidate = Path(raw).expanduser()
    if workspace is None:
        if candidate.is_absolute() or ".." in candidate.parts:
            raise TacuError(f"Capability step {index} has an unsafe {kind} path.")
        return raw.replace("\\", "/")
    from .automation import os_critical_path

    root = workspace.expanduser().resolve(strict=False)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve(strict=False)
    if os_critical_path(resolved):
        raise TacuError("OS-critical paths cannot be created, edited, or deleted.")
    if resolved == root or root in resolved.parents:
        relative = resolved.relative_to(root)
        text = str(relative).replace("\\", "/")
        if not text or text == ".":
            raise TacuError(f"Capability step {index} needs a {kind} path.")
        return text
    return str(resolved)


def validate_capability_step(item: dict[str, Any], *, index: int,
                             workspace: Path | None = None) -> dict[str, Any]:
    """Validate one model capability step; return a native_steps-shaped dict."""

    tool = item.get("tool")
    operation = item.get("operation")
    purpose = item.get("purpose") or f"{tool}.{operation}"
    inputs = item.get("inputs") if isinstance(item.get("inputs"), dict) else {}
    if not isinstance(tool, str) or not isinstance(operation, str):
        raise TacuError(f"Capability step {index} needs tool and operation.")
    tool, operation = tool.strip(), operation.strip()
    if (tool, operation) not in _known_ops():
        raise TacuError(
            f"Capability step {index} is not in the TACU catalog: {tool}.{operation}."
        )
    cleaned = {key: value for key, value in inputs.items() if value is not None}
    if tool == "write_file" and not cleaned.get("path") and inputs.get("name"):
        cleaned["path"] = inputs["name"]
    allowed = set(_tool_input_keys(tool))
    if allowed:
        if "operation" in allowed:
            cleaned["operation"] = operation
        cleaned = {key: value for key, value in cleaned.items() if key in allowed}
        if "operation" in allowed:
            cleaned["operation"] = operation
    else:
        cleaned["operation"] = operation
    if tool == "write_file":
        cleaned["path"] = _normalize_tool_path(
            str(cleaned.get("path") or ""), workspace=workspace, index=index, kind="write_file",
        )
        cleaned.setdefault("overwrite", True)
        cleaned.setdefault("create_parents", True)
        if not isinstance(cleaned.get("content"), str) or not str(cleaned.get("content") or "").strip():
            raise TacuError(f"Capability step {index} write_file needs non-empty content.")
        if len(cleaned["content"]) > 100_000:
            raise TacuError(f"Capability step {index} content exceeds 100 KB.")
    if tool == "edit_file":
        cleaned["path"] = _normalize_tool_path(
            str(cleaned.get("path") or ""), workspace=workspace, index=index, kind="edit_file",
        )
        hunks = cleaned.get("edits")
        if isinstance(hunks, list) and hunks:
            cleaned["edits"] = hunks
        elif not str(cleaned.get("old_text") or "") or "new_text" not in cleaned:
            raise TacuError(f"Capability step {index} needs path plus old_text/new_text, or edits[].")
        cleaned.setdefault("expected_matches", 1)
    if tool == "search_code":
        query = str(cleaned.get("query") or "").strip()
        if not query:
            raise TacuError(f"Capability step {index} needs a search query.")
        cleaned["query"] = query
        cleaned.setdefault("path", ".")
    if tool == "read_file":
        cleaned["path"] = _normalize_tool_path(
            str(cleaned.get("path") or ""), workspace=workspace, index=index, kind="read_file",
        )
        if cleaned.get("offset") is not None:
            cleaned["start_line"] = cleaned["offset"]
        cleaned.setdefault("start_line", 1)
    if tool == "shell":
        executable = str(cleaned.get("executable") or "").strip()
        if not executable or any(character.isspace() for character in executable):
            raise TacuError(f"Capability step {index} shell needs an executable.")
        args = cleaned.get("args") or []
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise TacuError(f"Capability step {index} shell args must be strings.")
        lowered = [arg.casefold() for arg in args]
        name = Path(executable).name.casefold()
        if name in {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"} and any(
            arg in {"-c", "-lc", "/c"} for arg in lowered
        ):
            raise TacuError(f"Capability step {index} cannot use nested shell -c. Pass a script path as argv.")
        if name in {"python", "python3", "node", "ruby", "perl"} and any(arg in {"-c", "-e"} for arg in args):
            raise TacuError(f"Capability step {index} cannot use inline interpreter code.")
        cleaned["executable"] = executable
        cleaned["args"] = args
        cleaned.setdefault("cwd", ".")
        cleaned.setdefault("timeout", 120)
    if operation == "write" and tool == "filesystem":
        name = str(cleaned.get("name") or "")
        cleaned["name"] = _normalize_tool_path(name, workspace=workspace, index=index, kind="write")
        cleaned.setdefault("overwrite", True)
        if "content" not in cleaned:
            cleaned["content"] = ""
        if not isinstance(cleaned["content"], str):
            raise TacuError(f"Capability step {index} content must be a string.")
        if len(cleaned["content"]) > 100_000:
            raise TacuError(f"Capability step {index} content exceeds 100 KB.")
    if operation == "serve":
        cleaned.setdefault("port", 8000)
        cleaned.setdefault("open_browser", False)
    if operation == "delete":
        cleaned["name"] = _normalize_tool_path(
            str(cleaned.get("name") or ""), workspace=workspace, index=index, kind="delete",
        )
    # Coerce typed inputs early so small models' "10" / "true" still validate.
    try:
        from .tools.registry import REGISTRY
        from .tools.contracts import _coerce_input
        module = REGISTRY.get(tool)
        props = ((module.SPEC.input_schema or {}).get("properties") or {}) if module else {}
        for key, value in list(cleaned.items()):
            kind = (props.get(key) or {}).get("type")
            cleaned[key] = _coerce_input(kind, value)
    except Exception:
        pass
    return {
        "tool": tool,
        "operation": operation,
        "inputs": cleaned,
        "purpose": str(purpose).strip() or f"{tool}.{operation}",
    }


def parse_capability_plan(raw: str, *, limit: int, workspace: Path | None = None) -> list[dict[str, Any]]:
    payload = _json_object(raw)
    steps_payload = payload.get("steps")
    if not isinstance(steps_payload, list) or not steps_payload:
        raise TacuError("The model returned no capability steps.")
    if len(steps_payload) > limit:
        raise TacuError(f"The capability plan exceeded the {limit}-step limit.")
    if not steps_look_like_capabilities(steps_payload):
        raise TacuError("capability_shape_mismatch")
    return [validate_capability_step(item, index=index, workspace=workspace)
            for index, item in enumerate(steps_payload, 1) if isinstance(item, dict)]


def _step_data(item: dict[str, Any]) -> dict[str, Any]:
    return ((item.get("result") or {}).get("data")) or {}


def _result_tool(item: dict[str, Any]) -> str:
    result = item.get("result") or {}
    if isinstance(result.get("tool"), str) and result["tool"]:
        return result["tool"]
    data = _step_data(item)
    if data.get("containers") is not None or data.get("images") is not None or data.get("networks") is not None:
        return "docker"
    if data.get("models") is not None or data.get("operation") in {
            "running_models", "installed_models", "model_info", "pull", "rm", "stop"}:
        return "ollama"
    if data.get("is_repo") is not None or data.get("repositories") is not None or data.get("commits") is not None:
        return "git"
    command = item.get("command") or []
    if command:
        return str(command[0])
    return ""


def snapshot_edit_targets(intent: str, workspace: Path) -> dict[str, str]:
    """File bodies the critic compares after a mutation."""

    names: list[str] = []
    target = file_edit_target(intent)
    if target:
        names.append(target)
    spec = extract_file_write(intent)
    if spec and spec.get("name"):
        names.append(str(spec["name"]))
    bodies: dict[str, str] = {}
    root = workspace.expanduser().resolve(strict=False)
    for name in names:
        candidate = (root / name).resolve(strict=False)
        try:
            if candidate.is_file() and (candidate == root or root in candidate.parents):
                bodies[name] = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return bodies


def format_critic_evidence(intent: str, results: list[dict[str, Any]], workspace: Path | None) -> str:
    parts: list[str] = []
    if results:
        last = results[-1].get("result") or {}
        error = last.get("error") or {}
        if error:
            parts.append(f"Tool error {error.get('code')}: {error.get('message')}")
    path = file_edit_target(intent)
    if not path and results:
        data = _step_data(results[-1])
        raw_path = str(data.get("path") or data.get("name") or "")
        if raw_path:
            path = Path(raw_path).name
    if workspace and path:
        target = workspace / path
        try:
            if target.is_file():
                parts.append(f"File {path} now:\n{target.read_text(encoding='utf-8', errors='replace')[:8_000]}")
        except OSError:
            pass
    return "\n".join(parts).strip()


def _retention_ratio(before: str, after: str) -> float:
    original = {line.strip() for line in before.splitlines() if line.strip()}
    updated = {line.strip() for line in after.splitlines() if line.strip()}
    if not original:
        return 1.0
    return len(original & updated) / len(original)


def _file_text_after(intent: str, results: list[dict[str, Any]], workspace: Path | None) -> str | None:
    path = file_edit_target(intent)
    if not path and results:
        data = _step_data(results[-1])
        raw_path = str(data.get("path") or data.get("name") or "")
        path = Path(raw_path).name if raw_path else None
    if workspace and path:
        target = workspace / path
        try:
            if target.is_file():
                return target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    for item in reversed(results):
        data = _step_data(item)
        for key in ("text", "preview"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


def critique_goal(intent: str, results: list[dict[str, Any]], *,
                  workspace: Path | None = None,
                  before: dict[str, str] | None = None) -> str | None:
    """Return a stable failure code when the goal is unmet. None means the goal looks met."""

    if intent_is_delete(intent):
        if not results:
            return DELETE_MISSING
        if any(_step_data(item).get("bytes_written") is not None for item in results):
            return WRONG_OPERATION
        deletes = [
            item for item in results
            if _step_data(item).get("operation") == "delete" or _step_data(item).get("deleted")
        ]
        if not deletes:
            return DELETE_MISSING
        return None

    if intent_is_file_edit(intent):
        if not results:
            return EDIT_MISSING
        mutated = any(
            _step_data(item).get("bytes_written") is not None
            or _step_data(item).get("changed") is True
            or bool(_step_data(item).get("diff"))
            for item in results
        )
        if not mutated:
            return EDIT_MISSING
        after = _file_text_after(intent, results, workspace)
        path = file_edit_target(intent)
        if before and path and after is not None and path in before:
            if _retention_ratio(before[path], after) < 0.5:
                return EDIT_DESTRUCTIVE
        needles = intent_content_needles(intent)
        if needles and after is not None:
            haystack = after
            if not all(needle in haystack for needle in needles):
                return EDIT_CONTENT_MISMATCH

    spec = extract_file_write(intent)
    if not results:
        if spec:
            return WRITE_MISSING
        return NO_RESULTS
    for item in results:
        data = _step_data(item)
        if data.get("exit_code") not in (None, 0):
            return EXIT_NONZERO
        result = item.get("result") or {}
        if result.get("ok") is False:
            return EXIT_NONZERO

    if spec:
        writes = [item for item in results if _step_data(item).get("bytes_written") is not None]
        if not writes:
            return WRITE_MISSING
        data = _step_data(writes[0])
        path = Path(str(data.get("path") or data.get("name") or ""))
        written = int(data.get("bytes_written") or 0)
        coding = prefers_coding_write(intent, str(spec["name"]))
        if path.name and path.name != spec["name"]:
            if not spec.get("name_inferred"):
                return WRITE_WRONG_NAME
            if spec.get("content_supplied") and not coding:
                return WRITE_WRONG_NAME
        if coding and path.suffix.casefold() and path.suffix.casefold() not in _CODE_SUFFIXES:
            return WRITE_WRONG_NAME
        expected = len(str(spec.get("content") or "").encode())
        if spec.get("content_supplied") and expected and written != expected:
            return WRITE_CONTENT_MISMATCH
        if coding and written < 16:
            return WRITE_CONTENT_MISMATCH
        if not spec.get("content_supplied") and written <= 0:
            return WRITE_CONTENT_MISMATCH

    wants_serve = intent_is_site_create(intent) and any(
        phrase in intent.casefold()
        for phrase in ("http.server", "chrome", "browser", "local server", "serve", "load it")
    )
    if wants_serve and not any(_step_data(item).get("url") and _step_data(item).get("pid") for item in results):
        return SERVE_NOT_STARTED

    # Host-evidence checks (same vocabulary as mutation codes).
    domain = intent_host_domain(intent)
    if domain:
        used = {_result_tool(item) for item in results}
        # "is docker installed" names Docker Desktop, and the application tool is
        # the right answer to it. Demanding the docker catalog here sent a correct
        # plan back for replanning twice before giving the same answer anyway.
        answered_as_application = "application" in used and intent_is_application_query(intent)
        if domain not in used and not answered_as_application:
            return WRONG_OPERATION
    text = intent.casefold()
    state = connection_state_from_intent(intent)
    recorded_state = next(
        (_step_data(item).get("state") for item in results if _step_data(item).get("state")),
        None,
    )
    connections: list[dict[str, Any]] = []
    for item in results:
        connections.extend(_step_data(item).get("connections") or [])
    if state == "NOT_ESTABLISHED":
        if str(recorded_state or "").upper() == "ESTABLISHED":
            return CONNECTIONS_WRONG_STATE
        if connections and all((row.get("state") or "").upper() == "ESTABLISHED" for row in connections):
            return CONNECTIONS_WRONG_STATE
    wants_public = any(phrase in text for phrase in (
        "public ip", "external ip", "wan ip", "internet ip", "internet traffic", "public address",
    ))
    wants_ip = (not wants_public) and any(
        phrase in text for phrase in ("ip address", "primary ip", "my ip", "lan address")
    )
    wants_host = any(phrase in text for phrase in (
        "hostname", "system name", "computer name", "machine name", "host name",
    ))
    has_ip = any((_step_data(item).get("primary") or {}).get("ipv4") for item in results)
    has_host = any((_step_data(item).get("system") or {}).get("hostname") for item in results)
    has_public = any(_step_data(item).get("public_ip") for item in results)
    if wants_public and not has_public:
        return MISSING_PUBLIC_IP
    if wants_ip and not has_ip:
        return MISSING_IP
    if wants_host and not has_host:
        return MISSING_HOSTNAME
    install_ask = ("when was" in text and "installed" in text) or "install date" in text
    if install_ask:
        apps: list[dict[str, Any]] = []
        for item in results:
            apps.extend(_step_data(item).get("applications") or [])
        if apps and not any(
            app.get("created") or app.get("date_added") or app.get("fs_creation_date") for app in apps
        ):
            return MISSING_INSTALL_DATE
    return None


def correction_from_failure(intent: str, failure_code: str) -> list[dict[str, Any]]:
    """Deterministic capability retry from a critic failure code."""

    if failure_code in {WRONG_OPERATION, DELETE_MISSING}:
        spec = extract_file_delete(intent)
        domain = intent_host_domain(intent)
        if spec and not domain:
            return [{
                "tool": "filesystem",
                "operation": "delete",
                "inputs": {"operation": "delete", "name": spec["name"]},
                "purpose": f"Remove `{spec['name']}` from the workspace",
            }]
        native = native_steps_for_intent(intent)
        if native:
            return native
        return []
    if failure_code in {WRITE_MISSING, WRITE_WRONG_NAME, WRITE_CONTENT_MISMATCH}:
        spec = extract_file_write(intent)
        if not spec:
            return []
        content = str(spec.get("content") or "")
        if not content.strip():
            content = script_body_for_intent(intent, spec["name"]) or ""
        if not content.strip():
            return []
        if prefers_coding_write(intent, spec["name"]):
            return [{
                "tool": "write_file",
                "operation": "write",
                "inputs": {
                    "path": spec["name"],
                    "content": content,
                    "overwrite": True,
                    "create_parents": True,
                },
                "purpose": f"Create `{spec['name']}` with the requested content",
            }]
        return [{
            "tool": "filesystem",
            "operation": "write",
            "inputs": {
                "operation": "write",
                "name": spec["name"],
                "content": content,
                "overwrite": True,
            },
            "purpose": f"Create `{spec['name']}` with the requested content",
        }]
    if failure_code in {EDIT_MISSING, EDIT_CONTENT_MISMATCH, EDIT_DESTRUCTIVE}:
        return []
    if failure_code == SERVE_NOT_STARTED:
        native = native_steps_for_intent(intent)
        serve = [item for item in native if item.get("operation") == "serve"]
        if serve:
            return serve
        return [{
            "tool": "filesystem",
            "operation": "serve",
            "inputs": {
                "operation": "serve",
                "port": 8000,
                "open_browser": any(
                    word in intent.casefold() for word in ("chrome", "browser", "safari", "firefox")
                ),
            },
            "purpose": "Serve the workspace over HTTP on 127.0.0.1",
        }]
    if failure_code == CONNECTIONS_WRONG_STATE:
        native = native_steps_for_intent(intent)
        connections = [item for item in native if item.get("operation") == "connections"]
        if connections:
            return connections
        port = _port_from_intent(intent)
        inputs: dict[str, Any] = {
            "operation": "connections",
            "state": "NOT_ESTABLISHED",
            "limit": 20,
        }
        if port:
            inputs["port"] = port
        return [{
            "tool": "network",
            "operation": "connections",
            "inputs": inputs,
            "purpose": "List TCP connections that are not ESTABLISHED",
        }]
    if failure_code == MISSING_INSTALL_DATE:
        return [item for item in native_steps_for_intent(intent) if item.get("tool") == "application"]
    if failure_code == MISSING_PUBLIC_IP:
        public = [item for item in native_steps_for_intent(intent) if item.get("operation") == "public_ip"]
        return public or [{
            "tool": "network", "operation": "public_ip",
            "inputs": {"operation": "public_ip"},
            "purpose": "Look up the public IP used for internet traffic",
        }]
    if failure_code in {MISSING_IP, MISSING_HOSTNAME}:
        native = native_steps_for_intent(intent)
        if native:
            return native
        return [
            {"tool": "system", "operation": "hostname", "inputs": {"operation": "hostname"},
             "purpose": "Report the local hostname"},
            {"tool": "network", "operation": "interfaces", "inputs": {"operation": "interfaces"},
             "purpose": "Inspect network interfaces and the primary address"},
        ]
    # Fall back to native shortlist for other codes (exit_nonzero, no_results, …).
    return native_steps_for_intent(intent)[:2]
