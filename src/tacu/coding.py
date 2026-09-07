"""The coding profile: a bigger planner, bigger budgets, and one model resident.

Host questions are one step and a fact. Building something is many steps that
have to agree with each other, and a 12B planner asked for four coordinated
actions returns a good plan roughly half the time — the rest is truncated JSON
and timeouts. `ti code` is the same harness pointed at a model that can hold the
whole task, with the budgets that model needs.

The other half is memory. A 27B model with a 32k KV cache does not share 36 GB
comfortably with a 12B model that nothing is currently asking for, and with a
long keep-alive the small one will not step aside on its own. So the coding
profile unloads it first. Nothing reloads it here: the next ordinary question
loads it again on demand, which is exactly when it is wanted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .platform import ollama_argv, run_argv, which


@dataclass(frozen=True)
class CodingProfile:
    """What `ti code` changes about how the harness runs."""

    model: str
    # A reasoning model spends tokens thinking before it answers, and the
    # default ladder was measured on a model that thinks less.
    num_predict: int
    num_ctx: int
    # Long-horizon work earns more attempts to get it right.
    cognitive_turns: int
    max_steps: int
    timeout: int


# A build is many small steps; the five-step ceiling suits a single host question.
MAX_CODING_STEPS = 10


CODING_MODEL = "qwen3.8:27b-mlx"
PROFILE = CodingProfile(
    model=CODING_MODEL,
    num_predict=4096,
    num_ctx=16384,
    cognitive_turns=6,
    max_steps=8,
    timeout=1800,
)


def coding_model() -> str:
    """The planner `ti code` uses. Overridable, so a better model can replace it."""

    return os.environ.get("TACU_CODING_MODEL", CODING_MODEL).strip() or CODING_MODEL


def installed_models() -> list[str]:
    """Model names Ollama reports, or an empty list when it cannot be asked."""

    if not which("ollama"):
        return []
    raw = run_argv(ollama_argv("installed_models"), timeout=20)
    if raw["exit_code"] != 0:
        return []
    names: list[str] = []
    for line in raw["stdout"].splitlines()[1:]:
        parts = line.split()
        if parts:
            names.append(parts[0])
    return names


def model_is_installed(model: str, available: list[str] | None = None) -> bool:
    """Is this model present? A bare name matches its default tag."""

    names = installed_models() if available is None else available
    wanted = model.strip()
    if wanted in names:
        return True
    stem = wanted.split(":", 1)[0]
    return any(name == wanted or name.split(":", 1)[0] == stem for name in names)


def loaded_models() -> list[str]:
    """What Ollama currently holds in memory."""

    if not which("ollama"):
        return []
    raw = run_argv(ollama_argv("running_models"), timeout=20)
    if raw["exit_code"] != 0:
        return []
    return [line.split()[0] for line in raw["stdout"].splitlines()[1:] if line.split()]


def release_other_models(keep: str) -> list[str]:
    """Unload every model except the one about to be used.

    Ollama will evict under pressure on its own, but a long keep-alive means it
    holds a model nothing is asking for until the timer expires — and a 27B
    planner wants that memory now. Only loaded models are touched, so this costs
    nothing when there is nothing to release.
    """

    if not which("ollama"):
        return []
    released: list[str] = []
    keep_stem = keep.split(":", 1)[0]
    for name in loaded_models():
        if name == keep or name.split(":", 1)[0] == keep_stem:
            continue
        raw = run_argv(ollama_argv("stop") + [name], timeout=30)
        if raw["exit_code"] == 0:
            released.append(name)
    return released


def missing_model_message(model: str) -> str:
    """Say what is missing and the one command that fixes it."""

    return (
        f"ti code plans with {model}, which is not installed.\n"
        f"  Install it:  ollama pull {model}\n"
        f"  Or point ti code at a model you have:  "
        f"TACU_CODING_MODEL=your-model ti code …\n"
        f"  Or use the default planner instead:  ti auto …"
    )


# The only tools the coding lane offers. TACU has more than thirty; showing a
# local model the forensics and packet-capture surface alongside them spends
# context on schemas it will never use and invites calls that make no sense here.
CODING_TOOL_SURFACE: tuple[str, ...] = (
    "read_file", "edit_file", "write_file", "search_code", "repo_map",
    "inspect_symbol", "diagnostics", "run_tests", "shell",
)


def coding_tool_schemas() -> list[dict[str, Any]]:
    """The coding tools in the shape Ollama's native tool calling expects."""

    from .tools import specs

    wanted = {spec.name: spec for spec in specs() if spec.name in CODING_TOOL_SURFACE}
    schemas: list[dict[str, Any]] = []
    for name in CODING_TOOL_SURFACE:
        spec = wanted.get(name)
        if spec is None:
            continue
        schemas.append({
            "type": "function",
            "function": {
                "name": name,
                "description": " ".join((spec.description or "").split())[:400],
                "parameters": spec.input_schema,
            },
        })
    return schemas
