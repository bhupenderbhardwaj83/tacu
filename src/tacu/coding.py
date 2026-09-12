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


# Coding gets its own action budget; host and lookup limits stay independent.
MAX_CODING_STEPS = 100


CODING_MODEL = "qwen3.8:27b-mlx"
PROFILE = CodingProfile(
    model=CODING_MODEL,
    num_predict=4096,
    num_ctx=16384,
    cognitive_turns=6,
    max_steps=MAX_CODING_STEPS,
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
    "inspect_symbol", "diagnostics", "run_tests", "shell", "verify", "service_process",
    # Reading the host, which this lane genuinely needs: is the server it
    # started actually up, and is that port already taken. Without them,
    # "tell me all the python servers running" had only `shell` to reach for,
    # ran `ps` three times and stopped on the repetition guard, and a service
    # start that hit an occupied health port had no way to find out what held
    # it. Both are read-only, so this widens what the lane can see, not what it
    # can do. The surface stays scoped deliberately: forensics, docker, juicy
    # and the rest are still out, and `system` stays out because hardware and
    # uptime are not part of building and running code.
    "process", "network",
)


# The tools that only look. A question about this machine or this codebase is
# answered by reading it — the alternative, when routing cannot build arguments,
# has been to ask the model with no evidence at all, and it answers anyway.
ANSWER_TOOL_SURFACE: tuple[str, ...] = (
    "filesystem", "read_file", "search_code", "repo_map", "inspect_symbol",
    "system", "process", "network", "application",
)


# What `ti auto` and `ti do` reach for: the host lanes people would otherwise
# drop to a native CLI for, plus enough of the file tools to act on what they
# find. Deliberately not the coding tools — building software is `ti code`'s
# job and giving a model both surfaces at once is how it picks the wrong one.
# Every mutating operation here still passes the policy gate and its own
# approval check on the way through; the surface decides what can be asked for,
# never what can be done without asking.
INTENT_TOOL_SURFACE: tuple[str, ...] = (
    "process", "network", "system", "application", "filesystem",
    "docker", "git", "ollama", "package", "service", "security", "recon", "email",
    "read_file", "search_code", "repo_map",
)

# `ti auto` is capability-only and `ti do` may fall back to a shell — the same
# split the planner has always made. An argv-only capability is checkable in a
# way an arbitrary command line is not, so unattended work does not get one.
REVIEWED_TOOL_SURFACE: tuple[str, ...] = INTENT_TOOL_SURFACE + ("shell",)


def tool_schemas(surface: tuple[str, ...]) -> list[dict[str, Any]]:
    """Named tools in the shape Ollama's native tool calling expects."""

    from .tools import specs

    wanted = {spec.name: spec for spec in specs() if spec.name in surface}
    schemas: list[dict[str, Any]] = []
    for name in surface:
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


def coding_tool_schemas() -> list[dict[str, Any]]:
    return tool_schemas(CODING_TOOL_SURFACE)


def intent_tool_schemas(*, autonomous: bool) -> list[dict[str, Any]]:
    return tool_schemas(intent_surface(autonomous=autonomous))


def intent_surface(*, autonomous: bool) -> tuple[str, ...]:
    return INTENT_TOOL_SURFACE if autonomous else REVIEWED_TOOL_SURFACE


def answer_tool_schemas() -> list[dict[str, Any]]:
    """The read-only surface, checked rather than trusted.

    `ti ask` promises never to change anything, and that promise rested on a
    hand-written tuple of nine names. Nothing stopped a later edit adding a tool
    that writes, and nothing would have noticed. A model cannot call what it is
    never offered, so this is where the promise is actually kept — enforce it
    here, where the offer is made, rather than hoping the list stays right.
    """

    from .tools import specs

    writes = sorted(spec.name for spec in specs()
                    if spec.name in ANSWER_TOOL_SURFACE and spec.risk_level != "read")
    if writes:
        raise RuntimeError(
            "The read-only tool surface must only read; these can change things: "
            + ", ".join(writes))
    # Reading is not the only way out. `ti ask` answers from this machine, and a
    # tool that reaches the internet on the model's own initiative — recon —
    # would let a question about a file turn into requests to a dozen services
    # nobody asked for. Outbound tools are reached through the planner, where
    # the user named the target.
    outbound = sorted(spec.name for spec in specs()
                      if spec.name in ANSWER_TOOL_SURFACE and "network:outbound" in spec.permissions)
    if outbound:
        raise RuntimeError(
            "The lookup surface must stay on this machine; these reach the internet: "
            + ", ".join(outbound))
    return tool_schemas(ANSWER_TOOL_SURFACE)
