"""Successful-command memory for layered ghost prompts (Layer 3)."""

from __future__ import annotations

import os
import time
from pathlib import Path

from .core import app_home

MAX_ENTRIES = 400
_SKIP = frozenset({
    "help", "completion", "shell-init", "version", "-h", "--help",
    "__ghost-suggest",
})


def ghost_log_path() -> Path:
    return app_home() / "ghost_cmds.log"


def record_successful_command(argv: list[str] | None, *, cwd: str | None = None) -> None:
    """Append one successful interactive-style command for history-ranked ghosts."""

    words = [str(part) for part in (argv or []) if str(part).strip()]
    if not words or words[0] in _SKIP:
        return
    # Keep lines pasteable and short.
    line = "ti " + " ".join(words)
    if len(line) > 220:
        return
    path = ghost_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = f"{int(time.time())}\t{cwd or os.getcwd()}\t{line}\n"
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(entry)
        _trim(path)
    except OSError:
        return


def _trim(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    if len(lines) <= MAX_ENTRIES:
        return
    path.write_text("\n".join(lines[-MAX_ENTRIES:]) + "\n", encoding="utf-8")


def suggest_from_history(prefix: str, *, cwd: str | None = None, limit: int = 1) -> list[str]:
    """Rank prior successful `ti …` lines by prefix match, recency, frequency, cwd."""

    key = (prefix or "").strip()
    if not key.startswith("ti"):
        return []
    path = ghost_log_path()
    if not path.is_file():
        return []
    try:
        rows = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    here = cwd or os.getcwd()
    scores: dict[str, float] = {}
    now = time.time()
    for index, row in enumerate(rows):
        parts = row.split("\t")
        if len(parts) < 3:
            continue
        try:
            stamp = float(parts[0])
        except ValueError:
            stamp = 0.0
        row_cwd, command = parts[1], parts[2]
        if not command.startswith(key) or command == key:
            continue
        age_hours = max(0.0, (now - stamp) / 3600.0)
        recency = 1.0 / (1.0 + age_hours / 24.0)
        frequency = 1.0
        locality = 1.35 if row_cwd == here else 1.0
        # Later lines are newer; slight bonus for order.
        order = 1.0 + index / max(1, len(rows))
        scores[command] = scores.get(command, 0.0) + frequency * recency * locality * order
    ranked = sorted(scores, key=scores.get, reverse=True)
    return ranked[:limit]
