"""Persistent OS-flavored command/recipe memory — pasteable argv + capability identity."""

from __future__ import annotations

import json
import os
import shlex
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .platform import (
    detect,
    listening_tcp_argv,
    ollama_argv,
    process_list_argv,
    tcp_connections_argv,
)

RECIPE_LIMIT = 200


@dataclass(frozen=True)
class Recipe:
    id: int
    created_at: str
    updated_at: str
    os: str
    ps_flavour: str
    tool: str
    operation: str
    purpose: str
    labels: str
    intent: str
    argv: tuple[str, ...]
    native_inputs: str
    source: str
    hit_count: int

    @property
    def paste(self) -> str:
        return shlex.join(list(self.argv))

    @property
    def capability(self) -> str:
        if self.tool == "shell":
            return "shell"
        return f"{self.tool}.{self.operation}"


class RecipeStore:
    """SQLite cookbook of capability ops with OS-flavored pasteable argv."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            path.parent.chmod(0o700)
        self.connection = sqlite3.connect(path)
        if os.name != "nt":
            path.chmod(0o600)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS recipes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              os TEXT NOT NULL,
              ps_flavour TEXT NOT NULL,
              tool TEXT NOT NULL,
              operation TEXT NOT NULL,
              purpose TEXT NOT NULL,
              labels TEXT NOT NULL DEFAULT '',
              intent TEXT NOT NULL DEFAULT '',
              argv_json TEXT NOT NULL,
              native_inputs TEXT NOT NULL DEFAULT '{}',
              source TEXT NOT NULL DEFAULT '',
              hit_count INTEGER NOT NULL DEFAULT 1,
              UNIQUE(os, tool, operation, argv_json)
            )"""
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS recipes_search ON recipes(os, tool, operation, labels, purpose)"
        )
        self.connection.commit()

    def __enter__(self) -> "RecipeStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.connection.close()

    def count(self, *, os_name: str | None = None) -> int:
        if os_name:
            row = self.connection.execute(
                "SELECT COUNT(*) FROM recipes WHERE os=?", (os_name,)
            ).fetchone()
        else:
            row = self.connection.execute("SELECT COUNT(*) FROM recipes").fetchone()
        return int(row[0])

    def get(self, recipe_id: int) -> Recipe | None:
        row = self.connection.execute(
            "SELECT id,created_at,updated_at,os,ps_flavour,tool,operation,purpose,"
            "labels,intent,argv_json,native_inputs,source,hit_count FROM recipes WHERE id=?",
            (recipe_id,),
        ).fetchone()
        return self._decode(row) if row else None

    def latest(self, *, os_name: str | None = None) -> Recipe | None:
        host = os_name or detect().os
        row = self.connection.execute(
            "SELECT id,created_at,updated_at,os,ps_flavour,tool,operation,purpose,"
            "labels,intent,argv_json,native_inputs,source,hit_count FROM recipes "
            "WHERE os=? ORDER BY updated_at DESC, id DESC LIMIT 1",
            (host,),
        ).fetchone()
        return self._decode(row) if row else None

    def list(self, *, limit: int = 40, os_name: str | None = None) -> list[Recipe]:
        host = os_name or detect().os
        rows = self.connection.execute(
            "SELECT id,created_at,updated_at,os,ps_flavour,tool,operation,purpose,"
            "labels,intent,argv_json,native_inputs,source,hit_count FROM recipes "
            "WHERE os=? ORDER BY hit_count DESC, updated_at DESC, id DESC LIMIT ?",
            (host, max(0, min(limit, RECIPE_LIMIT))),
        ).fetchall()
        return [self._decode(row) for row in rows]

    def search(self, query: str, *, limit: int = 40, os_name: str | None = None) -> list[Recipe]:
        needle = (query or "").strip()
        host = os_name or detect().os
        if not needle:
            return self.list(limit=limit, os_name=host)
        like = f"%{needle}%"
        rows = self.connection.execute(
            "SELECT id,created_at,updated_at,os,ps_flavour,tool,operation,purpose,"
            "labels,intent,argv_json,native_inputs,source,hit_count FROM recipes "
            "WHERE os=? AND ("
            "purpose LIKE ? COLLATE NOCASE OR labels LIKE ? COLLATE NOCASE "
            "OR tool LIKE ? COLLATE NOCASE OR operation LIKE ? COLLATE NOCASE "
            "OR intent LIKE ? COLLATE NOCASE OR argv_json LIKE ? COLLATE NOCASE"
            ") ORDER BY hit_count DESC, updated_at DESC, id DESC LIMIT ?",
            (host, like, like, like, like, like, like, max(0, min(limit, RECIPE_LIMIT))),
        ).fetchall()
        return [self._decode(row) for row in rows]

    def upsert(
        self,
        *,
        tool: str,
        operation: str,
        argv: Iterable[str],
        purpose: str = "",
        labels: str = "",
        intent: str = "",
        native_inputs: str = "{}",
        source: str = "",
        os_name: str | None = None,
        ps_flavour: str | None = None,
    ) -> Recipe:
        args = tuple(str(part) for part in argv if str(part).strip() or str(part) == "0")
        if not args:
            raise ValueError("Recipe argv is empty.")
        ctx = detect()
        host = os_name or ctx.os
        flavour = ps_flavour or ctx.ps_flavour
        argv_json = json.dumps(list(args), ensure_ascii=False)
        now = datetime.now(timezone.utc).isoformat()
        purpose_text = (purpose or f"{tool}.{operation}").strip()[:200]
        label_text = (labels or purpose_text).strip()[:400]
        intent_text = (intent or "").strip()[:300]
        inputs = native_inputs if native_inputs.strip() else "{}"
        existing = self.connection.execute(
            "SELECT id, hit_count FROM recipes WHERE os=? AND tool=? AND operation=? AND argv_json=?",
            (host, tool, operation, argv_json),
        ).fetchone()
        if existing:
            recipe_id, hits = int(existing[0]), int(existing[1]) + 1
            self.connection.execute(
                "UPDATE recipes SET updated_at=?, purpose=?, labels=?, intent=?, "
                "native_inputs=?, source=?, hit_count=? WHERE id=?",
                (now, purpose_text, label_text, intent_text, inputs, source or "", hits, recipe_id),
            )
        else:
            cursor = self.connection.execute(
                "INSERT INTO recipes(created_at,updated_at,os,ps_flavour,tool,operation,"
                "purpose,labels,intent,argv_json,native_inputs,source,hit_count) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)",
                (
                    now, now, host, flavour, tool, operation, purpose_text, label_text,
                    intent_text, argv_json, inputs, source or "",
                ),
            )
            recipe_id = int(cursor.lastrowid or 0)
            self.connection.execute(
                "DELETE FROM recipes WHERE id NOT IN ("
                "SELECT id FROM recipes ORDER BY hit_count DESC, updated_at DESC LIMIT ?"
                ")",
                (RECIPE_LIMIT,),
            )
        self.connection.commit()
        item = self.get(recipe_id)
        if item is None:
            latest = self.latest(os_name=host)
            if latest is None:
                raise ValueError("Recipe was not retained.")
            return latest
        return item

    def delete(self, recipe_id: int) -> bool:
        cursor = self.connection.execute("DELETE FROM recipes WHERE id=?", (recipe_id,))
        self.connection.commit()
        return cursor.rowcount > 0

    def clear(self) -> int:
        count = self.count()
        self.connection.execute("DELETE FROM recipes")
        self.connection.commit()
        return count

    def ensure_seeded(self) -> int:
        """Insert built-in OS recipes when this host has none yet. Returns added count."""

        host = detect().os
        if self.count(os_name=host) > 0:
            return 0
        return seed_platform_recipes(self)

    @staticmethod
    def _decode(row: tuple[Any, ...]) -> Recipe:
        argv = tuple(json.loads(row[10]))
        return Recipe(
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7],
            row[8], row[9], argv, row[11], row[12], int(row[13]),
        )


def seed_platform_recipes(store: RecipeStore) -> int:
    """Materialize common pasteable argv for the current OS."""

    ctx = detect()
    seeds: list[tuple[str, str, str, list[str], str]] = [
        ("process", "top_cpu", "List processes (CPU/RSS columns)", process_list_argv(),
         "top cpu process list ps"),
        ("network", "listen", "Listening TCP sockets", listening_tcp_argv(),
         "listen listening tcp ports lsof"),
        ("network", "connections", "TCP connections (ESTABLISHED)",
         tcp_connections_argv(state="ESTABLISHED"),
         "connections established tcp sockets"),
        ("ollama", "list", "List local Ollama models", ollama_argv("list"),
         "ollama models list"),
    ]
    if ctx.os == "macos":
        seeds.append(
            ("system", "sw_vers", "macOS version", ["sw_vers"], "macos version sw_vers")
        )
    added = 0
    for tool, operation, purpose, argv, labels in seeds:
        if not argv:
            continue
        store.upsert(
            tool=tool,
            operation=operation,
            argv=argv,
            purpose=purpose,
            labels=labels,
            source="seed",
        )
        added += 1
    return added


def pasteable_from_intent_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Pull capability identity + pasteable argv from an intent-run step result."""

    result = entry.get("result") or {}
    if not isinstance(result, dict) or not result.get("ok", True):
        return None
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    tool = str(result.get("tool") or "").strip()
    recipe = data.get("recipe") if data else None
    argv: list[str] | None = None
    if isinstance(recipe, (list, tuple)) and recipe:
        argv = [str(part) for part in recipe]
    elif isinstance(recipe, str) and recipe.strip():
        try:
            argv = shlex.split(recipe)
        except ValueError:
            argv = [recipe.strip()]
    elif tool == "shell":
        command = entry.get("command")
        if isinstance(command, (list, tuple)) and command:
            argv = [str(part) for part in command]
    if not argv:
        return None
    operation = str((data or {}).get("operation") or "").strip()
    command = entry.get("command")
    if not operation and isinstance(command, list) and len(command) >= 2 and tool and command[0] == tool:
        operation = str(command[1])
    if tool == "shell" or not tool:
        tool = "shell"
        operation = operation or "argv"
    purpose = str(entry.get("purpose") or f"{tool}.{operation}").strip()
    inputs = "{}"
    if data and data.get("operation"):
        # Keep a compact inputs snapshot when present
        compact = {key: data[key] for key in ("operation", "limit", "state", "name", "path") if key in data}
        if compact:
            inputs = json.dumps(compact, ensure_ascii=False)
    return {
        "tool": tool,
        "operation": operation or "command",
        "argv": argv,
        "purpose": purpose,
        "native_inputs": inputs,
    }


def index_intent_results(
    store: RecipeStore,
    intent: str,
    results: list[dict[str, Any]],
    *,
    source: str,
) -> list[Recipe]:
    """Upsert pasteable recipes from successful auto/do steps."""

    indexed: list[Recipe] = []
    tokens = " ".join((intent or "").casefold().split()[:12])
    for entry in results:
        extracted = pasteable_from_intent_entry(entry)
        if not extracted:
            continue
        labels = f"{extracted['purpose']} {extracted['tool']} {extracted['operation']} {tokens}".strip()
        recipe = store.upsert(
            tool=extracted["tool"],
            operation=extracted["operation"],
            argv=extracted["argv"],
            purpose=extracted["purpose"],
            labels=labels,
            intent=intent,
            native_inputs=extracted["native_inputs"],
            source=source,
        )
        indexed.append(recipe)
    return indexed


def preview_argv(argv: Iterable[str], *, width: int = 64) -> str:
    text = shlex.join(list(argv))
    if len(text) > width:
        return text[: width - 1] + "…"
    return text
