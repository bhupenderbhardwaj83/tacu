"""Persistent numbered clipboard tray — side-channel, not scrollback."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CLIP_LIMIT = 50


@dataclass(frozen=True)
class ClipItem:
    id: int
    created_at: str
    updated_at: str
    label: str
    body: str
    source: str


class ClipStore:
    """SQLite tray of copyable snippets (max CLIP_LIMIT items).

    Tray numbers are the `#` shown in `ti clip list` and used by `ti clip N`.
    When the tray is empty (after clear or deleting the last item), the next
    add starts again at #1. While items remain, new IDs are max(id)+1 so
    existing numbers stay stable until removed.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            path.parent.chmod(0o700)
        self.connection = sqlite3.connect(path)
        if os.name != "nt":
            path.chmod(0o600)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS clips (
              id INTEGER PRIMARY KEY,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              label TEXT NOT NULL,
              body TEXT NOT NULL,
              source TEXT NOT NULL DEFAULT ''
            )"""
        )
        self.connection.commit()

    def __enter__(self) -> "ClipStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.connection.close()

    def _reset_numbering(self) -> None:
        """Allow the next insert to be #1 when the tray is empty."""

        try:
            self.connection.execute("DELETE FROM sqlite_sequence WHERE name='clips'")
        except sqlite3.OperationalError:
            pass

    def _next_id(self) -> int:
        if self.count() == 0:
            self._reset_numbering()
            return 1
        row = self.connection.execute("SELECT COALESCE(MAX(id), 0) FROM clips").fetchone()
        return int(row[0]) + 1

    def add(self, body: str, *, label: str = "", source: str = "") -> ClipItem:
        text = (body or "").strip("\n")
        if not text.strip():
            raise ValueError("Clipboard item body is empty.")
        now = datetime.now(timezone.utc).isoformat()
        title = (label or _default_label(text)).strip()[:80]
        clip_id = self._next_id()
        self.connection.execute(
            "INSERT INTO clips(id,created_at,updated_at,label,body,source) VALUES (?,?,?,?,?,?)",
            (clip_id, now, now, title, text, source or ""),
        )
        # Drop oldest by id when over capacity, then keep numbers stable for survivors.
        self.connection.execute(
            "DELETE FROM clips WHERE id NOT IN (SELECT id FROM clips ORDER BY id DESC LIMIT ?)",
            (CLIP_LIMIT,),
        )
        self.connection.commit()
        item = self.get(clip_id)
        if item is None:
            # Trimmed away an insert that somehow exceeded limit in one step — return newest.
            rows = self.list()
            if not rows:
                raise ValueError("Clipboard item was not retained.")
            return rows[-1]
        return item

    def get(self, clip_id: int) -> ClipItem | None:
        row = self.connection.execute(
            "SELECT id,created_at,updated_at,label,body,source FROM clips WHERE id=?",
            (clip_id,),
        ).fetchone()
        return self._decode(row) if row else None

    def list(self, *, limit: int = CLIP_LIMIT) -> list[ClipItem]:
        rows = self.connection.execute(
            "SELECT id,created_at,updated_at,label,body,source FROM "
            "(SELECT * FROM clips ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
            (max(0, min(limit, CLIP_LIMIT)),),
        ).fetchall()
        return [self._decode(row) for row in rows]

    def update(self, clip_id: int, *, body: str | None = None, label: str | None = None) -> ClipItem:
        item = self.get(clip_id)
        if item is None:
            raise KeyError(clip_id)
        new_body = item.body if body is None else body.strip("\n")
        if not new_body.strip():
            raise ValueError("Clipboard item body is empty.")
        if label is not None:
            new_label = label.strip()[:80] or _default_label(new_body)
        elif body is not None:
            # Editing the body refreshes the list label unless --label was passed.
            new_label = _default_label(new_body)
        else:
            new_label = item.label
        now = datetime.now(timezone.utc).isoformat()
        self.connection.execute(
            "UPDATE clips SET updated_at=?, label=?, body=? WHERE id=?",
            (now, new_label, new_body, clip_id),
        )
        self.connection.commit()
        updated = self.get(clip_id)
        assert updated is not None
        return updated

    def delete(self, clip_id: int) -> bool:
        cursor = self.connection.execute("DELETE FROM clips WHERE id=?", (clip_id,))
        if self.count() == 0:
            self._reset_numbering()
        self.connection.commit()
        return cursor.rowcount > 0

    def search(self, query: str, *, limit: int = CLIP_LIMIT) -> list[ClipItem]:
        needle = (query or "").strip()
        if not needle:
            return self.list(limit=limit)
        like = f"%{needle}%"
        rows = self.connection.execute(
            "SELECT id,created_at,updated_at,label,body,source FROM clips "
            "WHERE label LIKE ? OR body LIKE ? OR source LIKE ? "
            "ORDER BY id DESC LIMIT ?",
            (like, like, like, max(0, min(limit, CLIP_LIMIT))),
        ).fetchall()
        return [self._decode(row) for row in reversed(rows)]

    def clear(self) -> int:
        count = self.connection.execute("SELECT COUNT(*) FROM clips").fetchone()[0]
        self.connection.execute("DELETE FROM clips")
        self._reset_numbering()
        self.connection.commit()
        return int(count)

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM clips").fetchone()[0])

    @staticmethod
    def _decode(row: tuple[Any, ...]) -> ClipItem:
        return ClipItem(row[0], row[1], row[2], row[3], row[4], row[5] or "")


def _default_label(body: str) -> str:
    first = " ".join((body.splitlines() or [""])[0].split())
    if len(first) > 48:
        return first[:45] + "…"
    return first or "clip"


def is_custom_label(item: ClipItem) -> bool:
    """True when the label was chosen with --label rather than derived from the body."""

    return bool(item.label) and item.label != _default_label(item.body)


def origin_line(item: ClipItem, *, width: int = 28) -> str:
    """What to show beside the preview: your label, else where the snippet came from.

    An auto-generated label is the first line of the body, which just repeats the
    preview, so it is not worth a column.
    """

    text = item.label if is_custom_label(item) else item.source
    if not text:
        return ""
    if len(text) > width:
        text = text[: width - 1] + "…"
    return text


def preview_line(item: ClipItem, *, width: int = 56) -> str:
    text = " ".join(item.body.split())
    if len(text) > width:
        text = text[: width - 1] + "…"
    return text
