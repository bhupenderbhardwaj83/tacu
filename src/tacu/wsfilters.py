"""Wireshark display-filter names from a local field catalog.

Models are often trained on older Wireshark releases. When
``utils/wireshark_filters.csv`` is present (FieldName, FilterString,
Description), it is the authority for field names. The whole sheet is never
sent to the model — only a handful of matches for the current question.
"""

from __future__ import annotations

import csv
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .core import app_home

# Always-valid names for packet questions, even when the CSV is missing.
CORE_FILTERS: tuple[tuple[str, str], ...] = (
    ("ip.addr", "source or destination IPv4 address"),
    ("ip.src", "source IPv4 address"),
    ("ip.dst", "destination IPv4 address"),
    ("tcp.port", "TCP source or destination port"),
    ("tcp.srcport", "TCP source port"),
    ("tcp.dstport", "TCP destination port"),
    ("udp.port", "UDP source or destination port"),
    ("dns", "DNS packets"),
    ("dns.qry.name", "DNS query name"),
    ("dns.a", "DNS A (IPv4) answer"),
    ("http.host", "HTTP Host header"),
    ("tls.handshake.extensions_server_name", "TLS SNI (server name)"),
    ("tcp.flags.syn", "TCP SYN flag"),
)

_FILTER_ASK = re.compile(
    r"\b(display\s+filters?|wireshark\s+filters?|pcap\s+filters?|tshark|bpf)\b"
    r"|\bfilters?\b",
    re.IGNORECASE,
)
_STOP = frozenset({
    "the", "a", "an", "of", "for", "to", "in", "on", "and", "or", "with", "from",
    "show", "me", "tell", "what", "which", "how", "all", "packet", "packets",
    "traffic", "communication", "wireshark", "display", "filter", "filters",
    "please", "that", "this", "does", "did", "can", "you", "give", "about",
    "using", "use", "see", "find", "list", "name", "names",
})
_DOMAIN = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ALIASES = {
    "sni": "tls.handshake.extensions_server_name",
    "host": "http.host",
    "hostname": "http.host",
    "query": "dns.qry.name",
    "sport": "tcp.srcport",
    "dport": "tcp.dstport",
    "syn": "tcp.flags.syn",
}


@dataclass(frozen=True)
class FilterField:
    filter_string: str
    field_name: str
    description: str


def wants_filter_help(question: str) -> bool:
    return bool(_FILTER_ASK.search(question or ""))


def catalog_path(*, cwd: Path | None = None, workspace: Path | None = None,
                 extra_roots: Sequence[Path] | None = None) -> Path | None:
    """First existing ``utils/wireshark_filters.csv`` from cwd, workspace, or repo."""

    roots: list[Path] = []
    here = Path.cwd() if cwd is None else cwd
    roots.append(here)
    if extra_roots:
        for item in extra_roots:
            path = Path(item)
            roots.append(path if path.is_dir() else path.parent)
    if workspace:
        roots.append(workspace)
    else:
        try:
            from .configuration import configured_workspace
            chosen = configured_workspace()
        except Exception:
            chosen = None
        if chosen:
            roots.append(chosen)
    seen: set[Path] = set()
    for root in roots:
        path = (root / "utils" / "wireshark_filters.csv").expanduser()
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if path.is_file():
            return path
    return None


def lookup_filters(question: str, *, catalog: Path | None = None,
                   cache_dir: Path | None = None, extra_roots: Sequence[Path] | None = None,
                   limit: int = 12) -> list[FilterField]:
    """Return catalog rows that match protocol/field tokens in the question."""

    path = catalog if catalog is not None else catalog_path(extra_roots=extra_roots)
    if path is None or not path.is_file():
        return []
    tokens = _tokens(question)
    if not tokens:
        return []
    connection = _indexed(path, cache_dir=cache_dir)
    try:
        found: dict[str, FilterField] = {}
        for token in tokens:
            needle = _ALIASES.get(token, token)
            rows = connection.execute(
                """
                SELECT filter_string, field_name, description FROM fields
                WHERE lower(filter_string) = ?
                   OR lower(filter_string) LIKE ?
                   OR lower(filter_string) LIKE ?
                ORDER BY length(filter_string)
                LIMIT ?
                """,
                (needle, needle + ".%", "%." + needle, max(4, limit)),
            ).fetchall()
            for filter_string, field_name, description in rows:
                found.setdefault(filter_string, FilterField(
                    filter_string, field_name, description or "",
                ))
                if len(found) >= limit:
                    return list(found.values())[:limit]
        return list(found.values())[:limit]
    finally:
        connection.close()


def _tokens(question: str) -> list[str]:
    words = re.findall(r"[a-z0-9_.]+", (question or "").casefold())
    out: list[str] = []
    for word in words:
        if word in _STOP or len(word) < 2:
            continue
        if _DOMAIN.match(word) or _IP.match(word):
            continue
        if word not in out:
            out.append(word)
    return out


def _indexed(catalog: Path, *, cache_dir: Path | None = None) -> sqlite3.Connection:
    cache_root = cache_dir if cache_dir is not None else app_home() / "cache"
    cache_root.mkdir(parents=True, exist_ok=True)
    cache = cache_root / "wireshark_filters.sqlite"
    stamp = f"{catalog.resolve()}::{int(catalog.stat().st_mtime)}"
    connection = sqlite3.connect(cache)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS fields ("
        "filter_string TEXT PRIMARY KEY, field_name TEXT, description TEXT)"
    )
    row = connection.execute("SELECT value FROM meta WHERE key='stamp'").fetchone()
    if row and row[0] == stamp:
        return connection
    connection.execute("DELETE FROM fields")
    with catalog.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        batch: list[tuple[str, str, str]] = []
        for record in reader:
            filt = (record.get("FilterString") or "").strip()
            if not filt:
                continue
            batch.append((
                filt,
                (record.get("FieldName") or "").strip(),
                (record.get("Description") or "").strip()[:200],
            ))
            if len(batch) >= 20_000:
                connection.executemany(
                    "INSERT OR IGNORE INTO fields VALUES (?,?,?)", batch)
                batch.clear()
        if batch:
            connection.executemany(
                "INSERT OR IGNORE INTO fields VALUES (?,?,?)", batch)
    connection.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('stamp', ?)", (stamp,))
    connection.commit()
    return connection
