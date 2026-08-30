"""Temporary analytical store for files too large to read into a model.

A loaded file becomes its own SQLite database under `datasets/`, described by a
small profile. The profile — not the data — is what a person or a model reads to
decide what to ask. Datasets expire (4 hours by default) and are swept on the
next `ti data` call, so this never becomes silent permanent storage.

Everything here is deterministic: no model is involved in loading or querying.
"""

from __future__ import annotations

import csv
import io
import itertools
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

from .core import TacuError, app_home, HIGH_JUICY_KINDS, colorize_output, detect_juicy
from .juicy import kind_matches_query, value_matches_needles
from .juicy import juicy_ansi
from .theme import PALETTE, color_enabled, paint

DEFAULT_TTL_HOURS = 4
TABLE_NAME = "data"
CATALOG_NAME = "catalog.db"
# Rows sampled to infer column types before the table is created.
TYPE_SAMPLE_ROWS = 1_000
INSERT_BATCH = 50_000
QUERY_ROW_LIMIT = 500
QUERY_TIMEOUT_SECONDS = 30
MAX_COLUMNS = 512

_SQL_FORBIDDEN = re.compile(
    r"\b(attach|detach|pragma|insert|update|delete|drop|create|alter|replace|"
    r"vacuum|reindex|analyze|begin|commit|rollback|savepoint|load_extension)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ColumnProfile:
    name: str
    source_name: str
    affinity: str
    non_null: int
    distinct: int
    minimum: str
    maximum: str
    samples: list[str]


@dataclass(frozen=True)
class DatasetInfo:
    id: str
    name: str
    source_path: str
    created_at: str
    expires_at: str
    row_count: int
    column_count: int
    source_bytes: int
    ragged_rows: int
    columns: list[str] = field(default_factory=list)

    @property
    def path(self) -> Path:
        return datasets_home() / f"{self.id}.db"

    @property
    def expired(self) -> bool:
        return _parse_time(self.expires_at) <= datetime.now(timezone.utc)

    def remaining(self) -> str:
        delta = _parse_time(self.expires_at) - datetime.now(timezone.utc)
        seconds = int(delta.total_seconds())
        if seconds <= 0:
            return "expired"
        if seconds < 3600:
            return f"{seconds // 60}m left"
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m left"


@dataclass(frozen=True)
class DatasetProfile:
    info: DatasetInfo
    columns: list[ColumnProfile]


def datasets_home(home: Path | None = None) -> Path:
    root = (home or app_home()) / "datasets"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        root.chmod(0o700)
    return root


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return datetime.now(timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _secure(path: Path) -> None:
    if os.name != "nt" and path.exists():
        path.chmod(0o600)


def _catalog(home: Path | None = None) -> sqlite3.Connection:
    path = datasets_home(home) / CATALOG_NAME
    connection = sqlite3.connect(path)
    _secure(path)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS datasets (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, source_path TEXT NOT NULL,
          created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          row_count INTEGER NOT NULL, column_count INTEGER NOT NULL,
          source_bytes INTEGER NOT NULL, ragged_rows INTEGER NOT NULL DEFAULT 0,
          columns_json TEXT NOT NULL DEFAULT '[]'
        )"""
    )
    connection.commit()
    return connection


def _row_to_info(row: Sequence[Any]) -> DatasetInfo:
    import json

    return DatasetInfo(
        id=row[0], name=row[1], source_path=row[2], created_at=row[3], expires_at=row[4],
        row_count=int(row[5]), column_count=int(row[6]), source_bytes=int(row[7]),
        ragged_rows=int(row[8]), columns=list(json.loads(row[9] or "[]")),
    )


def list_datasets(home: Path | None = None, *, sweep: bool = True) -> list[DatasetInfo]:
    if sweep:
        sweep_expired(home)
    with _catalog(home) as connection:
        rows = connection.execute(
            "SELECT id,name,source_path,created_at,expires_at,row_count,column_count,"
            "source_bytes,ragged_rows,columns_json FROM datasets ORDER BY created_at DESC"
        ).fetchall()
    return [_row_to_info(row) for row in rows]


def allocate_dataset_name(requested: str = "", home: Path | None = None) -> str:
    """Pick a unique handle: --name if given, otherwise dt1, dt2, and so on.

    File stems are not used. A long filename would truncate in `ti data list`
    and then could not be typed back as a query key.
    """

    used = {item.name.casefold() for item in list_datasets(home, sweep=False)}
    candidate = (requested or "").strip()[:60]
    if candidate:
        if candidate.casefold() in used:
            raise TacuError(
                f"A dataset named {candidate!r} is already loaded. "
                f"Pick a different --name, or remove it with: ti data rm {candidate}"
            )
        return candidate
    index = 1
    while f"dt{index}" in used:
        index += 1
    return f"dt{index}"


def source_hint(path: str, *, words: int = 3, width: int = 24) -> str:
    """First few tokens of the loaded filename, for `ti data list`."""

    name = Path(path or "").name
    if not name:
        return "-"
    stem = Path(name).stem
    parts = [part for part in re.split(r"[_\-\s]+", stem) if part]
    hint = " ".join(parts[:words]) if parts else stem
    if len(hint) > width:
        return hint[: width - 1] + "…"
    return hint or "-"


def resolve_dataset(reference: str, home: Path | None = None) -> DatasetInfo:
    """Find a dataset by id, id prefix, or name. Names are matched case-insensitively."""

    needle = (reference or "").strip()
    if not needle:
        raise TacuError("Name a dataset. See what is loaded with: ti data list")
    available = list_datasets(home)
    if not available:
        raise TacuError("No datasets are loaded. Load one with: ti data load FILE.csv")
    for item in available:
        if item.id == needle or item.name == needle:
            return item
    folded = needle.casefold()
    matches = [item for item in available
               if item.id.startswith(needle) or item.name.casefold() == folded]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        names = " · ".join(f"{item.id[:8]} {item.name}" for item in matches[:5])
        raise TacuError(f"{needle!r} matches several datasets: {names}")
    known = " · ".join(f"{item.id[:8]} {item.name}" for item in available[:5])
    raise TacuError(f"No dataset matches {needle!r}. Loaded: {known}")


def sweep_expired(home: Path | None = None) -> int:
    """Delete datasets past their TTL. Cheap enough to run on every command."""

    removed = 0
    with _catalog(home) as connection:
        rows = connection.execute("SELECT id, expires_at FROM datasets").fetchall()
        stale = [row[0] for row in rows if _parse_time(row[1]) <= datetime.now(timezone.utc)]
        for dataset_id in stale:
            (datasets_home(home) / f"{dataset_id}.db").unlink(missing_ok=True)
            connection.execute("DELETE FROM datasets WHERE id=?", (dataset_id,))
            removed += 1
        connection.commit()
    return removed


def drop_dataset(info: DatasetInfo, home: Path | None = None) -> None:
    (datasets_home(home) / f"{info.id}.db").unlink(missing_ok=True)
    with _catalog(home) as connection:
        connection.execute("DELETE FROM datasets WHERE id=?", (info.id,))
        connection.commit()


def drop_all(home: Path | None = None) -> int:
    items = list_datasets(home, sweep=False)
    for item in items:
        drop_dataset(item, home)
    return len(items)


def enrich_dataset(info: DatasetInfo, home: Path | None = None) -> DatasetInfo:
    """Rebuild a packet-capture dataset with names learned from the same file."""

    from .readers import detect_format

    source = Path(info.source_path).expanduser()
    if not source.is_file() and not source.is_absolute():
        source = (Path.cwd() / source).resolve()
    if not source.is_file():
        raise TacuError(
            f"Cannot enrich {info.name}: the original capture is gone ({info.source_path}). "
            f"Load it again with: ti data load FILE.pcap --name {info.name}"
        )
    kind = detect_format(source)
    if kind != "pcap":
        raise TacuError(
            f"{info.name} was not loaded from a packet capture. "
            "Name enrichment is for pcap/pcapng files."
        )
    left = _parse_time(info.expires_at) - datetime.now(timezone.utc)
    hours = max(0.01, left.total_seconds() / 3600)
    name = info.name
    drop_dataset(info, home)
    return load_any(source, name=name, ttl_hours=hours, home=home)


def _identifier(raw: str, used: set[str]) -> str:
    """Turn a spreadsheet header into a safe, unique SQL identifier."""

    cleaned = re.sub(r"\W+", "_", (raw or "").strip()).strip("_")
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"col_{cleaned}" if cleaned else "col"
    cleaned = cleaned[:60]
    candidate, suffix = cleaned, 2
    while candidate.casefold() in used:
        candidate = f"{cleaned}_{suffix}"
        suffix += 1
    used.add(candidate.casefold())
    return candidate


def _blank(value: Any) -> bool:
    """A cell carries no information. JSON gives real nulls; CSV gives empty text."""

    if value is None:
        return True
    return isinstance(value, str) and value.strip() == ""


def _looks_integer(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return value.is_integer()
    text = str(value).strip()
    if not text or text in {"-", "+"}:
        return False
    body = text[1:] if text[0] in "+-" else text
    return body.isdigit() and len(body) <= 18


def _looks_real(value: Any) -> bool:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return True
    try:
        float(str(value).strip())
        return True
    except (TypeError, ValueError):
        return False


def _infer_affinity(values: list[Any]) -> str:
    seen = [value for value in values if not _blank(value)]
    if not seen:
        return "TEXT"
    if all(_looks_integer(value) for value in seen):
        return "INTEGER"
    if all(_looks_real(value) for value in seen):
        return "REAL"
    return "TEXT"


def _convert(value: Any, affinity: str) -> Any:
    if _blank(value):
        return None
    if isinstance(value, bool):
        return int(value)
    if not isinstance(value, str):
        # JSON and XLSX already hand over typed values.
        return value
    text = value.strip()
    if affinity == "INTEGER":
        try:
            return int(text)
        except ValueError:
            return value
    if affinity == "REAL":
        try:
            return float(text)
        except ValueError:
            return value
    return value


class _CountingLines:
    """Feed csv.reader while tracking progress.

    `handle.tell()` raises once csv.reader has called next() on the file, so the
    only way to report progress is to measure the lines as they go past.
    """

    def __init__(self, handle: Any) -> None:
        self._handle = handle
        self.characters = 0

    def __iter__(self) -> "_CountingLines":
        return self

    def __next__(self) -> str:
        line = next(self._handle)
        self.characters += len(line)
        return line


def _sniff(sample: str, delimiter: str | None) -> tuple[str, bool]:
    if delimiter:
        chosen = delimiter
    else:
        try:
            chosen = csv.Sniffer().sniff(sample, delimiters=",\t;|").delimiter
        except csv.Error:
            chosen = "\t" if sample.count("\t") > sample.count(",") else ","
    try:
        header = csv.Sniffer().has_header(sample)
    except csv.Error:
        header = True
    if not header and _strong_text_header(sample, chosen):
        header = True
    return chosen, header


_COMMON_HEADER_NAMES = {
    "active", "address", "amount", "category", "city", "code", "country",
    "created", "date", "description", "email", "enabled", "first_name",
    "host", "hostname", "id", "ip", "last_name", "level", "message",
    "mobile", "name", "number", "owner", "phone", "port", "price",
    "region", "score", "service", "status", "timestamp", "total", "type",
    "updated", "url", "user", "username", "value",
}


def _header_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().casefold()).strip("_")


def _header_value_kind(value: str) -> str:
    text = value.strip()
    if not text:
        return "blank"
    lowered = text.casefold()
    if lowered in {"true", "false", "yes", "no", "enabled", "disabled"}:
        return "boolean"
    if _looks_integer(text):
        return "integer"
    if _looks_real(text):
        return "real"
    if "@" in text and "." in text.rsplit("@", 1)[-1]:
        return "email"
    if re.fullmatch(r"\+?[0-9][0-9 ()-]{6,}", text):
        return "phone"
    if re.match(r"https?://", text, re.IGNORECASE):
        return "url"
    return "text"


def _strong_text_header(sample: str, delimiter: str) -> bool:
    """Recover common all-text headers that ``csv.Sniffer`` misses.

    The fallback is deliberately conservative: every first-row cell must look
    like a unique field label, and the row must have semantic evidence from
    common column names or typed values underneath it. Ambiguous files remain
    controllable through explicit ``--header`` / ``--no-header`` flags.
    """

    try:
        rows = list(itertools.islice(csv.reader(io.StringIO(sample), delimiter=delimiter), 12))
    except csv.Error:
        return False
    if len(rows) < 2 or len(rows[0]) < 2:
        return False
    width = len(rows[0])
    comparable = [row for row in rows[1:] if len(row) == width]
    if not comparable:
        return False
    first = [value.strip() for value in rows[0]]
    keys = [_header_key(value) for value in first]
    if any(not key or len(value) > 80 for key, value in zip(keys, first)):
        return False
    if len(set(keys)) != len(keys):
        return False
    if any(_header_value_kind(value) != "text" for value in first):
        return False
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9 _./()-]*", value) for value in first):
        return False

    common = sum(key in _COMMON_HEADER_NAMES or key.endswith("_id") for key in keys)
    typed_contrasts = 0
    for index in range(width):
        kinds = {
            _header_value_kind(row[index])
            for row in comparable
            if row[index].strip()
        }
        if kinds and kinds != {"text"}:
            typed_contrasts += 1
    return common >= 2 or (common >= 1 and typed_contrasts >= 1)


def load_csv(
    source: Path,
    *,
    name: str = "",
    ttl_hours: float = DEFAULT_TTL_HOURS,
    delimiter: str | None = None,
    has_header: bool | None = None,
    home: Path | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> DatasetInfo:
    """Stream a delimited file into its own SQLite database.

    Memory stays flat: rows are inserted in batches and never all held at once.
    Ragged rows are padded or trimmed rather than aborting the load, and counted
    so the profile can warn about them.
    """

    path = source.expanduser()
    if not path.is_file():
        raise TacuError(f"No such file: {path}")
    total_bytes = path.stat().st_size
    if total_bytes == 0:
        raise TacuError(f"{path.name} is empty.")

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as probe:
        sample = probe.read(64 * 1024)
    if not sample.strip():
        raise TacuError(f"{path.name} has no readable text.")
    chosen_delimiter, sniffed_header = _sniff(sample, delimiter)
    header_present = sniffed_header if has_header is None else has_header

    dataset_id = uuid.uuid4().hex
    target = datasets_home(home) / f"{dataset_id}.db"
    target.unlink(missing_ok=True)

    handle = path.open("r", encoding="utf-8-sig", errors="replace", newline="")
    counter = _CountingLines(handle)
    connection: sqlite3.Connection | None = None
    try:
        reader = csv.reader(counter, delimiter=chosen_delimiter)
        try:
            first = next(reader)
        except StopIteration as error:
            raise TacuError(f"{path.name} has no rows.") from error
        if len(first) > MAX_COLUMNS:
            raise TacuError(
                f"{path.name} has {len(first)} columns; the limit is {MAX_COLUMNS}. "
                "Select fewer columns first, e.g. with cut or awk."
            )

        used: set[str] = set()
        if header_present:
            source_names = [value.strip() for value in first]
            pending_first: list[str] | None = None
        else:
            source_names = [f"column_{index + 1}" for index in range(len(first))]
            pending_first = first
        column_names = [_identifier(value, used) for value in source_names]
        width = len(column_names)

        sample_rows: list[list[str]] = []
        if pending_first is not None:
            sample_rows.append(pending_first)
        for row in reader:
            sample_rows.append(row)
            if len(sample_rows) >= TYPE_SAMPLE_ROWS:
                break
        affinities = [
            _infer_affinity([row[index] for row in sample_rows if index < len(row)])
            for index in range(width)
        ]

        plan = _RowPlan(
            source_names=source_names,
            column_names=column_names,
            affinities=affinities,
            sample_rows=sample_rows,
            rows=reader,
            consumed=lambda: counter.characters,
        )
        return _build_store(
            path, plan, dataset_id=dataset_id, target=target, name=name,
            ttl_hours=ttl_hours, home=home, on_progress=on_progress, total_bytes=total_bytes,
        )
    finally:
        handle.close()


@dataclass
class _RowPlan:
    """Everything a reader has to settle before rows can be stored."""

    source_names: list[str]
    column_names: list[str]
    affinities: list[str]
    sample_rows: list[list[Any]]
    rows: Iterator[list[Any]]
    consumed: Callable[[], int]


def _build_store(
    path: Path,
    plan: _RowPlan,
    *,
    dataset_id: str,
    target: Path,
    name: str,
    ttl_hours: float,
    home: Path | None,
    on_progress: Callable[[int, int], None] | None,
    total_bytes: int,
    progress_total: int | None = None,
) -> DatasetInfo:
    """Write a planned set of rows into its own database and register it.

    Shared by every format so that batching, type conversion, the catalog entry
    and the TTL behave identically whatever the file started out as.
    """

    assigned = allocate_dataset_name(name, home)
    width = len(plan.column_names)
    # A compressed sheet gives no meaningful byte position, so progress counts rows.
    reportable = total_bytes if progress_total is None else progress_total
    connection = sqlite3.connect(target)
    ragged = 0
    row_count = 0
    batch: list[tuple[Any, ...]] = []
    try:
        _secure(target)
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        declaration = ", ".join(
            f'"{column}" {affinity}'
            for column, affinity in zip(plan.column_names, plan.affinities)
        )
        connection.execute(f"CREATE TABLE {TABLE_NAME} ({declaration})")
        connection.execute(
            "CREATE TABLE tacu_columns (position INTEGER, name TEXT, source_name TEXT, affinity TEXT)"
        )
        connection.executemany(
            "INSERT INTO tacu_columns VALUES (?,?,?,?)",
            [(index, plan.column_names[index], plan.source_names[index], plan.affinities[index])
             for index in range(width)],
        )
        insert = f"INSERT INTO {TABLE_NAME} VALUES ({','.join('?' * width)})"

        def normalise(row: list[Any]) -> tuple[Any, ...]:
            nonlocal ragged
            if len(row) != width:
                ragged += 1
                row = (row + [None] * width)[:width] if len(row) < width else row[:width]
            return tuple(_convert(row[index], plan.affinities[index]) for index in range(width))

        def flush() -> None:
            if batch:
                connection.executemany(insert, batch)
                batch.clear()

        for row in plan.sample_rows:
            batch.append(normalise(row))
            row_count += 1
        flush()

        for row in plan.rows:
            batch.append(normalise(row))
            row_count += 1
            if len(batch) >= INSERT_BATCH:
                flush()
                if on_progress:
                    on_progress(min(plan.consumed(), reportable) if reportable else row_count,
                                row_count)
        flush()
        connection.commit()
    finally:
        connection.close()

    if on_progress:
        on_progress(reportable or row_count, row_count)

    now = datetime.now(timezone.utc)
    info = DatasetInfo(
        id=dataset_id,
        name=assigned,
        source_path=str(path.expanduser().resolve()),
        created_at=now.isoformat(),
        expires_at=(now + timedelta(hours=max(0.01, ttl_hours))).isoformat(),
        row_count=row_count,
        column_count=width,
        source_bytes=total_bytes,
        ragged_rows=ragged,
        columns=plan.column_names,
    )
    _register(info, home)
    return info


def load_records(
    source: Path,
    *,
    name: str = "",
    ttl_hours: float = DEFAULT_TTL_HOURS,
    file_format: str = "",
    array_path: str = "",
    sheet: str = "",
    flatten_depth: int = 2,
    has_header: bool = True,
    home: Path | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> DatasetInfo:
    """Load a JSON, NDJSON, XLSX, PCAP, Burp export, registry hive, or SQLite/text backup file.

    Records need not agree on their keys: the columns are the union of the keys
    seen in the first sample, and a key that only turns up later is skipped
    rather than aborting a load that is already gigabytes in.
    """

    from .readers import collect_columns, open_records

    path = source.expanduser()
    if not path.is_file():
        raise TacuError(f"No such file: {path}")
    total_bytes = path.stat().st_size
    if total_bytes == 0:
        raise TacuError(f"{path.name} is empty.")

    stream = open_records(path, file_format=file_format, array_path=array_path,
                          sheet=sheet, depth=flatten_depth, has_header=has_header)
    source_names, sample = collect_columns(stream.records)
    if not source_names:
        raise TacuError(f"{path.name} produced no records to load.")
    if len(source_names) > MAX_COLUMNS:
        raise TacuError(
            f"{path.name} flattens to {len(source_names)} columns; the limit is {MAX_COLUMNS}. "
            "Load it with --depth 1 to keep nested objects as JSON text instead."
        )

    used: set[str] = set()
    column_names = [_identifier(value, used) for value in source_names]
    affinities = [
        _infer_affinity([record.get(key) for record in sample])
        for key in source_names
    ]

    def as_row(record: dict[str, Any]) -> list[Any]:
        return [record.get(key) for key in source_names]

    dataset_id = uuid.uuid4().hex
    target = datasets_home(home) / f"{dataset_id}.db"
    target.unlink(missing_ok=True)

    plan = _RowPlan(
        source_names=list(source_names),
        column_names=column_names,
        affinities=affinities,
        sample_rows=[as_row(record) for record in sample],
        rows=(as_row(record) for record in stream.records),
        consumed=stream.consumed,
    )
    return _build_store(
        path, plan, dataset_id=dataset_id, target=target, name=name, ttl_hours=ttl_hours,
        home=home, on_progress=on_progress, total_bytes=total_bytes,
        progress_total=0 if stream.kind == "xlsx" else total_bytes,
    )


def load_any(
    source: Path,
    *,
    file_format: str = "",
    delimiter: str | None = None,
    has_header: bool | None = None,
    array_path: str = "",
    sheet: str = "",
    flatten_depth: int = 2,
    **kwargs: Any,
) -> DatasetInfo:
    """Load a file of any supported format, choosing the reader by looking at it."""

    from .readers import detect_format

    path = source.expanduser()
    if not path.is_file():
        raise TacuError(f"No such file: {path}")
    kind = file_format or detect_format(path)
    if kind == "csv":
        return load_csv(path, delimiter=delimiter, has_header=has_header, **kwargs)
    return load_records(
        path, file_format=kind, array_path=array_path, sheet=sheet,
        flatten_depth=flatten_depth, has_header=True if has_header is None else has_header,
        **kwargs,
    )


def _register(info: DatasetInfo, home: Path | None = None) -> None:
    import json

    with _catalog(home) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO datasets VALUES (?,?,?,?,?,?,?,?,?,?)",
            (info.id, info.name, info.source_path, info.created_at, info.expires_at,
             info.row_count, info.column_count, info.source_bytes, info.ragged_rows,
             json.dumps(info.columns)),
        )
        connection.commit()


def _readonly_connection(info: DatasetInfo, home: Path | None = None) -> sqlite3.Connection:
    path = datasets_home(home) / f"{info.id}.db"
    if not path.is_file():
        raise TacuError(f"Dataset {info.name} is missing its store; reload the file.")
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def profile_dataset(info: DatasetInfo, home: Path | None = None) -> DatasetProfile:
    """Summarise every column so a person can see the shape without reading rows."""

    connection = _readonly_connection(info, home)
    try:
        meta = connection.execute(
            "SELECT position, name, source_name, affinity FROM tacu_columns ORDER BY position"
        ).fetchall()
        columns: list[ColumnProfile] = []
        for _, name, source_name, affinity in meta:
            quoted = f'"{name}"'
            non_null, distinct, minimum, maximum = connection.execute(
                f"SELECT COUNT({quoted}), COUNT(DISTINCT {quoted}), MIN({quoted}), MAX({quoted}) "
                f"FROM {TABLE_NAME}"
            ).fetchone()
            samples = [
                str(row[0]) for row in connection.execute(
                    f"SELECT DISTINCT {quoted} FROM {TABLE_NAME} "
                    f"WHERE {quoted} IS NOT NULL LIMIT 3"
                ).fetchall()
            ]
            columns.append(ColumnProfile(
                name=name, source_name=source_name, affinity=affinity,
                non_null=int(non_null or 0), distinct=int(distinct or 0),
                minimum="" if minimum is None else str(minimum),
                maximum="" if maximum is None else str(maximum),
                samples=samples,
            ))
    finally:
        connection.close()
    return DatasetProfile(info=info, columns=columns)


def guard_sql(sql: str) -> str:
    """Accept a single read-only SELECT and nothing else.

    The connection is already opened read-only, so this is defence in depth: it
    turns a confusing SQLite error into a clear refusal.
    """

    text = (sql or "").strip().rstrip(";").strip()
    if not text:
        raise TacuError('Write a query. Example: ti data query NAME "SELECT * FROM data LIMIT 5"')
    if ";" in text:
        raise TacuError("Run one statement at a time; ';' is not allowed.")
    stripped = re.sub(r"--[^\n]*", " ", text)
    stripped = re.sub(r"/\*.*?\*/", " ", stripped, flags=re.S)
    if not re.match(r"^\s*(select|with)\b", stripped, re.IGNORECASE):
        raise TacuError("Only SELECT queries are allowed on a dataset.")
    found = _SQL_FORBIDDEN.search(stripped)
    if found:
        raise TacuError(f"{found.group(0).upper()} is not allowed on a dataset; queries are read-only.")
    return text


def _deny_writes(action: int, arg1: str | None, arg2: str | None,
                 database: str | None, trigger: str | None) -> int:
    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ}
    if action == sqlite3.SQLITE_FUNCTION:
        return sqlite3.SQLITE_DENY if (arg2 or "").lower() == "load_extension" else sqlite3.SQLITE_OK
    return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY


def run_query(
    info: DatasetInfo,
    sql: str,
    *,
    limit: int = QUERY_ROW_LIMIT,
    timeout: float = QUERY_TIMEOUT_SECONDS,
    home: Path | None = None,
) -> tuple[list[str], list[tuple[Any, ...]], bool]:
    """Run one guarded SELECT. Returns (columns, rows, truncated)."""

    statement = guard_sql(sql)
    connection = _readonly_connection(info, home)
    deadline = time.monotonic() + timeout
    try:
        connection.set_authorizer(_deny_writes)
        connection.set_progress_handler(
            lambda: 1 if time.monotonic() > deadline else 0, 10_000)
        try:
            cursor = connection.execute(statement)
            rows = cursor.fetchmany(limit + 1)
        except sqlite3.OperationalError as error:
            note = str(error)
            if "interrupted" in note.lower():
                raise TacuError(f"Query exceeded {timeout:.0f}s and was stopped.") from error
            if "not authorized" in note.lower():
                raise TacuError("That query is not permitted; datasets are read-only.") from error
            raise TacuError(f"SQL error: {note}") from error
        columns = [description[0] for description in (cursor.description or [])]
    finally:
        connection.set_progress_handler(None, 0)
        connection.close()
    truncated = len(rows) > limit
    return columns, list(rows[:limit]), truncated


def head_rows(info: DatasetInfo, count: int = 20, home: Path | None = None
              ) -> tuple[list[str], list[tuple[Any, ...]], bool]:
    names = set(info.columns)
    if "req_headers" in names or "form" in names:
        chosen = [column for column in _BURP_HEAD if column in names]
        if chosen:
            quoted = ", ".join(f'"{column}"' for column in chosen)
            return run_query(info, f"SELECT {quoted} FROM {TABLE_NAME}",
                             limit=max(1, count), home=home)
    return run_query(info, f"SELECT * FROM {TABLE_NAME}", limit=max(1, count), home=home)


def search_rows(info: DatasetInfo, needle: str, *, limit: int = 50, home: Path | None = None
                ) -> tuple[list[str], list[tuple[Any, ...]], bool]:
    """Find rows where any column contains the text. No index needed for a scan."""

    if not (needle or "").strip():
        raise TacuError('Give some text to search for. Example: ti data search NAME "timeout"')
    quoted = " OR ".join(f'CAST("{column}" AS TEXT) LIKE ?' for column in info.columns)
    if not quoted:
        raise TacuError(f"Dataset {info.name} has no columns to search.")
    connection = _readonly_connection(info, home)
    try:
        connection.set_authorizer(_deny_writes)
        cursor = connection.execute(
            f"SELECT * FROM {TABLE_NAME} WHERE {quoted} LIMIT ?",
            [f"%{needle}%"] * len(info.columns) + [limit + 1],
        )
        rows = cursor.fetchall()
        columns = [description[0] for description in (cursor.description or [])]
    finally:
        connection.close()
    return columns, rows[:limit], len(rows) > limit


_COLUMN_JUICY_HINTS = (
    "pass", "user", "email", "token", "secret", "key", "auth", "cookie",
    "phone", "pan", "aadhaar", "otp", "session", "api",
)
_JUICY_SELECT = (
    "item", "packet", "time", "method", "url", "status", "host", "location", "form", "juicy",
)
JUICY_SCAN_ROWS = 10_000


def _hint_column(name: str) -> bool:
    folded = name.casefold()
    return any(word in folded for word in _COLUMN_JUICY_HINTS)


def _row_where(columns: Sequence[str], row: Sequence[Any]) -> str:
    names = {name.casefold(): index for index, name in enumerate(columns)}
    parts: list[str] = []
    for key, label in (("packet", "packet"), ("item", "item"), ("frame", "packet")):
        if key not in names:
            continue
        value = row[names[key]]
        if value in (None, "", 0, "0"):
            continue
        text = str(value).strip()
        if text:
            parts.append(f"{label} {text}")
    place = ""
    for key in ("url", "time", "id", "path", "host"):
        if key not in names:
            continue
        value = row[names[key]]
        if value is not None and str(value).strip():
            place = str(value).strip()
            break
    if not place and row and not parts:
        place = str(row[0])
    if parts and place:
        return " · ".join(parts + [place])
    if parts:
        return " · ".join(parts)
    return place


def _column_key(name: str) -> str:
    return re.sub(r"\W+", "_", (name or "").strip()).strip("_").casefold()


def _named_column(names: Sequence[str], *aliases: str) -> str | None:
    index = {_column_key(item): item for item in names}
    for alias in aliases:
        found = index.get(_column_key(alias))
        if found:
            return found
    return None


def _findings_table_columns(names: Sequence[str]) -> tuple[str, str, str | None, str | None, str | None] | None:
    """True when this store is a ti juicy extract (kind + value), not a raw dump."""

    kind_col = _named_column(names, "kind")
    value_col = _named_column(names, "value")
    if not kind_col or not value_col:
        return None
    if _named_column(names, "juicy"):
        return None
    conf_col = _named_column(names, "confidence")
    where_col = _named_column(names, "where", "source file", "source_file", "url", "path")
    line_col = _named_column(
        names, "source file line number", "source_file_line_number", "line",
    )
    return kind_col, value_col, conf_col, where_col, line_col


def filter_juicy(info: DatasetInfo, *, limit: int = 100, home: Path | None = None,
                 kinds: frozenset[str] | None = None,
                 needles: Sequence[str] = (),
                 ) -> tuple[list[str], list[tuple[Any, ...]], bool, str]:
    """Analyst view of juicy values — clear text, never redacted.

    A `ti juicy` extract (kind + value columns) is read as-is. Burp tables use
    the `juicy` column. Other files are scanned with detect_juicy plus columns
    whose names look like credentials.
    `kinds` restricts hits to those kinds. `needles` keep matching values.
    """

    names = list(info.columns)
    if "juicy" in names:
        chosen = [column for column in _JUICY_SELECT if column in names]
        if "juicy" not in chosen:
            chosen.append("juicy")
        quoted = ", ".join(f'"{column}"' for column in chosen)
        columns, rows, truncated = run_query(
            info,
            f'SELECT {quoted} FROM {TABLE_NAME} '
            f'WHERE juicy IS NOT NULL AND TRIM(CAST(juicy AS TEXT)) != ""',
            limit=limit if not needles else JUICY_SCAN_ROWS, home=home,
        )
        if needles:
            kept = [
                row for row in rows
                if value_matches_needles(
                    " ".join("" if cell is None else str(cell) for cell in row), needles,
                )
            ]
            return columns, kept[:limit], truncated or len(kept) > limit, "juicy column"
        return columns, rows, truncated, "juicy column"
    inventory = _findings_table_columns(names)
    if inventory:
        kind_col, value_col, conf_col, where_col, line_col = inventory
        packet_col = _named_column(names, "packet")
        item_col = _named_column(names, "item")
        select = [kind_col, value_col]
        for extra in (conf_col, where_col, line_col, packet_col, item_col):
            if extra and extra not in select:
                select.append(extra)
        quoted = ", ".join(f'"{column}"' for column in select)
        columns, rows, _ = run_query(
            info, f"SELECT {quoted} FROM {TABLE_NAME}",
            limit=JUICY_SCAN_ROWS, home=home,
        )
        positions = {name: index for index, name in enumerate(columns)}
        found: list[tuple[Any, ...]] = []
        for row in rows:
            kind = "" if row[positions[kind_col]] is None else str(row[positions[kind_col]]).strip()
            value = "" if row[positions[value_col]] is None else str(row[positions[value_col]]).strip()
            if not kind or not value:
                continue
            if kinds and not kind_matches_query(kind, kinds):
                continue
            if needles and not value_matches_needles(value, needles):
                continue
            confidence = "high"
            if conf_col is not None:
                raw = row[positions[conf_col]]
                confidence = "high" if raw is None else str(raw).strip() or "high"
            place_parts: list[str] = []
            if where_col is not None and row[positions[where_col]] not in (None, ""):
                place_parts.append(str(row[positions[where_col]]).strip())
            if line_col is not None and row[positions[line_col]] not in (None, ""):
                place_parts.append(f"line {row[positions[line_col]]}")
            if packet_col is not None and row[positions[packet_col]] not in (None, "", 0, "0"):
                place_parts.append(f"packet {row[positions[packet_col]]}")
            if item_col is not None and row[positions[item_col]] not in (None, "", 0, "0"):
                place_parts.append(f"item {row[positions[item_col]]}")
            found.append((" · ".join(place_parts), kind, value, confidence))
            if len(found) >= limit:
                break
        truncated = len(found) >= limit
        return ["where", "kind", "value", "confidence"], found[:limit], truncated, "findings table"
    columns, rows, _ = run_query(
        info, f"SELECT * FROM {TABLE_NAME}", limit=JUICY_SCAN_ROWS, home=home)
    found: list[tuple[Any, ...]] = []
    seen: set[tuple[str, str, str]] = set()
    hint_indexes = [index for index, name in enumerate(columns) if _hint_column(name)]
    allowed = kinds
    for row in rows:
        where = _row_where(columns, row)
        for index in hint_indexes:
            value = "" if row[index] is None else str(row[index]).strip()
            if not value:
                continue
            col_kind = columns[index]
            if allowed and not kind_matches_query(col_kind, allowed):
                continue
            if needles and not value_matches_needles(value, needles):
                continue
            mark = (where, col_kind, value)
            if mark in seen:
                continue
            seen.add(mark)
            found.append((where, col_kind, value, "high"))
        blob = "\n".join("" if cell is None else str(cell) for cell in row)
        for item in detect_juicy(blob):
            if allowed:
                if not kind_matches_query(item.kind, allowed):
                    continue
            elif item.kind not in HIGH_JUICY_KINDS:
                continue
            if needles and not value_matches_needles(item.value, needles):
                continue
            mark = (where, item.kind, item.value)
            if mark in seen:
                continue
            seen.add(mark)
            found.append((where, item.kind, item.value, item.confidence))
        if len(found) >= limit:
            break
    truncated = len(found) >= limit
    return ["where", "kind", "value", "confidence"], found[:limit], truncated, "scan"


def iter_rows(info: DatasetInfo, home: Path | None = None) -> Iterator[tuple[Any, ...]]:
    connection = _readonly_connection(info, home)
    try:
        yield from connection.execute(f"SELECT * FROM {TABLE_NAME}")
    finally:
        connection.close()


_SRC_FLOW = {"src", "src_port", "src_name"}
_DST_FLOW = {"dst", "dst_port", "dst_name"}
_BURP_HEAD = (
    "item", "burp_id", "time", "method", "url", "status", "host", "host_ip", "location", "form", "juicy",
)


def _cell_text(value: Any) -> str:
    """One display line: HTTP/2 headers contain CR/LF inside the first 18 characters."""

    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _full_width_column(name: str) -> bool:
    """Analyst-facing secret columns are never ellipsized in a table."""

    folded = (name or "").casefold().replace(" ", "_")
    if folded in {"value", "juicy"}:
        return True
    return _hint_column(name)


def format_table(columns: Sequence[str], rows: Sequence[Sequence[Any]], *,
                 width: int = 18, color: bool | None = None) -> str:
    """Render a small result set as aligned text.

    Packet-capture columns src / src_port / src_name are sage; dst / dst_port /
    dst_name are dusty rose. Alignment uses the plain text width, so ANSI codes
    do not shift the table. Pass color=False when the table is for a model or a file.
    Columns that hold secrets (`value`, `juicy`, password/token/…) keep their full
    text — a 28-character cap must not hide a bearer token.
    """

    if not columns:
        return "(no columns)"
    if color is None:
        color = color_enabled()
    cells = [[_cell_text(value) for value in row] for row in rows]
    widths: list[int] = []
    for index, column in enumerate(columns):
        natural = max(len(column), *(len(row[index]) for row in cells)) if cells else len(column)
        widths.append(natural if _full_width_column(column) else min(width, natural))
    output = io.StringIO()

    names = {column.casefold(): index for index, column in enumerate(columns)}

    def tint(name: str, text: str, row: Sequence[str], *, is_header: bool = False) -> str:
        key = name.casefold()
        if key in _SRC_FLOW:
            return paint(text, PALETTE.src, enabled=True)
        if key in _DST_FLOW:
            return paint(text, PALETTE.dst, enabled=True)
        if is_header:
            return text
        if key == "kind":
            return paint(text, juicy_ansi(text.strip()), enabled=True)
        if key == "value":
            kind = row[names["kind"]].strip() if "kind" in names else ""
            conf = row[names["confidence"]].strip() if "confidence" in names else "high"
            return paint(text, juicy_ansi(kind, confidence=conf), enabled=True)
        if key == "juicy":
            return colorize_output(text, enabled=True)
        if key == "confidence":
            rank = text.strip().casefold()
            shade = PALETTE.juicy_secret if rank == "critical" else (
                PALETTE.juicy_auth if rank == "high" else (
                    PALETTE.juicy_id if rank == "medium" else PALETTE.muted))
            return paint(text, shade, enabled=True)
        return text

    def line(values: Sequence[str], *, is_header: bool = False) -> str:
        parts = []
        for index, value in enumerate(values):
            text = value if len(value) <= widths[index] else value[: widths[index] - 1] + "…"
            padded = text.ljust(widths[index])
            if color:
                padded = tint(columns[index], padded, values, is_header=is_header)
            parts.append(padded)
        return "  ".join(parts).rstrip()

    output.write(line(list(columns), is_header=True) + "\n")
    output.write("  ".join("─" * size for size in widths) + "\n")
    for row in cells:
        output.write(line(row) + "\n")
    return output.getvalue().rstrip("\n")
