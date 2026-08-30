"""Turn JSON, NDJSON, XLSX, PCAP, Burp exports and backup files into plain records.

Every reader yields dictionaries and nothing else, so `dataset` keeps one storage
path: type inference, batched inserts, the catalog and the TTL sweep are shared by
all formats. Adding a format means adding a reader here, not a second loader.

Memory stays flat in every reader. Nothing holds the whole file:
NDJSON goes line by line, a JSON array is cut into elements by a scanner that
keeps only the current element, an XLSX sheet is pulled through iterparse, and
PCAP frames are decoded one packet at a time.
"""

from __future__ import annotations

import gzip
import json
import re
import sqlite3
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator
from xml.etree import ElementTree

from .burpread import (
    burp_project_error, iter_burp_json_value, iter_burp_xml,
    looks_like_burp_json, looks_like_burp_xml, looks_like_html, looks_like_xml,
)
from .core import TacuError
from .hiveread import is_registry_hive, iter_registry_values
from .pcapread import is_pcap_magic, iter_enriched_packets

READ_BLOCK = 256 * 1024
# Keys are collected from this many records before the table is created. A key
# that first appears after this point cannot become a column.
KEY_SAMPLE_RECORDS = 500
DEFAULT_FLATTEN_DEPTH = 2
SNIFF_BYTES = 64 * 1024

FORMATS = ("csv", "ndjson", "json", "xlsx", "pcap", "sqlite", "text", "registry", "burp")


@dataclass
class RecordStream:
    """Records from one file, plus what the reader had to decide on its own."""

    kind: str
    records: Iterator[dict[str, Any]]
    note: str = ""
    consumed: Callable[[], int] = field(default=lambda: 0)


# --------------------------------------------------------------------------- #
# format detection
# --------------------------------------------------------------------------- #

_JSON_SUFFIXES = {".json": "json", ".ndjson": "ndjson", ".jsonl": "ndjson", ".ldjson": "ndjson"}
_SHEET_SUFFIXES = {".xlsx", ".xlsm"}
_PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
_SQLITE_MAGIC = b"SQLite format 3"


def detect_format(path: Path) -> str:
    """Name the format from the extension, then confirm it by looking inside.

    Extensions lie often enough to matter: `.json` files holding one object per
    line are common, and that is NDJSON, not JSON. `.bak` is sniffed by content
    because backups are often a renamed SQLite, JSON, CSV, capture, or registry hive.
    Microsoft SQL Server backups are detected and refused with an export recipe.
    Burp `.burp` project files are refused the same way: export XML or JSON first.
    """

    suffix = path.suffix.casefold()
    if suffix in _SHEET_SUFFIXES:
        return "xlsx"
    if suffix in {".csv", ".tsv"}:
        return "csv"
    if suffix in _PCAP_SUFFIXES:
        return "pcap"

    head = _head_bytes(path, 64)
    if not head:
        raise TacuError(f"{path.name} is empty.")
    inner = _inner_magic(path, head)
    if is_pcap_magic(inner):
        return "pcap"
    if inner.startswith(_SQLITE_MAGIC):
        return "sqlite"
    if is_registry_hive(inner) or is_registry_hive(head):
        return "registry"
    if not _mostly_text(head) and _looks_mssql_backup(path, head):
        raise _mssql_backup_error(path)

    if zipfile.is_zipfile(path) and head[:2] != b"\x1f\x8b":
        try:
            with zipfile.ZipFile(path) as bundle:
                if any(entry.startswith("xl/") for entry in bundle.namelist()):
                    return "xlsx"
        except zipfile.BadZipFile:
            pass

    sample, complete = _text_sample(path, head)
    if sample is None:
        if suffix == ".burp":
            raise burp_project_error(path)
        if suffix == ".bak":
            raise TacuError(
                f"{path.name} is a backup TACU cannot unpack (not SQLite, pcap, JSON, CSV, "
                "text, or a Windows registry hive). Microsoft SQL Server .bak files are a "
                "restore stream for the SQL Server engine — export tables to CSV or JSON "
                "on the SQL host, then: ti data load FILE.csv"
            )
        raise TacuError(f"{path.name} has no readable text.")
    if not sample.strip():
        raise TacuError(f"{path.name} has no readable text.")

    if looks_like_burp_xml(sample):
        return "burp"
    if suffix in {".html", ".htm"} or looks_like_html(sample):
        return "text"
    if looks_like_xml(sample):
        raise TacuError(
            f"{path.name} is XML, but not a Burp HTTP-history or issue export. "
            "In Burp: Proxy → HTTP history → select items → Save items "
            "(any filename — extension is optional). "
            "A saved web page is HTML — load it with: ti data load FILE.html "
            "or scan it with: ti extract juicy FILE.html. Other XML is not a table."
        )
    shape = _json_shape(sample, complete=complete)
    if shape and looks_like_burp_json(sample):
        return "burp"
    if shape:
        return shape
    if suffix in _JSON_SUFFIXES:
        return _JSON_SUFFIXES[suffix]
    if suffix == ".bak" and not _looks_delimited(sample):
        return "text"
    if suffix == ".burp":
        raise burp_project_error(path)
    return "csv"


def _head_bytes(path: Path, size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def _inner_magic(path: Path, head: bytes) -> bytes:
    if head[:2] != b"\x1f\x8b":
        return head
    try:
        with gzip.open(path, "rb") as handle:
            return handle.read(64)
    except (OSError, EOFError):
        return head


_MSSQL_MARKERS = (
    b"Microsoft SQL Server",
    "Microsoft SQL Server".encode("utf-16-le"),
    b"TapeLabelHeader",
    "TapeLabelHeader".encode("utf-16-le"),
)


def _looks_mssql_backup(path: Path, head: bytes) -> bool:
    blob = head if len(head) >= 4096 else _head_bytes(path, 64 * 1024)
    return any(marker in blob for marker in _MSSQL_MARKERS)


def _mssql_backup_error(path: Path) -> TacuError:
    return TacuError(
        f"{path.name} is a Microsoft SQL Server backup, not a table dump. "
        "A .bak is a restore stream for the SQL Server engine (8 KB pages, "
        "compression, encryption) — TACU cannot open it as rows. On the SQL "
        "host export the tables you need, then load the export:\n"
        "  bcp db.dbo.MyTable out MyTable.csv -c -t, -S SERVER -T\n"
        "  ti data load MyTable.csv"
    )


def _text_sample(path: Path, head: bytes) -> tuple[str | None, bool]:
    gzipped = head[:2] == b"\x1f\x8b"
    if not gzipped and head and not _mostly_text(head):
        return None, False
    try:
        if gzipped:
            handle = gzip.open(path, "rt", encoding="utf-8-sig", errors="replace")
        else:
            handle = path.open("rt", encoding="utf-8-sig", errors="replace")
        with handle:
            sample = handle.read(SNIFF_BYTES + 1)
    except (OSError, EOFError, UnicodeError):
        return None, False
    return sample, len(sample) <= SNIFF_BYTES


def _mostly_text(head: bytes) -> bool:
    if not head:
        return False
    if b"\x00" in head[:64]:
        return False
    printable = sum(1 for byte in head if 9 <= byte <= 13 or 32 <= byte <= 126)
    return printable / len(head) >= 0.85


def _looks_delimited(sample: str) -> bool:
    lines = [line for line in sample.splitlines() if line.strip()][:5]
    if len(lines) < 2:
        return False
    for delimiter in (",", "\t", ";", "|"):
        counts = [line.count(delimiter) for line in lines]
        if min(counts) >= 1 and max(counts) - min(counts) <= 1:
            return True
    return False


def _json_shape(sample: str, *, complete: bool) -> str:
    """Decide between a JSON document and one record per line.

    Small files can simply be parsed. For large ones only the first lines are
    available, and the final line of a sample is usually cut off, so it is not
    allowed to influence the decision.
    """

    if complete:
        try:
            whole = json.loads(sample)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(whole, list):
                return "json"
            if isinstance(whole, dict):
                # An object wrapping a list of records is a document; anything
                # else is most useful treated as a single record.
                return "json" if _wraps_records(whole) else "ndjson"

    lines = [line.strip().rstrip(",") for line in sample.splitlines() if line.strip()]
    judged = lines if complete else lines[:-1]
    records = []
    for line in judged[:5]:
        if not line.startswith("{"):
            records = []
            break
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records = []
            break
    if records:
        if len(records) == 1 and _wraps_records(records[0]):
            return "json"
        return "ndjson"

    stripped = sample.lstrip()
    return "json" if stripped[:1] in ("[", "{") else ""


def _wraps_records(value: dict[str, Any]) -> bool:
    """True when some key holds a list of objects — the usual API-export shape."""

    return any(isinstance(item, list) and item and isinstance(item[0], dict)
               for item in value.values())


# --------------------------------------------------------------------------- #
# flattening
# --------------------------------------------------------------------------- #

def flatten(record: Any, *, depth: int = DEFAULT_FLATTEN_DEPTH) -> dict[str, Any]:
    """Turn one nested record into flat columns, keeping what will not fit as JSON.

    Nested objects become dotted columns while `depth` allows it. Lists, and
    anything deeper, are stored as JSON text — SQLite's json_extract can still
    reach inside them, which is far better than inventing hundreds of sparse
    columns for a document that has no single tabular shape.
    """

    if not isinstance(record, dict):
        return {"value": _scalar(record)}
    flat: dict[str, Any] = {}
    _walk(record, "", max(1, depth), flat)
    return flat


def _walk(node: dict[str, Any], prefix: str, remaining: int, out: dict[str, Any]) -> None:
    for key, value in node.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict) and remaining > 1 and value:
            _walk(value, name, remaining - 1, out)
        elif isinstance(value, (dict, list)):
            out[name] = json.dumps(value, ensure_ascii=False)
        else:
            out[name] = _scalar(value)


def _scalar(value: Any) -> Any:
    if value is None or isinstance(value, (int, float, str)):
        return value
    if isinstance(value, bool):
        return int(value)
    return json.dumps(value, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# PCAP
# --------------------------------------------------------------------------- #

def read_pcap(path: Path) -> RecordStream:
    """One row per packet, with src_name/dst_name from DNS, SNI, and Host in the file."""

    state = {"bytes": path.stat().st_size}

    def records() -> Iterator[dict[str, Any]]:
        yield from iter_enriched_packets(path)

    return RecordStream("pcap", records(), "one row per captured packet", lambda: state["bytes"])


# --------------------------------------------------------------------------- #
# SQLite backup (.db, .bak of a SQLite file)
# --------------------------------------------------------------------------- #

def read_sqlite(path: Path, *, depth: int = DEFAULT_FLATTEN_DEPTH) -> RecordStream:
    """Each table row becomes a record, with a `table` column naming the source."""

    head = _head_bytes(path, 16)
    if head[:2] == b"\x1f\x8b":
        raise TacuError(
            f"{path.name} is a gzipped SQLite backup. Decompress it first, then: "
            f"ti data load {path.with_suffix('')}"
        )
    state = {"bytes": path.stat().st_size}

    def records() -> Iterator[dict[str, Any]]:
        uri = path.resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            connection.row_factory = sqlite3.Row
            tables = [
                name for (name,) in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            if not tables:
                raise TacuError(f"{path.name} is a SQLite file with no tables to load.")
            for table in tables:
                quoted = '"' + table.replace('"', '""') + '"'
                try:
                    rows = connection.execute(f"SELECT * FROM {quoted}")
                except sqlite3.Error:
                    continue
                for row in rows:
                    record = {"table": table}
                    for key in row.keys():
                        record[str(key)] = _sqlite_cell(row[key])
                    yield flatten(record, depth=depth)
        finally:
            connection.close()

    return RecordStream("sqlite", records(), "one row per SQLite table row", lambda: state["bytes"])


def _sqlite_cell(value: Any) -> Any:
    if isinstance(value, bytes):
        preview = value[:80]
        text = preview.decode("utf-8", errors="replace")
        if _mostly_text(preview):
            return text + ("…" if len(value) > 80 else "")
        return preview.hex() + ("…" if len(value) > 80 else "")
    return value


# --------------------------------------------------------------------------- #
# Line-oriented text backups
# --------------------------------------------------------------------------- #

def read_text(path: Path) -> RecordStream:
    """One row per line — useful for renamed log or dump `.bak` files."""

    state = {"bytes": 0}

    def records() -> Iterator[dict[str, Any]]:
        gzipped = _head_bytes(path, 2) == b"\x1f\x8b"
        if gzipped:
            handle = gzip.open(path, "rt", encoding="utf-8-sig", errors="replace")
        else:
            handle = path.open("rt", encoding="utf-8-sig", errors="replace")
        with handle:
            for number, line in enumerate(handle, 1):
                state["bytes"] += len(line)
                yield {"line": number, "text": line.rstrip("\n")}

    return RecordStream("text", records(), "one row per line", lambda: state["bytes"])


def read_registry(path: Path) -> RecordStream:
    """One row per registry value (key, name, type, data)."""

    state = {"bytes": path.stat().st_size}

    def records() -> Iterator[dict[str, Any]]:
        yield from iter_registry_values(path)

    return RecordStream("registry", records(), "one row per registry value",
                        lambda: state["bytes"])


def read_burp(path: Path) -> RecordStream:
    """One row per HTTP item from a Burp XML export or JSON dump."""

    head = _head_bytes(path, 64)
    sample, complete = _text_sample(path, head)
    state = {"bytes": 0}

    def records() -> Iterator[dict[str, Any]]:
        if sample and looks_like_burp_xml(sample):
            yield from iter_burp_xml(path)
            return
        produced = False
        shape = _json_shape(sample or "", complete=complete) if sample else ""
        ndjson = shape == "ndjson" or (
            (sample or "").lstrip().startswith("{") and "\n{" in (sample or "")[:4000]
        )
        if ndjson:
            with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
                for line in handle:
                    state["bytes"] += len(line)
                    text = line.strip().rstrip(",")
                    if not text:
                        continue
                    try:
                        value = json.loads(text)
                    except json.JSONDecodeError:
                        continue
                    for record in iter_burp_json_value(value):
                        produced = True
                        yield record
            if produced:
                return
        if (sample or "").lstrip().startswith("["):
            scanner = _ArrayScanner()
            for block in _blocks(path):
                state["bytes"] += len(block)
                for value in scanner.feed(block):
                    for record in iter_burp_json_value(value):
                        produced = True
                        yield record
            if produced:
                return
        if path.stat().st_size > 64 * 1024 * 1024:
            raise TacuError(
                f"{path.name} is too large to read as one JSON document. "
                "Dump NDJSON (one item per line), or Save items as XML."
            )
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        state["bytes"] = len(text)
        value = json.loads(text)
        yield from iter_burp_json_value(value)

    return RecordStream("burp", records(), "one row per HTTP item",
                        lambda: state["bytes"] or path.stat().st_size)


# --------------------------------------------------------------------------- #
# NDJSON
# --------------------------------------------------------------------------- #

def read_ndjson(path: Path, *, depth: int = DEFAULT_FLATTEN_DEPTH,
                strict: bool = False) -> RecordStream:
    """One JSON value per line. Streams to any file size."""

    state = {"bytes": 0, "skipped": 0}
    # A pretty-printed document has no valid JSON on any single line, so it is
    # re-read as one value. Bounded, because this is the one non-streaming path.
    WHOLE_FILE_LIMIT = 64 * 1024 * 1024

    def records() -> Iterator[dict[str, Any]]:
        produced = 0
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for number, line in enumerate(handle, 1):
                state["bytes"] += len(line)
                text = line.strip().rstrip(",")
                if not text or text in "[]":
                    continue
                try:
                    value = json.loads(text)
                except json.JSONDecodeError as error:
                    if strict:
                        raise TacuError(
                            f"{path.name} line {number} is not valid JSON: {error.msg}") from error
                    state["skipped"] += 1
                    continue
                produced += 1
                yield flatten(value, depth=depth)
        if produced:
            return
        if path.stat().st_size > WHOLE_FILE_LIMIT:
            raise TacuError(
                f"{path.name} is not one JSON record per line, and is too large to read whole. "
                "Convert it to one record per line, or name the array with --path KEY."
            )
        whole = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
        for value in (whole if isinstance(whole, list) else [whole]):
            yield flatten(value, depth=depth)

    note = "one JSON record per line"
    return RecordStream("ndjson", records(), note, lambda: state["bytes"])


# --------------------------------------------------------------------------- #
# JSON — incremental array scanner
# --------------------------------------------------------------------------- #

# Structural characters, found in bulk so whole runs of ordinary text are copied
# in one slice instead of one character at a time.
_OUTSIDE_STRING = re.compile(r'["\[\]{},]')
_INSIDE_STRING = re.compile(r'["\\]')


def _blocks(path: Path, size: int = READ_BLOCK) -> Iterator[str]:
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        while True:
            block = handle.read(size)
            if not block:
                return
            yield block


class _ArrayScanner:
    """Cut a JSON array into its elements without holding the whole array.

    The standard library has no streaming JSON parser, so this tracks nesting
    depth and string state to find element boundaries, then hands each element
    to `json.loads` on its own. Only one element is ever in memory.
    """

    def __init__(self) -> None:
        self.depth = 0
        self.in_string = False
        self.pending_escape = False
        self.buffer: list[str] = []
        self.finished = False

    def feed(self, block: str) -> Iterator[Any]:
        position = 0
        length = len(block)
        while position < length and not self.finished:
            if self.pending_escape:
                self.buffer.append(block[position])
                self.pending_escape = False
                position += 1
                continue

            pattern = _INSIDE_STRING if self.in_string else _OUTSIDE_STRING
            match = pattern.search(block, position)
            if match is None:
                # No structural character left: copy the remainder in one go.
                if self.depth:
                    self.buffer.append(block[position:])
                return
            start = match.start()
            if self.depth and start > position:
                self.buffer.append(block[position:start])
            character = match.group()
            position = match.end()

            if self.in_string:
                self.buffer.append(character)
                if character == "\\":
                    if position >= length:
                        self.pending_escape = True
                    else:
                        self.buffer.append(block[position])
                        position += 1
                else:
                    self.in_string = False
                continue

            if self.depth == 0:
                # Waiting for the opening bracket of the array.
                if character == "[":
                    self.depth = 1
                else:
                    raise TacuError(
                        "Expected a JSON array of records. "
                        "Use --path KEY when the records sit under a key.")
                continue

            if character == '"':
                self.in_string = True
                self.buffer.append(character)
            elif character in "[{":
                self.depth += 1
                self.buffer.append(character)
            elif character in "]}":
                self.depth -= 1
                if self.depth == 0:
                    element = self._take()
                    if element is not None:
                        yield element
                    self.finished = True
                    return
                self.buffer.append(character)
            elif character == ",":
                if self.depth == 1:
                    element = self._take()
                    if element is not None:
                        yield element
                else:
                    self.buffer.append(character)

    def _take(self) -> Any:
        text = "".join(self.buffer).strip()
        self.buffer.clear()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError as error:
            preview = text[:60].replace("\n", " ")
            raise TacuError(f"Could not read a JSON record near {preview!r}: {error.msg}") from error


def _skip_to_array(blocks: Iterator[str], wanted: str) -> tuple[Iterator[str], str]:
    """Position the stream just after the '[' of the array holding the records.

    A top-level object such as {"items": [...]} is the usual shape of an API
    export, so the array is found by key rather than refused.
    """

    buffered = ""
    key_pattern = re.compile(r'"((?:[^"\\]|\\.)*)"\s*:\s*(.)', re.S)
    for block in blocks:
        buffered += block
        stripped = buffered.lstrip()
        if stripped[:1] == "[":
            offset = buffered.index("[") + 1
            return _prepend(buffered[offset:], blocks), ""
        if stripped[:1] and stripped[0] != "{":
            raise TacuError("Expected a JSON array or object at the top level.")
        for match in key_pattern.finditer(buffered):
            key, following = match.group(1), match.group(2)
            if following != "[":
                continue
            if wanted and key != wanted:
                continue
            return _prepend(buffered[match.end():], blocks), key
        if len(buffered) > 8 * READ_BLOCK:
            break
    if wanted:
        raise TacuError(f'No array found under the key "{wanted}".')
    raise TacuError(
        "No array of records found near the start of the file. "
        "Name it with --path KEY, or convert to one record per line.")


def _prepend(head: str, rest: Iterator[str]) -> Iterator[str]:
    if head:
        yield head
    yield from rest


def read_json(path: Path, *, array_path: str = "", depth: int = DEFAULT_FLATTEN_DEPTH) -> RecordStream:
    """A JSON array of records, of any size, streamed element by element."""

    state = {"bytes": 0, "key": ""}

    def records() -> Iterator[dict[str, Any]]:
        raw = _blocks(path)

        def counted() -> Iterator[str]:
            for block in raw:
                state["bytes"] += len(block)
                yield block

        stream, key = _skip_to_array(counted(), array_path)
        state["key"] = key
        scanner = _ArrayScanner()
        scanner.depth = 1  # already inside the array
        for block in stream:
            for element in scanner.feed(block):
                yield flatten(element, depth=depth)
            if scanner.finished:
                return

    note = f'array under "{array_path}"' if array_path else "JSON array"
    return RecordStream("json", records(), note, lambda: state["bytes"])


# --------------------------------------------------------------------------- #
# XLSX
# --------------------------------------------------------------------------- #

_MAIN_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
# Number formats Excel reserves for dates and times.
_BUILTIN_DATE_FORMATS = set(range(14, 23)) | set(range(27, 37)) | set(range(45, 48)) | set(range(50, 59))
_DATE_HINT = re.compile(r"(?<!\\)[ymdhs]", re.IGNORECASE)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _column_index(reference: str) -> int:
    """'BC12' -> 54. Cell references are the only reliable way to place sparse cells."""

    letters = "".join(character for character in reference if character.isalpha())
    index = 0
    for character in letters.upper():
        index = index * 26 + (ord(character) - 64)
    return max(0, index - 1)


def sheet_names(path: Path) -> list[str]:
    with zipfile.ZipFile(path) as bundle:
        try:
            root = ElementTree.fromstring(bundle.read("xl/workbook.xml"))
        except KeyError as error:
            raise TacuError(f"{path.name} is not a readable workbook.") from error
    return [element.get("name", "") for element in root.iter(f"{_MAIN_NS}sheet")]


def _sheet_target(bundle: zipfile.ZipFile, wanted: str) -> tuple[str, str]:
    root = ElementTree.fromstring(bundle.read("xl/workbook.xml"))
    sheets = list(root.iter(f"{_MAIN_NS}sheet"))
    if not sheets:
        raise TacuError("This workbook has no sheets.")
    chosen = None
    if wanted:
        for element in sheets:
            if (element.get("name") or "").casefold() == wanted.casefold():
                chosen = element
                break
        if chosen is None:
            available = ", ".join(element.get("name", "") for element in sheets)
            raise TacuError(f'No sheet named "{wanted}". Available: {available}')
    else:
        chosen = sheets[0]

    relations = ElementTree.fromstring(bundle.read("xl/_rels/workbook.xml.rels"))
    identifier = chosen.get(f"{_REL_NS}id")
    for relation in relations:
        if relation.get("Id") == identifier:
            target = relation.get("Target", "")
            path = target[1:] if target.startswith("/") else f"xl/{target}"
            return path.replace("xl/xl/", "xl/"), chosen.get("name", "")
    raise TacuError("The workbook does not say where its sheet data lives.")


def _shared_strings(bundle: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in bundle.namelist():
        return []
    values: list[str] = []
    with bundle.open("xl/sharedStrings.xml") as handle:
        for event, element in ElementTree.iterparse(handle, events=("end",)):
            if _local(element.tag) != "si":
                continue
            values.append("".join(
                node.text or "" for node in element.iter(f"{_MAIN_NS}t")))
            element.clear()
    return values


def _date_styles(bundle: zipfile.ZipFile) -> set[int]:
    """Style indexes whose number format means the value is a date."""

    if "xl/styles.xml" not in bundle.namelist():
        return set()
    root = ElementTree.fromstring(bundle.read("xl/styles.xml"))
    custom = {}
    for element in root.iter(f"{_MAIN_NS}numFmt"):
        code = element.get("formatCode", "")
        identifier = element.get("numFmtId")
        if identifier and identifier.isdigit():
            body = re.sub(r'"[^"]*"|\[[^\]]*\]', "", code)
            custom[int(identifier)] = bool(_DATE_HINT.search(body))
    styles: set[int] = set()
    container = root.find(f"{_MAIN_NS}cellXfs")
    for position, element in enumerate(container or []):
        raw = element.get("numFmtId")
        if raw is None or not raw.isdigit():
            continue
        identifier = int(raw)
        if identifier in _BUILTIN_DATE_FORMATS or custom.get(identifier):
            styles.add(position)
    return styles


def _excel_date(serial: float, *, date1904: bool) -> str:
    """Excel stores dates as day counts, so they arrive as bare numbers."""

    origin = datetime(1904, 1, 1) if date1904 else datetime(1899, 12, 30)
    moment = origin + timedelta(days=serial)
    if abs(serial - int(serial)) < 1e-9:
        return moment.date().isoformat()
    return moment.replace(microsecond=0).isoformat(sep=" ")


def _uses_1904(bundle: zipfile.ZipFile) -> bool:
    root = ElementTree.fromstring(bundle.read("xl/workbook.xml"))
    properties = root.find(f"{_MAIN_NS}workbookPr")
    return bool(properties is not None and properties.get("date1904") in {"1", "true"})


def read_xlsx(path: Path, *, sheet: str = "", has_header: bool = True) -> RecordStream:
    """The first sheet of a workbook, or a named one, streamed row by row."""

    state = {"rows": 0, "sheet": ""}

    def records() -> Iterator[dict[str, Any]]:
        with zipfile.ZipFile(path) as bundle:
            target, chosen = _sheet_target(bundle, sheet)
            state["sheet"] = chosen
            strings = _shared_strings(bundle)
            date_styles = _date_styles(bundle)
            date1904 = _uses_1904(bundle)
            headers: list[str] = []

            with bundle.open(target) as handle:
                for event, element in ElementTree.iterparse(handle, events=("end",)):
                    if _local(element.tag) != "row":
                        continue
                    values = _row_values(element, strings, date_styles, date1904)
                    element.clear()
                    if not any(value not in (None, "") for value in values):
                        continue
                    if has_header and not headers:
                        headers = [str(value or f"column_{index + 1}")
                                   for index, value in enumerate(values)]
                        continue
                    if not headers:
                        headers = [f"column_{index + 1}" for index in range(len(values))]
                    state["rows"] += 1
                    record = {}
                    for index, value in enumerate(values):
                        key = headers[index] if index < len(headers) else f"column_{index + 1}"
                        record[key] = value
                    yield record

    note = f'sheet "{sheet}"' if sheet else "first sheet"
    return RecordStream("xlsx", records(), note, lambda: state["rows"])


def _row_values(row: Any, strings: list[str], date_styles: set[int],
                date1904: bool) -> list[Any]:
    """Read one <row>, placing sparse cells at their real column positions."""

    cells: dict[int, Any] = {}
    for cell in row.iter(f"{_MAIN_NS}c"):
        reference = cell.get("r") or ""
        position = _column_index(reference) if reference else len(cells)
        cells[position] = _cell_value(cell, strings, date_styles, date1904)
    if not cells:
        return []
    return [cells.get(index) for index in range(max(cells) + 1)]


def _cell_value(cell: Any, strings: list[str], date_styles: set[int], date1904: bool) -> Any:
    kind = cell.get("t")
    if kind == "inlineStr":
        container = cell.find(f"{_MAIN_NS}is")
        return "".join(node.text or "" for node in container.iter(f"{_MAIN_NS}t")) if container is not None else None
    node = cell.find(f"{_MAIN_NS}v")
    if node is None or node.text is None:
        return None
    raw = node.text
    if kind == "s":
        index = int(raw) if raw.isdigit() else -1
        return strings[index] if 0 <= index < len(strings) else None
    if kind == "b":
        return 1 if raw == "1" else 0
    if kind in {"str", "e"}:
        return raw
    if kind == "d":
        return raw
    style = cell.get("s")
    if style is not None and style.isdigit() and int(style) in date_styles:
        try:
            return _excel_date(float(raw), date1904=date1904)
        except (ValueError, OverflowError):
            return raw
    return raw


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #

def open_records(
    path: Path,
    *,
    file_format: str = "",
    array_path: str = "",
    sheet: str = "",
    depth: int = DEFAULT_FLATTEN_DEPTH,
    has_header: bool = True,
) -> RecordStream:
    """Pick a reader for the file and return its records."""

    kind = file_format or detect_format(path)
    if kind == "ndjson":
        return read_ndjson(path, depth=depth)
    if kind == "json":
        return read_json(path, array_path=array_path, depth=depth)
    if kind == "xlsx":
        return read_xlsx(path, sheet=sheet, has_header=has_header)
    if kind == "pcap":
        return read_pcap(path)
    if kind == "sqlite":
        return read_sqlite(path, depth=depth)
    if kind == "text":
        return read_text(path)
    if kind == "registry":
        return read_registry(path)
    if kind == "burp":
        return read_burp(path)
    raise TacuError(f"{kind} files are handled by the delimited loader, not here.")


def collect_columns(records: Iterator[dict[str, Any]], limit: int = KEY_SAMPLE_RECORDS,
                    ) -> tuple[list[str], list[dict[str, Any]]]:
    """Learn the column names from the first records, keeping them for the load.

    Records are not required to share keys, so the columns are the union of what
    the sample shows, in the order the keys first appear.
    """

    names: dict[str, None] = {}
    sample: list[dict[str, Any]] = []
    for record in records:
        sample.append(record)
        for key in record:
            names.setdefault(str(key), None)
        if len(sample) >= limit:
            break
    return list(names), sample
