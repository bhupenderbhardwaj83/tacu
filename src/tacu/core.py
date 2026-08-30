"""Persistence, command capture, evidence middleware, and juicy-info detection."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import platform
import re
import shlex
import signal
import sqlite3
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from .artifacts import save_raw_artifacts
from .companion import extract_facts
from .juicy import (
    HIGH_JUICY_KINDS, JUICY_KIND_NAMES, JuicyFinding, NativeIdTracker, REMOTE_REDACT_KINDS,
    colorize_finding, detect_juicy, juicy_ansi, wants_juicy,
    _luhn, _verhoeff, redacted_preview, secret_fingerprint,
)
from .profiles import find_profile
from .theme import PALETTE, color_enabled, paint, strip_ansi

APP_NAME = "tacu"
HISTORY_LIMIT = 100
CONTEXT_CHAR_LIMIT = 120_000
DEFAULT_MODEL = "gemma4:12b-mlx"
DEFAULT_BACKUP_MODEL = "qwen2.5-coder:7b"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_KEEP_ALIVE = "15m"
MAX_TOOL_BYTES = 500_000
TOOL_SCHEMA = "tacu.tool-result/v1"


class TacuError(RuntimeError):
    """An expected, user-facing error."""


@dataclass(frozen=True)
class Turn:
    id: int
    created_at: str
    model: str
    query: str
    response: str
    tool_result: dict[str, Any] | None


LEGACY_APP_NAME = "ticu"


def local_time_context(now: datetime | None = None) -> str:
    """Ground the model in this machine's own clock so "today" is never guessed.

    The operating system is authoritative for both the instant and the zone, so
    this stays local and never needs a network call.
    """

    current = (now or datetime.now()).astimezone()
    zone = current.strftime("%Z") or "local time"
    offset = current.strftime("%z")
    suffix = f" (UTC{offset[:3]}:{offset[3:]})" if offset else ""
    return (f"Current local date and time: {current.strftime('%A, %d %B %Y, %H:%M')} "
            f"{zone}{suffix}. This machine's clock is authoritative for the current date, "
            "time, day, and year. Use it instead of guessing from training data.")


def _data_root() -> Path:
    if platform.system() == "Windows":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    root = os.environ.get("XDG_DATA_HOME")
    return Path(root) if root else Path.home() / ".local" / "share"


def app_home() -> Path:
    override = os.environ.get("TACU_HOME")
    return Path(override).expanduser() if override else _data_root() / APP_NAME


def legacy_app_home() -> Path:
    """Where releases before the TACU rename kept their data."""
    return _data_root() / LEGACY_APP_NAME


def migrate_legacy_home() -> Path | None:
    """Move a pre-rename data directory into place once. Returns the old path if moved."""
    if os.environ.get("TACU_HOME"):
        return None
    current, legacy = app_home(), legacy_app_home()
    if current.exists() or not legacy.is_dir():
        return None
    try:
        current.parent.mkdir(parents=True, exist_ok=True)
        legacy.rename(current)
    except OSError:
        return None
    return legacy


class HistoryStore:
    """SQLite-backed store that permanently retains only the latest 100 turns."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            path.parent.chmod(0o700)
        self.connection = sqlite3.connect(path)
        if os.name != "nt":
            path.chmod(0o600)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS turns (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at TEXT NOT NULL,
              model TEXT NOT NULL,
              query TEXT NOT NULL,
              response TEXT NOT NULL,
              tool_result_json TEXT
            )"""
        )
        self.connection.commit()

    def __enter__(self) -> "HistoryStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.connection.close()

    def add(self, *, model: str, query: str, response: str, tool_result: dict[str, Any] | None) -> Turn:
        created_at = datetime.now(timezone.utc).isoformat()
        encoded = json.dumps(tool_result, ensure_ascii=False) if tool_result else None
        cursor = self.connection.execute(
            "INSERT INTO turns(created_at,model,query,response,tool_result_json) VALUES (?,?,?,?,?)",
            (created_at, model, query, response, encoded),
        )
        self.connection.execute(
            "DELETE FROM turns WHERE id NOT IN (SELECT id FROM turns ORDER BY id DESC LIMIT ?)",
            (HISTORY_LIMIT,),
        )
        self.connection.commit()
        assert cursor.lastrowid is not None
        return Turn(cursor.lastrowid, created_at, model, query, response, tool_result)

    def recent(self, limit: int = HISTORY_LIMIT) -> list[Turn]:
        rows = self.connection.execute(
            "SELECT id,created_at,model,query,response,tool_result_json FROM "
            "(SELECT * FROM turns ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
            (max(0, min(limit, HISTORY_LIMIT)),),
        ).fetchall()
        return [self._decode(row) for row in rows]

    def get(self, turn_id: int | None = None) -> Turn | None:
        fields = "id,created_at,model,query,response,tool_result_json"
        if turn_id is None:
            row = self.connection.execute(f"SELECT {fields} FROM turns ORDER BY id DESC LIMIT 1").fetchone()
        else:
            row = self.connection.execute(f"SELECT {fields} FROM turns WHERE id=?", (turn_id,)).fetchone()
        return self._decode(row) if row else None

    def search(self, query: str, *, limit: int = HISTORY_LIMIT) -> list[Turn]:
        """Filter retained turns by query, response, or model (case-insensitive LIKE)."""

        needle = (query or "").strip()
        if not needle:
            return self.recent(limit=limit)
        like = f"%{needle}%"
        rows = self.connection.execute(
            "SELECT id,created_at,model,query,response,tool_result_json FROM turns "
            "WHERE query LIKE ? COLLATE NOCASE OR response LIKE ? COLLATE NOCASE "
            "OR model LIKE ? COLLATE NOCASE "
            "ORDER BY id DESC LIMIT ?",
            (like, like, like, max(0, min(limit, HISTORY_LIMIT))),
        ).fetchall()
        return [self._decode(row) for row in reversed(rows)]

    def clear(self) -> None:
        self.connection.execute("DELETE FROM turns")
        self.connection.commit()

    @staticmethod
    def _decode(row: tuple[Any, ...]) -> Turn:
        return Turn(row[0], row[1], row[2], row[3], row[4], json.loads(row[5]) if row[5] else None)


def clean_text(data: bytes) -> tuple[str, bool, int]:
    original_size = len(data)
    truncated = original_size > MAX_TOOL_BYTES
    if truncated:
        half = MAX_TOOL_BYTES // 2
        data = data[:half] + b"\n\n[... middle omitted by tacu ...]\n\n" + data[-half:]
    text = strip_ansi(data.decode("utf-8", errors="replace"))
    text = "".join(char for char in text if char in "\n\r\t" or ord(char) >= 32)
    return text.rstrip(), truncated, original_size


def _parse_nmap_xml(text: str) -> dict[str, Any] | None:
    if not text.lstrip().startswith("<?xml") or "<nmaprun" not in text[:1000]:
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        addresses = [item.attrib for item in host.findall("address")]
        names = [item.attrib.get("name", "") for item in host.findall("hostnames/hostname")]
        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            service = port.find("service")
            ports.append({
                "protocol": port.attrib.get("protocol"),
                "port": int(port.attrib.get("portid", "0")),
                "state": state.attrib.get("state") if state is not None else None,
                "service": service.attrib if service is not None else {},
            })
        hosts.append({"addresses": addresses, "hostnames": names, "ports": ports})
    return {"type": "nmap", "hosts": hosts, "host_count": len(hosts)}


def classify_stdout(text: str, *, tool_name: str | None = None) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        return {"type": "text", "text": "", "line_count": 0}
    if tool_name == "nmap":
        parsed = _parse_nmap_xml(stripped)
        if parsed:
            return parsed
    if stripped[0] in "[{":
        try:
            return {"type": "json", "data": json.loads(stripped)}
        except json.JSONDecodeError:
            # JSON Lines is common for security tools.
            try:
                rows = [json.loads(line) for line in stripped.splitlines() if line.strip()]
                if rows:
                    return {"type": "jsonl", "rows": rows, "row_count": len(rows)}
            except json.JSONDecodeError:
                pass
    lines = stripped.splitlines()
    if 2 <= len(lines) <= 20_000:
        try:
            dialect = csv.Sniffer().sniff("\n".join(lines[:20]), delimiters=",\t;")
            rows = list(csv.reader(io.StringIO(stripped), dialect))
            width = len(rows[0])
            if width > 1 and all(len(row) == width for row in rows):
                return {"type": "table", "columns": rows[0], "rows": rows[1:], "row_count": len(rows) - 1}
        except (csv.Error, UnicodeError):
            pass
    return {"type": "text", "text": stripped, "line_count": len(lines)}


# Line-aligned block size for streaming scans. Keeps detect_juicy's per-block
# cost small: its line lookup rescans the block for every match.
JUICY_BLOCK_CHARS = 256 * 1024
# Carried between blocks so a multi-line PEM key split across a boundary is still seen.
JUICY_OVERLAP_CHARS = 8 * 1024


@dataclass(frozen=True)
class JuicyScan:
    """Result of scanning an arbitrarily large input for high-value identifiers."""

    findings: list[JuicyFinding]
    scanned_bytes: int
    scanned_lines: int
    complete: bool
    stopped_reason: str = ""


def scan_juicy_stream(
    blocks: Iterable[str],
    *,
    deadline: float | None = None,
    max_findings: int = 10_000,
    on_progress: Callable[[int, int, int], None] | None = None,
    source: str = "",
    keep: Callable[[JuicyFinding], bool] | None = None,
) -> JuicyScan:
    """Scan text of any size without holding all of it in memory.

    `blocks` yields chunks of text; they are re-cut on line boundaries so a finding
    is never split, with a small overlap so multi-line keys survive the seam.
    Returns partial results rather than dying when a deadline or cap is reached.
    `keep` filters during the scan so --grep on a large tree does not fill the cap
    with unrelated values. `source` is the file path for directory walks.
    """

    findings: list[JuicyFinding] = []
    seen: set[tuple[str, str, str]] = set()
    pending = ""
    overlap = ""
    line_offset = 0
    scanned_bytes = 0
    scanned_lines = 0
    complete = True
    reason = ""
    native = NativeIdTracker(source)

    def absorb(block: str, base_line: int) -> bool:
        """Scan one block. Returns False when the finding cap is reached."""

        native.prime(block)
        for finding in detect_juicy(block):
            stamped = replace(
                finding, line=base_line + finding.line,
                source=source or finding.source,
            )
            stamped = native.locate(stamped, block)
            if keep is not None and not keep(stamped):
                continue
            identity = (stamped.kind, stamped.value, stamped.source)
            if identity in seen:
                continue
            seen.add(identity)
            findings.append(stamped)
            if len(findings) >= max_findings:
                return False
        return True

    for chunk in blocks:
        if not chunk:
            continue
        scanned_bytes += len(chunk.encode("utf-8", errors="ignore"))
        pending += chunk
        while len(pending) >= JUICY_BLOCK_CHARS:
            cut = pending.rfind("\n", 0, JUICY_BLOCK_CHARS)
            if cut == -1:
                cut = JUICY_BLOCK_CHARS
            block, pending = pending[:cut], pending[cut:]
            # The overlap was already scanned, so its lines must not be counted twice.
            base = line_offset - overlap.count("\n")
            scanned = overlap + block
            if not absorb(scanned, base):
                return JuicyScan(findings, scanned_bytes, scanned_lines, False, "finding cap reached")
            native.advance(scanned, block[-JUICY_OVERLAP_CHARS:])
            line_offset += block.count("\n")
            scanned_lines = line_offset
            overlap = block[-JUICY_OVERLAP_CHARS:]
            if on_progress:
                on_progress(scanned_bytes, scanned_lines, len(findings))
            if deadline is not None and time.monotonic() > deadline:
                return JuicyScan(findings, scanned_bytes, scanned_lines, False, "timeout reached")

    if pending:
        base = line_offset - overlap.count("\n")
        scanned = overlap + pending
        if not absorb(scanned, base):
            complete, reason = False, "finding cap reached"
        native.advance(scanned, "")
        line_offset += pending.count("\n")
        scanned_lines = line_offset
    if on_progress:
        on_progress(scanned_bytes, scanned_lines, len(findings))
    return JuicyScan(sorted(findings, key=lambda item: (item.source, item.line, item.start)),
                     scanned_bytes, scanned_lines, complete, reason)


JUICY_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".tox", ".eggs",
    ".idea", ".vscode",
})
JUICY_SKIP_SUFFIXES = frozenset({
    ".pyc", ".pyo", ".so", ".dylib", ".o", ".a", ".png", ".jpg", ".jpeg",
    ".gif", ".webp", ".pdf", ".zip", ".gz", ".tgz", ".woff", ".woff2",
    ".exe", ".dll", ".bin", ".class", ".jar", ".7z", ".rar", ".xz",
})
JUICY_TREE_FILE_MAX = 100 * 1024 * 1024


def iter_juicy_files(root: Path, *, all_files: bool = False) -> Iterator[Path]:
    """Yield scan targets under a directory: source, config, CI, keys, dumps.

    Skips VCS, dependencies, builds, binaries, and media. Hidden files such as
    `.env` are included. Pass `all_files=True` to scan any non-binary file.
    """

    from .juicyscan import iter_scan_files
    return iter_scan_files(root, all_files=all_files)


def read_text_blocks(path: Path, *, block_chars: int = JUICY_BLOCK_CHARS) -> Iterator[str]:
    """Yield a file in bounded chunks so a 5 GB input never lands in memory."""

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        while True:
            block = handle.read(block_chars)
            if not block:
                return
            yield block


def redact_sensitive_text(text: str) -> tuple[str, int]:
    """Redact credential and PII values before evidence can reach a non-local provider."""

    pem = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.S)
    redacted, pem_count = pem.subn("[REDACTED:private-key]", text)
    findings = [item for item in detect_juicy(redacted) if item.kind in REMOTE_REDACT_KINDS]
    if not findings:
        return redacted, pem_count
    output: list[str] = []
    cursor = 0
    for finding in findings:
        if finding.start < cursor:
            continue
        output.append(redacted[cursor:finding.start])
        output.append(f"[REDACTED:{finding.kind}]")
        cursor = finding.end
    output.append(redacted[cursor:])
    return "".join(output), pem_count + len(findings)


def colorize_output(text: str, *, enabled: bool | None = None) -> str:
    """Color juicy values by family, hidden paths blue, and other paths yellow.

    Values are painted in the clear — never masked. Injection/config signals stay
    uncolored so ordinary command output is not a Christmas tree.
    """

    if enabled is None:
        enabled = color_enabled()
    if not enabled:
        return text
    # Regex highlighting on multi-megabyte dumps burns a full CPU core for no gain.
    if len(text) > 200_000:
        return text
    findings = detect_juicy(text)
    juicy_spans = [
        (item.start, item.end, juicy_ansi(item.kind, item.category, item.confidence))
        for item in findings if colorize_finding(item)
    ]
    path_pattern = re.compile(r"(?<!\w)(?:~|\.{0,2}/|[A-Za-z]:\\)[^\s:;,]+")
    spans = list(juicy_spans)
    for match in path_pattern.finditer(text):
        if any(match.start() < end and start < match.end() for start, end, _ in juicy_spans):
            continue
        parts = re.split(r"[/\\]", match.group())
        hidden = any(part.startswith(".") and part not in {".", ".."} for part in parts)
        spans.append((match.start(), match.end(), PALETTE.blue if hidden else PALETTE.yellow))
    # `ls -a` emits bare hidden names; `ls -F` emits directory names with `/`.
    for pattern, color in (
        (re.compile(r"(?<!\S)\.[A-Za-z0-9_.-]+(?:[/\\][^\s]*)?"), PALETTE.blue),
        (re.compile(r"(?<!\S)[^\s]+/(?=\s|$)"), PALETTE.yellow),
    ):
        for match in pattern.finditer(text):
            if any(match.start() < end and start < match.end() for start, end, _ in spans):
                continue
            spans.append((match.start(), match.end(), color))
    # Long-format `ls` marks directory entries with a leading `d`.
    offset = 0
    for line in text.splitlines(keepends=True):
        if re.match(r"^d[rwx-]{9}\s", line):
            name_match = re.search(r"(\S+)\s*$", line.rstrip("\r\n"))
            if name_match:
                start, end = offset + name_match.start(1), offset + name_match.end(1)
                if not any(start < old_end and old_start < end for old_start, old_end, _ in spans):
                    name = name_match.group(1)
                    spans.append((start, end, PALETTE.blue if name.startswith(".") else PALETTE.yellow))
        offset += len(line)
    result: list[str] = []
    cursor = 0
    for start, end, color in sorted(spans):
        if start < cursor:
            continue
        result.append(text[cursor:start])
        result.append(paint(text[start:end], color, enabled=True))
        cursor = end
    result.append(text[cursor:])
    return "".join(result)


def _plugin_enrichers() -> Iterable[tuple[str, Callable[[dict[str, Any]], dict[str, Any] | None]]]:
    try:
        points = metadata.entry_points(group="tacu.middleware")
    except TypeError:  # Python 3.9 compatibility for plugin discovery.
        points = metadata.entry_points().get("tacu.middleware", [])
    for point in points:
        try:
            yield point.name, point.load()
        except Exception:
            continue


def terminal_result(*, source: str, display_command: str, stdout: bytes, stderr: bytes = b"",
                    exit_code: int | None = None, duration_ms: int | None = None,
                    cwd: str | None = None, persist_raw: bool = False,
                    raw_artifacts: dict[str, Any] | None = None) -> dict[str, Any]:
    if persist_raw and raw_artifacts is None:
        raw_artifacts = save_raw_artifacts(app_home(), stdout=stdout, stderr=stderr)
    stdout_text, stdout_truncated, stdout_bytes = clean_text(stdout)
    stderr_text, stderr_truncated, stderr_bytes = clean_text(stderr)
    profile = find_profile(display_command)
    findings = detect_juicy(stdout_text + ("\n" + stderr_text if stderr_text else ""))
    classified_stdout = classify_stdout(stdout_text, tool_name=profile.name if profile else None)
    structured = classified_stdout.get("data") if classified_stdout.get("type") == "json" else None
    facts = extract_facts(stdout_text, display_command, structured)
    result: dict[str, Any] = {
        "schema": TOOL_SCHEMA,
        "tool": "terminal",
        "status": "observed" if exit_code is None else ("success" if exit_code == 0 else "failure"),
        "invocation": {"source": source, "command": display_command, "cwd": cwd,
                       "timestamp": datetime.now(timezone.utc).isoformat()},
        "profile": ({"name": profile.name, "category": profile.category, "output_hint": profile.output_hint}
                    if profile else None),
        "result": {
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout": classified_stdout,
            "stderr": {"type": "text", "text": stderr_text, "line_count": len(stderr_text.splitlines())},
        },
        "capture": {"stdout_bytes": stdout_bytes, "stderr_bytes": stderr_bytes,
                    "stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated,
                    "max_bytes_per_stream": MAX_TOOL_BYTES, "raw_artifacts": raw_artifacts},
        "juicy": {"count": len(findings), "kinds": sorted({item.kind for item in findings})},
    }
    if facts:
        result["facts"] = facts
    plugin_data: dict[str, Any] = {}
    for name, enricher in _plugin_enrichers():
        try:
            enriched = enricher(result)
            if enriched:
                plugin_data[name] = enriched
        except Exception as error:
            plugin_data[name] = {"error": f"{type(error).__name__}: {error}"}
    if plugin_data:
        result["plugins"] = plugin_data
    return result


def display_command(command: list[str]) -> str:
    return subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command)


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Stop the complete command process group without leaving child tools behind."""

    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            if os.name == "nt":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass


def run_command(command: list[str], *, shell: bool, timeout: int, source: str = "executed-command") -> dict[str, Any]:
    if not command:
        raise TacuError("No command was provided. Example: ticu run -q 'summarize' -- nmap -sV 127.0.0.1")
    shown = " ".join(command) if shell else display_command(command)
    if shell:
        if os.name == "nt":
            invocation = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", shown]
        else:
            invocation = [os.environ.get("SHELL", "/bin/sh"), "-lc", shown]
    else:
        invocation = command
    started = time.monotonic()
    options: dict[str, Any] = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        options["start_new_session"] = True
    try:
        process = subprocess.Popen(invocation, **options)
    except FileNotFoundError as error:
        raise TacuError(f"Command not found: {command[0]}") from error
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        exit_code = process.returncode
    except subprocess.TimeoutExpired:
        _terminate_process(process)
        stdout, stderr = process.communicate()
        stderr += f"\nCommand timed out after {timeout} seconds.".encode()
        exit_code = 124
    except KeyboardInterrupt:
        _terminate_process(process)
        raise
    return terminal_result(source=source, display_command=shown, stdout=stdout, stderr=stderr,
                           exit_code=exit_code, duration_ms=round((time.monotonic()-started)*1000),
                           cwd=os.getcwd(), persist_raw=True)

def docker_command(container: str, command: list[str]) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", container):
        raise TacuError("Invalid container name or id.")
    if not command:
        raise TacuError("A container command is required. Example: ticu docker web -q 'review ports' -- ss -lntp")
    return ["docker", "exec", container, *command]


def normalized_command(command: list[str]) -> list[str]:
    return command[1:] if command and command[0] == "--" else command


def content_result(*, source: str, label: str, data: bytes,
                   raw_artifacts: dict[str, Any] | None = None) -> dict[str, Any]:
    return terminal_result(source=source, display_command=label, stdout=data,
                           persist_raw=raw_artifacts is not None, raw_artifacts=raw_artifacts)


def evidence_text(result: dict[str, Any], stream: str = "stdout") -> str:
    block = result.get("result", {}).get(stream, {})
    kind = block.get("type")
    if kind == "text":
        return str(block.get("text", ""))
    if kind == "json":
        return json.dumps(block.get("data"), ensure_ascii=False, indent=2)
    if kind == "jsonl":
        return "\n".join(json.dumps(row, ensure_ascii=False) for row in block.get("rows", []))
    if kind == "table":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(block.get("columns", [])); writer.writerows(block.get("rows", []))
        return output.getvalue().rstrip()
    return json.dumps(block, ensure_ascii=False, indent=2)


def export_findings(findings: list[JuicyFinding], output: Path, file_format: str) -> Path:
    output = output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    if file_format == "json":
        content = json.dumps({"schema": "tacu.juicy/v1", "count": len(findings),
                              "findings": [asdict(item) for item in findings]}, ensure_ascii=False, indent=2) + "\n"
    elif file_format == "csv":
        buffer = io.StringIO(); writer = csv.writer(buffer)
        writer.writerow(
            ("kind", "category", "value", "source file", "source file line number",
             "packet", "item",
             "confidence", "fingerprint", "redacted", "context")
        )
        writer.writerows(
            (item.kind, item.category, item.value, item.source, item.line,
             item.packet or "", item.item or "",
             item.confidence,
             secret_fingerprint(item.kind, item.value), redacted_preview(item.value),
             item.context)
            for item in findings
        )
        content = buffer.getvalue()
    elif file_format == "jsonl":
        content = "".join(
            json.dumps(asdict(item), ensure_ascii=False) + "\n" for item in findings
        )
    else:
        content = "\n".join(
            f"{item.kind}\t{item.value}\tsource_file={item.source}\t"
            f"source_file_line={item.line}\tpacket={item.packet or ''}\t"
            f"item={item.item or ''}\t{item.confidence}"
            for item in findings
        ) + ("\n" if findings else "")
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(output)
    return output


def fingerprint_result(result: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(result, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
