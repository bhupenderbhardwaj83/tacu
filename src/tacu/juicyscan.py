"""Large-tree juicy scanning: project discovery, targeted files, JSONL, rotation.

`ti juicy DIR` walks a source-code root (many project folders) without loading it
into memory. Findings are appended to per-project JSONL as the walk runs, then
turned into per-project CSV plus MASTER_SUMMARY.csv. Report files keep values
in the clear, same as the terminal inventory and `ti juicy FILE` extracts.
A SHA-256 fingerprint is stored beside the live value for correlation.
LINE is the file line; PACKET is the Wireshark frame when known; ITEM is the
Burp history index when known — so you can jump back to the native tool.
"""

from __future__ import annotations

import csv
import fnmatch
import json
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, TextIO

from .juicy import (
    JuicyFinding,
    kind_category,
    meets_confidence,
    parse_native_int,
    secret_fingerprint,
)
from .theme import PALETTE, paint


# First-level folders under the scan root are treated as projects.
REPORTS_DIR_NAME = "_juicy_reports"
MANIFEST_NAME = "scan_manifest.json"
MASTER_SUMMARY_NAME = "MASTER_SUMMARY.csv"
ROTATION_REPORT_NAME = "ROTATION_REPORT.csv"
TERMINAL_SAMPLE = 80
PER_FILE_FINDING_CAP = 50_000
MAX_FILE_BYTES = 100 * 1024 * 1024
LOCATIONS_IN_ROTATION = 20


SKIP_DIRS = frozenset({
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "bower_components",
    "venv", ".venv", "env",
    "dist", "build", "target", "out", "bin", "obj",
    "coverage", ".cache", ".gradle", ".idea", ".vscode",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", ".eggs",
    "_juicy_reports",
})

SKIP_SUFFIXES = frozenset({
    ".class", ".jar", ".war", ".ear",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".pyc", ".pyo", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".mp3", ".mp4", ".mov",
    ".woff", ".woff2", ".ttf",
    ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".xz",
    ".pdf",
})

# Dumps and notes stay in the default walk so `ti juicy ./exports` still sees .txt/.csv.
SCAN_EXTENSIONS = frozenset({
    ".py", ".pyw",
    ".java", ".kt", ".kts", ".groovy", ".scala",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".cs", ".vb", ".fs", ".fsx",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
    ".go", ".rs",
    ".php", ".phtml",
    ".rb",
    ".pl", ".pm",
    ".swift", ".m", ".mm",
    ".dart", ".lua",
    ".r",
    ".cob", ".cbl", ".cpy",
    ".asp", ".asa",
    ".jsp", ".jspx",
    ".env", ".ini", ".cfg", ".conf", ".config", ".properties",
    ".toml", ".yaml", ".yml",
    ".json", ".json5",
    ".xml", ".plist",
    ".sql", ".ddl", ".dml",
    ".html", ".htm", ".xhtml",
    ".graphql", ".gql",
    ".http", ".rest", ".har",
    ".tf", ".tfvars", ".hcl", ".nomad",
    ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd",
    ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks", ".keystore",
    ".asc", ".gpg",
    ".csproj", ".fsproj", ".vbproj",
    ".txt", ".csv", ".log", ".md", ".rst",
})

SPECIAL_NAMES = frozenset(name.casefold() for name in (
    "dockerfile", "jenkinsfile",
    ".npmrc", ".yarnrc", ".yarnrc.yml",
    "package.json", "package-lock.json",
    "pom.xml", "settings.xml",
    "build.gradle", "gradle.properties",
    "requirements.txt", "pip.conf", ".pypirc",
    "pyproject.toml", "poetry.lock",
    "gemfile", "gemfile.lock",
    "composer.json", "composer.lock",
    "cargo.toml", "cargo.lock",
    "go.mod", "go.sum",
    "nuget.config",
    "chart.yaml", "values.yaml",
    ".gitlab-ci.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "authorized_keys",
))

SPECIAL_GLOBS = (
    "Dockerfile.*",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "values-*.yaml",
    "values-*.yml",
    ".env.*",
)


_SAFE_PROJECT = re.compile(r"[^A-Za-z0-9._-]+")

_ROTATION_RANK = {
    "private-key": 0, "aws-access-key": 0, "azure-key": 0, "google-api-key": 0,
    "db-uri": 0, "github-token": 0, "gitlab-token": 0, "basic-auth": 0,
    "password": 0, "secret-in-url": 0,
    "bearer": 1, "jwt": 1, "secret": 1, "stripe-key": 1, "slack-token": 1,
    "sendgrid-key": 1, "twilio-sid": 1, "npm-token": 1, "pypi-token": 1,
    "session-cookie": 1,
    "username": 2, "ssh-key": 2, "url": 2, "internal-host": 2,
    "debug-enabled": 2, "tls-verify-disabled": 2, "cors-wildcard": 2,
    "email": 3, "indian-phone": 3, "intl-phone": 3, "ipv4": 3, "ipv6": 3,
    "pan": 3, "aadhaar": 3, "credit-card": 3, "iban": 3, "upi": 3,
}


@dataclass
class TreeScan:
    """Outcome of walking a source-code root."""

    findings: list[JuicyFinding]
    scanned_bytes: int
    scanned_lines: int
    complete: bool
    stopped_reason: str
    reports_dir: Path
    files_scanned: int
    files_skipped: int
    files_resumed: int
    finding_count: int
    projects: list[str] = field(default_factory=list)

    def as_juicy_scan(self):
        from .core import JuicyScan
        return JuicyScan(
            self.findings, self.scanned_bytes, self.scanned_lines,
            self.complete, self.stopped_reason,
        )


def safe_project_name(name: str) -> str:
    cleaned = _SAFE_PROJECT.sub("_", (name or "root").strip()) or "root"
    return cleaned[:120]


def project_of(path: Path, root: Path) -> str:
    """First-level folder under the scan root is the project; files at the root use the root name."""

    try:
        rel = path.relative_to(root)
    except ValueError:
        return root.name or "root"
    parts = rel.parts
    if len(parts) <= 1:
        return root.name or "root"
    return parts[0]


def relative_source(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def file_in_project(rel: str, project: str) -> str:
    """Path inside the project folder (`config/application.yml`), not including the project name."""

    prefix = f"{project}/"
    if rel.startswith(prefix):
        return rel[len(prefix):]
    return rel


# Report-file confidence: 95–100 critical, 80–94 high, 60–79 medium, <60 low.
CONFIDENCE_SCORE = {"critical": 98, "high": 88, "medium": 70, "low": 45}

# Research buckets: SECRET / PII / NETWORK / SIGNAL.
_REPORT_CATEGORY = {
    "secret": "SECRET",
    "authentication": "SECRET",
    "identity": "PII",
    "financial": "PII",
    "network": "NETWORK",
    "http": "SIGNAL",
    "injection": "SIGNAL",
    "config": "SIGNAL",
}


def report_category(kind: str, category: str = "") -> str:
    family = (category or kind_category(kind) or "secret").casefold()
    return _REPORT_CATEGORY.get(family, "SECRET")


def report_confidence(level: str) -> int:
    return CONFIDENCE_SCORE.get((level or "low").casefold(), 45)


def report_severity(level: str) -> str:
    return (level or "low").upper()


def level_from_score(value: object) -> str:
    if isinstance(value, str) and value.casefold() in CONFIDENCE_SCORE:
        return value.casefold()
    try:
        score = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "low"
    if score >= 95:
        return "critical"
    if score >= 80:
        return "high"
    if score >= 60:
        return "medium"
    return "low"


def should_scan(path: Path, *, all_files: bool = False) -> bool:
    """True for source, config, CI, keys, dumps — or any non-skipped file with --all-files."""

    suffix = path.suffix.casefold()
    if suffix in SKIP_SUFFIXES:
        return False
    if all_files:
        return True
    name = path.name
    folded = name.casefold()
    if folded.startswith(".env"):
        return True
    if folded in SPECIAL_NAMES:
        return True
    if path.parent.name.casefold() == ".aws" and folded in {"credentials", "config"}:
        return True
    if any(fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(folded, pattern.casefold())
           for pattern in SPECIAL_GLOBS):
        return True
    return suffix in SCAN_EXTENSIONS


def _looks_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:8192]
    except OSError:
        return True
    return b"\x00" in sample


def iter_scan_files(
    root: Path,
    *,
    all_files: bool = False,
    max_bytes: int | None = None,
) -> Iterator[Path]:
    """Yield scan targets under root. Skips VCS, dependencies, builds, binaries, media."""

    root = root.expanduser()
    limit = MAX_FILE_BYTES if max_bytes is None else max_bytes
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if not should_scan(path, all_files=all_files):
                continue
            try:
                if not path.is_file() or path.stat().st_size > limit:
                    continue
            except OSError:
                continue
            if all_files and _looks_binary(path):
                continue
            yield path


def reports_dir_for(root: Path, output: Path | None, reports: Path | None) -> Path:
    """Where the per-project JSONL/CSV pack lands."""

    if reports is not None:
        return reports.expanduser()
    if output is not None and _looks_like_directory(output):
        return output.expanduser()
    return root.expanduser() / REPORTS_DIR_NAME


def combined_csv_for(output: Path | None) -> Path | None:
    """Optional analyst CSV next to the reports pack (`-o findings.csv`)."""

    if output is None or _looks_like_directory(output):
        return None
    return output.expanduser()


def _looks_like_directory(path: Path) -> bool:
    text = str(path)
    if text.endswith(("/", os.sep)):
        return True
    if path.exists():
        return path.is_dir()
    return path.suffix == ""


def _chmod_private(path: Path) -> None:
    if os.name != "nt" and path.exists():
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _jsonl_path(reports_dir: Path, project: str) -> Path:
    return reports_dir / f"{safe_project_name(project)}_report.jsonl"


def _csv_path(reports_dir: Path, project: str) -> Path:
    return reports_dir / f"{safe_project_name(project)}_report.csv"


def finding_record(item: JuicyFinding, *, project: str, file: str) -> dict[str, object]:
    """One JSONL row. Values stay in the clear; fingerprint correlates the same secret."""

    live = item.value
    return {
        "project": project,
        "file": file,
        "line": item.line,
        "packet": item.packet or 0,
        "item": item.item or 0,
        "detector": item.kind,
        "category": report_category(item.kind, item.category),
        "value": live,
        "confidence": report_confidence(item.confidence),
        "severity": report_severity(item.confidence),
        "context": item.context or "",
        "fingerprint": secret_fingerprint(item.kind, live),
    }


def _open_jsonl(reports_dir: Path, project: str, handles: dict[str, TextIO]) -> TextIO:
    if project not in handles:
        path = _jsonl_path(reports_dir, project)
        handles[project] = path.open("a", encoding="utf-8")
        _chmod_private(path)
    return handles[project]


def _close_handles(handles: dict[str, TextIO]) -> None:
    for handle in handles.values():
        try:
            handle.close()
        except OSError:
            pass
    handles.clear()


def _load_manifest(path: Path) -> dict[str, dict[str, int]]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    files = payload.get("files") if isinstance(payload, dict) else None
    if not isinstance(files, dict):
        return {}
    out: dict[str, dict[str, int]] = {}
    for key, meta in files.items():
        if isinstance(meta, dict) and "size" in meta and "mtime" in meta:
            out[str(key)] = {"size": int(meta["size"]), "mtime": int(meta["mtime"])}
    return out


def _save_manifest(path: Path, root: Path, files: dict[str, dict[str, int]]) -> None:
    payload = {"root": str(root), "files": files}
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _chmod_private(temporary)
    temporary.replace(path)
    _chmod_private(path)


def _file_stamp(path: Path) -> dict[str, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return {"size": stat.st_size, "mtime": int(stat.st_mtime)}


def _strip_jsonl_files(jsonl_path: Path, drop_files: set[str]) -> None:
    """Drop records for files that will be rescanned so resume does not duplicate."""

    if not jsonl_path.is_file() or not drop_files:
        return
    temporary = jsonl_path.with_suffix(".jsonl.tmp")
    kept = False
    with jsonl_path.open(encoding="utf-8") as source, temporary.open("w", encoding="utf-8") as dest:
        for line in source:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(record.get("file", "")) in drop_files:
                continue
            dest.write(line if line.endswith("\n") else line + "\n")
            kept = True
    if kept:
        temporary.replace(jsonl_path)
        _chmod_private(jsonl_path)
    else:
        temporary.unlink(missing_ok=True)
        jsonl_path.unlink(missing_ok=True)


def _iter_jsonl(path: Path) -> Iterator[dict[str, object]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def iter_report_records(reports_dir: Path) -> Iterator[dict[str, object]]:
    for path in sorted(reports_dir.glob("*_report.jsonl")):
        yield from _iter_jsonl(path)


def record_as_finding(record: dict[str, object]) -> JuicyFinding:
    kind = str(record.get("detector") or record.get("kind") or "")
    project = str(record.get("project") or "")
    path = str(record.get("file") or "")
    source = f"{project}/{path}" if project and path and not path.startswith(f"{project}/") else path
    return JuicyFinding(
        kind=kind,
        value=str(record.get("value") or ""),
        start=0,
        end=0,
        line=parse_native_int(record.get("line")),
        confidence=level_from_score(record.get("confidence")),
        category=str(record.get("category") or ""),
        source=source,
        context=str(record.get("context") or ""),
        packet=parse_native_int(record.get("packet")),
        item=parse_native_int(record.get("item")),
    )


CSV_COLUMNS = (
    "PROJECT", "FILE", "LINE", "PACKET", "ITEM", "CATEGORY", "DETECTOR", "SEVERITY",
    "CONFIDENCE", "VALUE", "CONTEXT", "SHA256_FINGERPRINT",
)


def _id_cell(value: object) -> object:
    if value in (None, "", 0, "0"):
        return ""
    return value


def _csv_row(record: dict[str, object]) -> tuple[object, ...]:
    return (
        record.get("project", ""),
        record.get("file", ""),
        record.get("line", ""),
        _id_cell(record.get("packet")),
        _id_cell(record.get("item")),
        record.get("category", ""),
        record.get("detector", ""),
        record.get("severity", ""),
        record.get("confidence", ""),
        record.get("value", ""),
        record.get("context", ""),
        record.get("fingerprint", ""),
    )


def write_project_csvs(reports_dir: Path) -> list[Path]:
    written: list[Path] = []
    for jsonl in sorted(reports_dir.glob("*_report.jsonl")):
        csv_path = jsonl.with_name(jsonl.name.replace("_report.jsonl", "_report.csv"))
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(CSV_COLUMNS)
            for record in _iter_jsonl(jsonl):
                writer.writerow(_csv_row(record))
        _chmod_private(csv_path)
        written.append(csv_path)
    return written


def write_master_summary(reports_dir: Path) -> Path:
    path = reports_dir / MASTER_SUMMARY_NAME
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for record in iter_report_records(reports_dir):
            writer.writerow(_csv_row(record))
    _chmod_private(path)
    return path


def write_rotation_report(reports_dir: Path) -> Path:
    """One row per secret identity: how many projects/files, where to rotate first."""

    groups: dict[str, dict[str, object]] = {}
    for record in iter_report_records(reports_dir):
        fingerprint = str(record.get("fingerprint") or "")
        if not fingerprint:
            continue
        bucket = groups.get(fingerprint)
        project = str(record.get("project") or "")
        file_path = str(record.get("file") or "")
        location = f"{project}/{file_path}:{record.get('line', '')}" if project else f"{file_path}:{record.get('line', '')}"
        extras = []
        packet = parse_native_int(record.get("packet"))
        item_no = parse_native_int(record.get("item"))
        if packet:
            extras.append(f"packet {packet}")
        if item_no:
            extras.append(f"item {item_no}")
        if extras:
            location = location + " · " + " · ".join(extras)
        score = int(record.get("confidence") or 0) if str(record.get("confidence", "")).isdigit() else report_confidence(str(record.get("confidence") or "low"))
        if bucket is None:
            groups[fingerprint] = {
                "detector": str(record.get("detector") or ""),
                "severity": str(record.get("severity") or ""),
                "confidence": score,
                "projects": {project} if project else set(),
                "files": {f"{project}/{file_path}" if project else file_path},
                "locations": [location],
                "count": 1,
            }
            continue
        bucket["count"] = int(bucket["count"]) + 1
        projects = bucket["projects"]
        files = bucket["files"]
        if isinstance(projects, set) and project:
            projects.add(project)
        if isinstance(files, set):
            files.add(f"{project}/{file_path}" if project else file_path)
        locations = bucket["locations"]
        if isinstance(locations, list) and len(locations) < LOCATIONS_IN_ROTATION:
            locations.append(location)
        if score > int(bucket.get("confidence") or 0):
            bucket["confidence"] = score
            bucket["severity"] = str(record.get("severity") or "")

    path = reports_dir / ROTATION_REPORT_NAME
    rows = []
    for fingerprint, bucket in groups.items():
        projects = bucket["projects"] if isinstance(bucket["projects"], set) else set()
        files = bucket["files"] if isinstance(bucket["files"], set) else set()
        locations = bucket["locations"] if isinstance(bucket["locations"], list) else []
        extra = int(bucket["count"]) - len(locations)
        place = "; ".join(str(item) for item in locations)
        if extra > 0:
            place = f"{place}; +{extra} more"
        rows.append((
            _ROTATION_RANK.get(str(bucket["detector"]), 9),
            str(bucket["detector"]),
            fingerprint,
            str(bucket["severity"]),
            len(projects),
            len(files),
            int(bucket["count"]),
            locations[0] if locations else "",
            place,
        ))
    rows.sort(key=lambda item: (item[0], -item[5], item[1], item[2]))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow((
            "SECRET_TYPE", "FINGERPRINT", "SEVERITY", "PROJECT_COUNT", "FILE_COUNT",
            "OCCURRENCES", "FIRST_LOCATION", "ALL_LOCATIONS",
        ))
        for row in rows:
            writer.writerow(row[1:])
    _chmod_private(path)
    return path


def finish_reports(reports_dir: Path) -> tuple[Path, Path, list[Path]]:
    project_csvs = write_project_csvs(reports_dir)
    master = write_master_summary(reports_dir)
    rotation = write_rotation_report(reports_dir)
    return master, rotation, project_csvs


def scan_tree(
    root: Path,
    *,
    reports_dir: Path,
    timeout: int = 0,
    keep: Callable[[JuicyFinding], bool] | None = None,
    all_files: bool = False,
    resume: bool = False,
    min_confidence: str = "low",
    on_progress: Callable[[int, int, str, int, int], None] | None = None,
) -> TreeScan:
    """Walk a source-code root, append JSONL per project, return a terminal sample."""

    root = root.expanduser()
    reports_dir = reports_dir.expanduser()
    reports_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            reports_dir.chmod(0o700)
        except OSError:
            pass

    from .core import read_text_blocks, scan_juicy_stream

    deadline = time.monotonic() + timeout if timeout and timeout > 0 else None
    manifest_path = reports_dir / MANIFEST_NAME
    previous = _load_manifest(manifest_path) if resume else {}
    next_manifest: dict[str, dict[str, int]] = dict(previous) if resume else {}
    handles: dict[str, TextIO] = {}
    sample: list[JuicyFinding] = []
    seen_sample: set[tuple[str, str, str]] = set()
    projects_seen: set[str] = set()
    scanned_bytes = 0
    scanned_lines = 0
    files_scanned = 0
    files_skipped = 0
    files_resumed = 0
    finding_count = 0
    complete = True
    reason = ""
    to_scan: list[tuple[Path, str, str, str, dict[str, int]]] = []
    drop_by_project: dict[str, set[str]] = defaultdict(set)

    for path in iter_scan_files(root, all_files=all_files):
        try:
            path.resolve().relative_to(reports_dir.resolve())
            continue
        except (ValueError, OSError):
            pass
        rel = relative_source(path, root)
        stamp = _file_stamp(path)
        if stamp is None:
            files_skipped += 1
            continue
        if resume and previous.get(rel) == stamp:
            files_resumed += 1
            continue
        project = project_of(path, root)
        inside = file_in_project(rel, project)
        to_scan.append((path, rel, project, inside, stamp))
        drop_by_project[project].add(inside)

    if resume:
        for project, drop_files in drop_by_project.items():
            _strip_jsonl_files(_jsonl_path(reports_dir, project), drop_files)
    else:
        for old in reports_dir.glob("*_report.jsonl"):
            old.unlink(missing_ok=True)

    try:
        for path, rel, project, inside, stamp in to_scan:
            if deadline is not None and time.monotonic() > deadline:
                complete, reason = False, "timeout reached"
                break
            projects_seen.add(project)
            files_scanned += 1

            def progress(done: int, lines: int, hits: int, label=rel, at=files_scanned) -> None:
                if on_progress:
                    on_progress(at, files_resumed, label, done, finding_count + hits)

            try:
                scan = scan_juicy_stream(
                    read_text_blocks(path),
                    deadline=deadline,
                    max_findings=PER_FILE_FINDING_CAP,
                    on_progress=progress,
                    source=rel,
                    keep=keep,
                )
            except OSError:
                files_skipped += 1
                continue
            scanned_bytes += scan.scanned_bytes
            scanned_lines += scan.scanned_lines
            next_manifest[rel] = stamp
            handle = _open_jsonl(reports_dir, project, handles)
            for item in scan.findings:
                if not meets_confidence(item, min_confidence):
                    continue
                handle.write(json.dumps(
                    finding_record(item, project=project, file=inside),
                    ensure_ascii=False,
                ) + "\n")
                finding_count += 1
                mark = (item.kind, item.value, item.source)
                if mark in seen_sample:
                    continue
                seen_sample.add(mark)
                if len(sample) < TERMINAL_SAMPLE:
                    sample.append(item)
            handle.flush()
            if not scan.complete:
                complete, reason = False, scan.stopped_reason
                break
    finally:
        _close_handles(handles)

    if resume:
        living = {relative_source(path, root) for path in iter_scan_files(root, all_files=all_files)}
        next_manifest = {key: value for key, value in next_manifest.items() if key in living}

    _save_manifest(manifest_path, root, next_manifest)

    live_sample = sample
    sample = []
    seen_sample = set()
    projects_seen = set()
    finding_count = 0
    for record in iter_report_records(reports_dir):
        finding_count += 1
        project = str(record.get("project") or "")
        if project:
            projects_seen.add(project)
        if live_sample or len(sample) >= TERMINAL_SAMPLE:
            continue
        item = record_as_finding(record)
        mark = (item.kind, item.value, item.source)
        if mark in seen_sample:
            continue
        seen_sample.add(mark)
        sample.append(item)
    if live_sample:
        sample = live_sample

    finish_reports(reports_dir)
    return TreeScan(
        findings=sorted(sample, key=lambda item: (item.source, item.line)),
        scanned_bytes=scanned_bytes,
        scanned_lines=scanned_lines,
        complete=complete,
        stopped_reason=reason,
        reports_dir=reports_dir,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        files_resumed=files_resumed,
        finding_count=finding_count,
        projects=sorted(projects_seen),
    )


def describe_tree_scan(result: TreeScan) -> str:
    lines = [
        paint(f"  reports: {result.reports_dir}", PALETTE.green),
    ]
    for project in result.projects:
        name = safe_project_name(project)
        lines.append(paint(
            f"    {name}_report.jsonl  ·  {name}_report.csv",
            PALETTE.muted,
        ))
    extras = f"{result.files_scanned:,} file(s) · {result.finding_count:,} finding(s)"
    if result.files_resumed:
        extras += f" · {result.files_resumed:,} unchanged skipped"
    lines.append(paint(f"  {extras}", PALETTE.muted))
    return "\n".join(lines)


def findings_from_reports(reports_dir: Path, *, limit: int | None = None) -> list[JuicyFinding]:
    """Rebuild findings from JSONL. Stops at `limit` if set."""

    items: list[JuicyFinding] = []
    for record in iter_report_records(reports_dir):
        items.append(record_as_finding(record))
        if limit is not None and len(items) >= limit:
            break
    return items


def write_tacu_csv(reports_dir: Path, output: Path) -> Path:
    """Copy MASTER_SUMMARY to `-o FILE` (values in the clear)."""
    output = output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for record in iter_report_records(reports_dir):
            writer.writerow(_csv_row(record))
    _chmod_private(temporary)
    temporary.replace(output)
    _chmod_private(output)
    return output
