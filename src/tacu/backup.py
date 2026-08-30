"""Portable backup and restore for the TACU data directory.

A backup is a single .tar.gz you can drop on a pen drive, iCloud Drive, Google
Drive, or Dropbox — no cloud API is involved, the destination is just a path.

SQLite files are copied with the online backup API rather than read byte-wise,
so an archive taken while TACU is mid-write is still consistent.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from . import __version__
from .core import TacuError, app_home

MANIFEST_NAME = "tacu-backup.json"
FORMAT_VERSION = 1
ARCHIVE_ROOT = "tacu-data"

# Databases need the online backup API; plain files can be copied directly.
DATABASE_FILES = ("history.db", "clipboard.db", "harness.db")
PLAIN_FILES = ("config.json", "ghost_cmds.log", "recipes.json")
ARTIFACT_DIR = "artifacts"
# Never archived: the venv is rebuilt by install.sh, and datasets are temporary by
# design. Both are simply absent from the copy lists above.
EXCLUDED = ("runtime", "datasets")

# Tables that can be merged row-by-row without renumbering anything the user sees.
MERGEABLE = {
    "history.db": ("turns", "id"),
    "clipboard.db": ("clips", "id"),
}


@dataclass(frozen=True)
class BackupInfo:
    """What a backup archive says about itself."""

    path: Path
    created_at: str
    tacu_version: str
    hostname: str
    includes_artifacts: bool
    entries: dict[str, int]
    size_bytes: int

    @property
    def item_count(self) -> int:
        return len(self.entries)

    def describe(self) -> str:
        when = self.created_at.replace("T", " ")[:19]
        extra = " + artifacts" if self.includes_artifacts else ""
        return f"{when} · tacu {self.tacu_version} · {human_size(self.size_bytes)}{extra}"


def human_size(count: int) -> str:
    size = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def default_archive_name(now: datetime | None = None) -> str:
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    return f"tacu-backup-{stamp}.tar.gz"


def _snapshot_database(source: Path, target: Path) -> None:
    """Copy a live SQLite file consistently using the online backup API."""

    with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as origin:
        with sqlite3.connect(target) as replica:
            origin.backup(replica)


def _staged_copy(home: Path, staging: Path, *, include_artifacts: bool) -> dict[str, int]:
    entries: dict[str, int] = {}
    for name in DATABASE_FILES:
        source = home / name
        if not source.exists():
            continue
        target = staging / name
        _snapshot_database(source, target)
        entries[name] = target.stat().st_size
    for name in PLAIN_FILES:
        source = home / name
        if not source.exists():
            continue
        shutil.copy2(source, staging / name)
        entries[name] = (staging / name).stat().st_size
    if include_artifacts and (home / ARTIFACT_DIR).is_dir():
        shutil.copytree(home / ARTIFACT_DIR, staging / ARTIFACT_DIR)
        total = sum(item.stat().st_size for item in (staging / ARTIFACT_DIR).rglob("*") if item.is_file())
        entries[ARTIFACT_DIR] = total
    return entries


def resolve_destination(destination: Path | None) -> Path:
    """Accept a directory (name is generated) or an explicit .tar.gz path."""

    if destination is None:
        return Path.cwd() / default_archive_name()
    target = destination.expanduser()
    if target.is_dir():
        return target / default_archive_name()
    if target.suffix not in {".gz", ".tgz"}:
        return target.with_name(target.name + ".tar.gz")
    return target


def create_backup(
    destination: Path | None = None,
    *,
    include_artifacts: bool = False,
    home: Path | None = None,
) -> BackupInfo:
    """Write every piece of TACU state into one portable archive."""

    root = home or app_home()
    if not root.exists():
        raise TacuError(f"No TACU data directory at {root}. Nothing to back up.")
    archive = resolve_destination(destination)
    archive.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as workspace:
        staging = Path(workspace) / ARCHIVE_ROOT
        staging.mkdir(parents=True)
        entries = _staged_copy(root, staging, include_artifacts=include_artifacts)
        if not entries:
            raise TacuError(f"No backup-worthy files found in {root}.")
        manifest = {
            "format": FORMAT_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tacu_version": __version__,
            "hostname": platform.node(),
            "platform": platform.platform(),
            "includes_artifacts": include_artifacts,
            "entries": entries,
        }
        (staging / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(staging, arcname=ARCHIVE_ROOT)

    if os.name != "nt":
        archive.chmod(0o600)
    return BackupInfo(
        path=archive,
        created_at=manifest["created_at"],
        tacu_version=manifest["tacu_version"],
        hostname=manifest["hostname"],
        includes_artifacts=include_artifacts,
        entries=entries,
        size_bytes=archive.stat().st_size,
    )


def resolve_archive(archive: Path) -> Path:
    """Accept a path, a folder, or a glob.

    The shell alias is `noglob ti`, so patterns like *.tar.gz arrive unexpanded
    and we have to resolve them here instead of letting zsh do it.
    """

    path = archive.expanduser()
    if path.is_file():
        return path
    if path.is_dir():
        found = list_backups(path)
        if not found:
            raise TacuError(f"No TACU backups in {path}. List a folder with: ti backup list {path}")
        return found[0].path
    text = str(path)
    if any(character in text for character in "*?["):
        matches = sorted(path.parent.expanduser().glob(path.name))
        if not matches:
            raise TacuError(f"No file matches {text}.")
        return max(matches, key=lambda item: item.stat().st_mtime)
    raise TacuError(f"No backup archive at {path}.")


def read_manifest(archive: Path) -> BackupInfo:
    """Read a backup's manifest without extracting the payload."""

    path = resolve_archive(archive)
    try:
        with tarfile.open(path, "r:gz") as bundle:
            try:
                member = bundle.extractfile(f"{ARCHIVE_ROOT}/{MANIFEST_NAME}")
            except KeyError:
                member = None
            if member is None:
                raise TacuError(f"{path.name} is not a TACU backup (no manifest inside).")
            manifest = json.loads(member.read().decode("utf-8"))
    except tarfile.TarError as error:
        raise TacuError(f"{path.name} is not a readable .tar.gz archive: {error}") from error
    except json.JSONDecodeError as error:
        raise TacuError(f"{path.name} has a corrupt manifest: {error}") from error
    if int(manifest.get("format", 0)) > FORMAT_VERSION:
        raise TacuError(
            f"{path.name} was written by a newer TACU (format {manifest['format']}). Upgrade first."
        )
    return BackupInfo(
        path=path,
        created_at=str(manifest.get("created_at", "")),
        tacu_version=str(manifest.get("tacu_version", "?")),
        hostname=str(manifest.get("hostname", "?")),
        includes_artifacts=bool(manifest.get("includes_artifacts", False)),
        entries=dict(manifest.get("entries", {})),
        size_bytes=path.stat().st_size,
    )


def list_backups(folder: Path | None = None) -> list[BackupInfo]:
    """Find TACU backups in a folder, newest first. Non-TACU archives are skipped."""

    root = (folder or Path.cwd()).expanduser()
    if not root.is_dir():
        raise TacuError(f"{root} is not a directory.")
    found: list[BackupInfo] = []
    for candidate in sorted(root.glob("*.tar.gz")) + sorted(root.glob("*.tgz")):
        try:
            found.append(read_manifest(candidate))
        except TacuError:
            continue
    return sorted(found, key=lambda info: info.created_at, reverse=True)


def _safe_members(bundle: tarfile.TarFile) -> Iterable[tarfile.TarInfo]:
    """Reject absolute paths, traversal, and links before anything is written."""

    for member in bundle.getmembers():
        name = member.name
        if name.startswith("/") or ".." in Path(name).parts:
            raise TacuError(f"Refusing to extract unsafe path from archive: {name}")
        if member.issym() or member.islnk():
            raise TacuError(f"Refusing to extract link from archive: {name}")
        yield member


def _merge_database(incoming: Path, current: Path, table: str, key: str) -> int:
    """Add rows the local database is missing; never overwrite an existing id."""

    if not current.exists():
        shutil.copy2(incoming, current)
        return -1
    connection = sqlite3.connect(current)
    try:
        connection.execute("ATTACH DATABASE ? AS backup", (str(incoming),))
        try:
            before = connection.execute(f"SELECT COUNT(*) FROM main.{table}").fetchone()[0]
            local_columns = [row[1] for row in connection.execute(f"PRAGMA main.table_info({table})")]
            archive_columns = {row[1] for row in connection.execute(f"PRAGMA backup.table_info({table})")}
            shared = [name for name in local_columns if name in archive_columns]
            if not shared:
                return 0
            joined = ",".join(shared)
            connection.execute(
                f"INSERT OR IGNORE INTO main.{table} ({joined}) "
                f"SELECT {joined} FROM backup.{table} "
                f"WHERE {key} NOT IN (SELECT {key} FROM main.{table})"
            )
            after = connection.execute(f"SELECT COUNT(*) FROM main.{table}").fetchone()[0]
            # DETACH refuses to run inside an open transaction.
            connection.commit()
        finally:
            connection.execute("DETACH DATABASE backup")
    finally:
        connection.close()
    return int(after - before)


def restore_backup(
    archive: Path,
    *,
    merge: bool = False,
    home: Path | None = None,
    safety_copy: bool = True,
) -> tuple[BackupInfo, dict[str, str]]:
    """Restore an archive over the live data directory.

    Replace mode swaps each file in wholesale. Merge mode keeps what you have and
    only adds turns and clips the local databases are missing. Either way a safety
    snapshot of the current state is written first unless you opt out.
    """

    info = read_manifest(archive)
    root = home or app_home()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)

    rescue: Path | None = None
    if safety_copy and any((root / name).exists() for name in DATABASE_FILES + PLAIN_FILES):
        rescue = root / f"pre-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
        create_backup(rescue, include_artifacts=False, home=root)

    outcome: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as workspace:
        staging = Path(workspace)
        with tarfile.open(info.path, "r:gz") as bundle:
            bundle.extractall(staging, members=_safe_members(bundle))
        payload = staging / ARCHIVE_ROOT
        if not payload.is_dir():
            raise TacuError(f"{info.path.name} has no {ARCHIVE_ROOT} directory inside it.")

        for name in DATABASE_FILES:
            incoming = payload / name
            if not incoming.exists():
                continue
            target = root / name
            if merge and name in MERGEABLE and target.exists():
                table, key = MERGEABLE[name]
                added = _merge_database(incoming, target, table, key)
                outcome[name] = f"merged, {added} new row(s)" if added >= 0 else "restored"
            else:
                shutil.copy2(incoming, target)
                outcome[name] = "replaced" if merge else "restored"
            if os.name != "nt":
                target.chmod(0o600)

        for name in PLAIN_FILES:
            incoming = payload / name
            if not incoming.exists():
                continue
            target = root / name
            if merge and target.exists():
                outcome[name] = "kept local"
                continue
            shutil.copy2(incoming, target)
            outcome[name] = "restored"

        incoming_artifacts = payload / ARTIFACT_DIR
        if incoming_artifacts.is_dir():
            destination = root / ARTIFACT_DIR
            destination.mkdir(parents=True, exist_ok=True)
            copied = 0
            for item in incoming_artifacts.rglob("*"):
                if not item.is_file():
                    continue
                relative = item.relative_to(incoming_artifacts)
                out = destination / relative
                if merge and out.exists():
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, out)
                copied += 1
            outcome[ARTIFACT_DIR] = f"{copied} file(s)"

    if rescue is not None:
        outcome["_safety_copy"] = str(rescue)
    return info, outcome
