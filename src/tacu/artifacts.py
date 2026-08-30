"""Permission-restricted raw evidence artifacts with bounded retention."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

MAX_ARTIFACT_BYTES = 100_000_000
ARTIFACT_RETENTION = 100


def save_raw_artifacts(state_dir: Path, *, stdout: bytes = b"", stderr: bytes = b"") -> dict[str, Any] | None:
    if not stdout and not stderr:
        return None
    root = state_dir / "artifacts"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        root.chmod(0o700)
    artifact_id = uuid.uuid4().hex
    streams: dict[str, Any] = {}
    for name, content in (("stdout", stdout), ("stderr", stderr)):
        if not content:
            continue
        stored = content[:MAX_ARTIFACT_BYTES]
        target = root / f"{artifact_id}.{name}.raw"
        target.write_bytes(stored)
        if os.name != "nt":
            target.chmod(0o600)
        streams[name] = {
            "uri": f"artifact://{artifact_id}/{name}",
            "path": str(target),
            "bytes": len(content),
            "stored_bytes": len(stored),
            "sha256": hashlib.sha256(content).hexdigest(),
            "truncated": len(stored) != len(content),
        }
    metadata = {"schema": "tacu.raw-artifact/v1", "id": artifact_id, "streams": streams}
    manifest = root / f"{artifact_id}.json"
    manifest.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        manifest.chmod(0o600)
    manifests = sorted(root.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    for expired in manifests[ARTIFACT_RETENTION:]:
        for item in root.glob(f"{expired.stem}.*"):
            try:
                item.unlink()
            except OSError:
                pass
    return metadata


class RawArtifactWriter:
    """Stream one stdout artifact to disk while keeping RAM usage bounded."""

    def __init__(self, state_dir: Path) -> None:
        self.root = state_dir / "artifacts"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            self.root.chmod(0o700)
        self.artifact_id = uuid.uuid4().hex
        self.path = self.root / f"{self.artifact_id}.stdout.raw"
        self.handle = self.path.open("wb")
        if os.name != "nt":
            self.path.chmod(0o600)
        self.digest = hashlib.sha256()
        self.total = 0
        self.stored = 0

    def write(self, chunk: bytes) -> None:
        self.digest.update(chunk)
        self.total += len(chunk)
        available = max(0, MAX_ARTIFACT_BYTES - self.stored)
        if available:
            retained = chunk[:available]
            self.handle.write(retained)
            self.stored += len(retained)

    def finish(self) -> dict[str, Any] | None:
        self.handle.close()
        if not self.total:
            self.path.unlink(missing_ok=True)
            return None
        metadata = {
            "schema": "tacu.raw-artifact/v1",
            "id": self.artifact_id,
            "streams": {
                "stdout": {
                    "uri": f"artifact://{self.artifact_id}/stdout",
                    "path": str(self.path),
                    "bytes": self.total,
                    "stored_bytes": self.stored,
                    "sha256": self.digest.hexdigest(),
                    "truncated": self.stored != self.total,
                }
            },
        }
        manifest = self.root / f"{self.artifact_id}.json"
        manifest.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        if os.name != "nt":
            manifest.chmod(0o600)
        manifests = sorted(self.root.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
        for expired in manifests[ARTIFACT_RETENTION:]:
            for item in self.root.glob(f"{expired.stem}.*"):
                try:
                    item.unlink()
                except OSError:
                    pass
        return metadata

    def abort(self) -> None:
        self.handle.close()
        self.path.unlink(missing_ok=True)
