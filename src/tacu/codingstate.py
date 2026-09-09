"""Durable, workspace-scoped coding checkpoints and a single-writer lock."""

from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from pathlib import Path

from .core import TacuError
from .managed import atomic_json, workspace_key


class CodingState:
    def __init__(self, workspace: Path, state_dir: Path):
        self.workspace = workspace.resolve()
        self.root = state_dir / "coding" / workspace_key(workspace)
        self.path = self.root / "latest.json"

    @contextmanager
    def lock(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.root / "lock").open("a+b") as stream:
            if os.name == "nt":
                import msvcrt
                stream.write(b"0")
                stream.flush()
                stream.seek(0)
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as error:
                    raise TacuError("Another coding invocation is using this workspace.") from error
            else:
                import fcntl
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    raise TacuError("Another coding invocation is using this workspace.") from error
            try:
                yield
            finally:
                if os.name == "nt":
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def load(self) -> dict:
        try:
            value = json.loads(self.path.read_text())
        except (OSError, ValueError) as error:
            raise TacuError("No readable coding checkpoint in this workspace.") from error
        if value.get("schema") != 1 or value.get("workspace") != str(self.workspace):
            raise TacuError("Coding checkpoint does not match this workspace or version.")
        snapshot = Path(value["snapshot"]["directory"]).resolve()
        if self.root.resolve() not in snapshot.parents:
            raise TacuError("Invalid snapshot location in coding checkpoint.")
        return value

    def prepare(self, loop) -> None:
        loop.snapshot.directory = self.root / uuid.uuid4().hex / "snapshot"
        loop.snapshot.targeted = True

    def save(self, loop, status: str = "running") -> None:
        value = loop.checkpoint()
        value.update(schema=1, workspace=str(self.workspace), status=status)
        atomic_json(self.path, value)

    def restore(self, loop, value: dict) -> None:
        loop.restore_checkpoint(value)
        # Files may have changed while the CLI was closed. Never carry a stale pass
        # (including one from a still-running server) into a resumed job.
        loop.guard.verified = False
        loop.guard.services.clear()
        from .codingguard import wants_server
        loop.guard.require_service = loop.guard.require_service or wants_server(loop.goal)
        loop.history.append({"role": "user", "content": "Resumed checkpoint. Recheck current files and rerun verification; earlier passes are stale."})
