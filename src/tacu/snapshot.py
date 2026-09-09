"""A copy of the source files taken before the first change, so a bad run is undoable.

Taken lazily: a job that only reads never pays for one. Only text-ish source
files are copied, and the heavy directories every project carries are skipped,
so the snapshot of a normal repository is small and quick rather than a full
recursive copy of node_modules.
"""

from __future__ import annotations

import shutil
import tempfile
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

# Directories that are rebuilt, not written by hand. Copying them is slow and
# restoring them is wrong.
SKIP_DIRS = frozenset({
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", "dist", "build", ".next", ".cache",
    "target", "vendor", ".terraform", "site-packages", ".idea", ".vscode",
})
# What counts as source worth restoring. A snapshot is for the code, not for a
# 400 MB capture file that happens to sit in the workspace.
SOURCE_SUFFIXES = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".go", ".rs", ".rb", ".php", ".java", ".kt", ".kts", ".scala", ".swift", ".m",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".sh", ".bash", ".zsh", ".ps1", ".sql",
    ".html", ".htm", ".css", ".scss", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".conf", ".md", ".rst", ".txt", ".env", ".example", ".lock", ".tf",
})
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 4_000


def is_source(path: Path) -> bool:
    if path.suffix.casefold() in SOURCE_SUFFIXES:
        return True
    # Dockerfile, Makefile, Jenkinsfile — no suffix, still source.
    return path.suffix == "" and path.name[:1].isupper() and path.name.isalpha()


def _walk_source(root: Path):
    stack = [root]
    seen = 0
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name not in SKIP_DIRS:
                    stack.append(child)
                continue
            if not is_source(child):
                continue
            try:
                if child.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield child
            seen += 1
            if seen >= MAX_FILES:
                return


@dataclass
class Snapshot:
    """A restore point for the source files of one workspace."""

    workspace: Path
    directory: Path | None = None
    captured: set[str] = field(default_factory=set)
    created: set[str] = field(default_factory=set)
    targeted: bool = False

    def _target(self, relative: str) -> Path:
        candidate = (self.workspace / relative).resolve()
        if candidate == self.workspace.resolve() or self.workspace.resolve() not in candidate.parents:
            raise ValueError(f"Snapshot path escapes workspace: {relative}")
        return candidate

    def capture(self, value: str) -> None:
        """Capture an exact edit target, including files outside the source suffix list."""
        target = self._target(value)
        relative = target.relative_to(self.workspace.resolve()).as_posix()
        self.targeted = True
        if relative in self.captured or relative in self.created:
            return
        if self.directory is None:
            self.directory = Path(tempfile.mkdtemp(prefix="tacu-restore-"))
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.exists():
            if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"Cannot safely snapshot {value}: expected a file no larger than {MAX_FILE_BYTES} bytes.")
            stored = self.directory / relative
            stored.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, stored)
            self.captured.add(relative)
        else:
            self.created.add(relative)

    def fingerprints(self) -> dict[str, str | None]:
        return {name: hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
                for name in sorted(self.captured | self.created)
                for path in [self._target(name)]}

    def take(self) -> Path:
        """Copy the source files once. Calling it again is a no-op."""

        if self.directory is not None:
            return self.directory
        base = Path(tempfile.mkdtemp(prefix="tacu-restore-"))
        for path in _walk_source(self.workspace):
            relative = path.relative_to(self.workspace)
            target = base / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(path, target)
                self.captured.add(relative.as_posix())
            except OSError:
                continue
        self.directory = base
        return base

    def changed(self) -> list[str]:
        """Source files that differ from the snapshot, or are new since it."""

        if self.directory is None:
            return []
        if self.targeted:
            return sorted(name for name in self.captured | self.created
                          if (self._target(name).exists() if name in self.created else
                              not self._target(name).is_file() or
                              self._target(name).read_bytes() != (self.directory / name).read_bytes()))
        differing: list[str] = []
        for path in _walk_source(self.workspace):
            relative = path.relative_to(self.workspace).as_posix()
            original = self.directory / relative
            try:
                if not original.is_file():
                    differing.append(relative)
                elif original.read_bytes() != path.read_bytes():
                    differing.append(relative)
            except OSError:
                continue
        return sorted(differing)

    def restore(self, expected: dict[str, str | None] | None = None) -> list[str]:
        """Put the source files back, and delete the ones that were not there."""

        if self.directory is None:
            return []
        if self.targeted:
            if expected is not None and self.fingerprints() != expected:
                raise ValueError("Files changed after the checkpoint. Undo refused to overwrite newer work.")
            changed = self.changed()
            for relative in changed:
                target = self._target(relative)
                if relative in self.created:
                    target.unlink()
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=".tacu-undo-")
                os.close(descriptor)
                try:
                    shutil.copy2(self.directory / relative, temporary)
                    os.replace(temporary, target)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
            return changed
        restored: list[str] = []
        for relative in sorted(self.captured):
            source = self.directory / relative
            target = self.workspace / relative
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.is_file() or target.read_bytes() != source.read_bytes():
                    shutil.copy2(source, target)
                    restored.append(relative)
            except OSError:
                continue
        for path in list(_walk_source(self.workspace)):
            relative = path.relative_to(self.workspace).as_posix()
            if relative not in self.captured:
                try:
                    path.unlink()
                    restored.append(relative)
                except OSError:
                    continue
        return sorted(set(restored))

    def discard(self) -> None:
        if self.directory is not None:
            shutil.rmtree(self.directory, ignore_errors=True)
            self.directory = None
