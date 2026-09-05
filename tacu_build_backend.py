"""Tiny PEP 517 backend so TACU can package itself without build dependencies."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import tarfile
import zipfile
from pathlib import Path

NAME = "tacu"


def _version() -> str:
    """Read the one place the version lives, so a release cannot half-happen."""

    source = (Path(__file__).parent / "src" / NAME / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', source, re.MULTILINE)
    if not match:
        raise RuntimeError(f"No __version__ found in src/{NAME}/__init__.py")
    return match.group(1)


VERSION = _version()
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
ROOT = Path(__file__).parent


def _metadata() -> str:
    return "\n".join((
        "Metadata-Version: 2.3", f"Name: {NAME}", f"Version: {VERSION}",
        "Summary: Terminal Ally & Companion Unit - a local-first AI harness for terminal tools",
        "Requires-Python: >=3.11", "License-Expression: MIT", "",
    ))


def get_requires_for_build_wheel(config_settings=None) -> list[str]:
    return []


def get_requires_for_build_sdist(config_settings=None) -> list[str]:
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None) -> str:
    target = Path(metadata_directory) / DIST_INFO
    target.mkdir(parents=True, exist_ok=True)
    (target / "METADATA").write_text(_metadata(), encoding="utf-8")
    (target / "WHEEL").write_text("Wheel-Version: 1.0\nGenerator: tacu-build\nRoot-Is-Purelib: true\nTag: py3-none-any\n", encoding="utf-8")
    (target / "entry_points.txt").write_text("[console_scripts]\nticu = tacu.cli:main\n", encoding="utf-8")
    return DIST_INFO


def _record_row(path: str, data: bytes) -> tuple[str, str, str]:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return path, f"sha256={digest}", str(len(data))


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None) -> str:
    filename = f"{NAME}-{VERSION}-py3-none-any.whl"
    target = Path(wheel_directory) / filename
    files: dict[str, bytes] = {}
    for path in sorted((ROOT / "src" / "tacu").rglob("*.py")):
        files[path.relative_to(ROOT / "src").as_posix()] = path.read_bytes()
    # Ship the release history so `ti version --history` works from an install too.
    changelog = ROOT / "CHANGELOG.md"
    if changelog.is_file():
        files[f"{NAME}/CHANGELOG.md"] = changelog.read_bytes()
    files[f"{DIST_INFO}/METADATA"] = _metadata().encode()
    files[f"{DIST_INFO}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: tacu-build\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    files[f"{DIST_INFO}/entry_points.txt"] = b"[console_scripts]\nticu = tacu.cli:main\n"
    rows = [_record_row(name, data) for name, data in files.items()]
    rows.append((f"{DIST_INFO}/RECORD", "", ""))
    buffer = io.StringIO(); csv.writer(buffer, lineterminator="\n").writerows(rows)
    files[f"{DIST_INFO}/RECORD"] = buffer.getvalue().encode()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return filename


def build_sdist(sdist_directory, config_settings=None) -> str:
    filename = f"{NAME}-{VERSION}.tar.gz"
    target = Path(sdist_directory) / filename
    included = [Path("pyproject.toml"), Path("tacu_build_backend.py"), Path("README.md"), Path("LICENSE"),
                Path("CHANGELOG.md"), Path("install.sh"), Path("install.ps1")]
    included.extend(path.relative_to(ROOT) for path in (ROOT / "src" / "tacu").rglob("*.py"))
    with tarfile.open(target, "w:gz") as archive:
        for relative in included:
            if (ROOT / relative).exists():
                archive.add(ROOT / relative, arcname=f"{NAME}-{VERSION}/{relative}")
    return filename
