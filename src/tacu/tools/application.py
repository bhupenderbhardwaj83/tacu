"""Locate installed applications and read native version metadata."""

from __future__ import annotations

import re

import plistlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..host_parsers import parse_ps
from ..platform import detect, process_list_argv_with_header, run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "application",
    "Find installed applications and report version, bundle metadata, code signature, "
    "and whether they are running. Prefer this over searching the current directory.",
    schema(properties={
        "operation": {"type": "string", "enum": ["find", "list", "version", "metadata", "running", "signature", "open"]},
        "name": {"type": "string"},
        "url": {"type": "string"},
        "limit": {"type": "integer"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)


def _app_roots() -> list[Path]:
    home = Path.home()
    if detect().os == "macos":
        return [Path("/Applications"), Path("/System/Applications"), home / "Applications"]
    if detect().os == "windows":
        roots = []
        for key in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            value = __import__("os").environ.get(key)
            if value:
                roots.append(Path(value))
        return roots
    return [Path("/usr/share/applications"), Path("/usr/local/share/applications"), home / ".local/share/applications"]


# Words people add that never appear in a bundle name.
_APP_QUERY_NOISE = frozenset((
    "app", "apps", "application", "applications", "software", "program", "programme",
    "tool", "client", "agent", "the", "a", "an", "my", "for", "mac", "macos", "version",
))


def _query_tokens(name: str) -> list[str]:
    cleaned = re.sub(r"[^A-Za-z0-9]+", " ", name.casefold().removesuffix(".app"))
    # Two-letter fragments match half of /Applications, so they are not evidence.
    return [word for word in cleaned.split()
            if len(word) >= 3 and word not in _APP_QUERY_NOISE]


def _bundle_identifier(path: Path) -> str:
    """The reverse-DNS id, which carries the vendor the display name often omits."""

    plist_path = path / "Contents" / "Info.plist"
    if not plist_path.is_file():
        return ""
    try:
        import plistlib

        with plist_path.open("rb") as handle:
            return str(plistlib.load(handle).get("CFBundleIdentifier") or "")
    except Exception:
        return ""


def _match_rank(path: Path, name: str) -> int:
    """How well a bundle answers to what was asked. Zero means it does not.

    A vendor name is often absent from the bundle: CrowdStrike ships "Falcon.app",
    so requiring the whole phrase would report a product as not installed while it
    sits in /Applications.
    """

    needle = name.casefold().removesuffix(".app").strip()
    stem = path.stem.casefold()
    if not needle:
        return 0
    if stem == needle:
        return 100
    # A fragment shorter than three characters matches half of /Applications.
    if len(needle) >= 3 and needle in stem:
        return 80
    tokens = _query_tokens(name)
    if not tokens:
        return 0
    hits = [word for word in tokens if word in stem]
    if not hits:
        # CrowdStrike ships Falcon.app but identifies as com.crowdstrike.falcon, so
        # the vendor is recorded even when the name omits it.
        identifier = _bundle_identifier(path).casefold()
        if identifier and all(word in identifier for word in tokens):
            return 50
        if identifier and any(len(word) >= 5 and word in identifier for word in tokens):
            return 30
        return 0
    if len(hits) == len(tokens):
        return 60
    # A single distinctive word is enough; a two-letter fragment is not.
    return 40 if max(len(word) for word in hits) >= 4 else 0


def _matches(path: Path, name: str) -> bool:
    return _match_rank(path, name) > 0


def _find_apps(name: str, limit: int = 10) -> list[Path]:
    """Best match first, so the closest bundle is the one reported on."""

    found: list[tuple[int, Path]] = []
    for root in _app_roots():
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            wanted = child.suffix.casefold() == ".app" or detect().os != "macos"
            if not wanted:
                continue
            rank = _match_rank(child, name)
            if rank:
                found.append((rank, child))
    # Rank before truncating, so a close match is never lost to an early weak one.
    found.sort(key=lambda pair: (-pair[0], pair[1].stem.casefold()))
    # A vendor hint buried in a bundle id is only interesting while nothing better
    # answers: "Google Chrome" should not also report a different Google product.
    if found and found[0][0] >= 60:
        found = [pair for pair in found if pair[0] >= 50]
    return [child for _rank, child in found[:limit]]


def _mdls_dates(path: Path) -> dict[str, str]:
    dates: dict[str, str] = {}
    if which("mdls"):
        raw = run_argv(
            ["mdls", "-name", "kMDItemFSCreationDate", "-name", "kMDItemDateAdded",
             "-name", "kMDItemContentCreationDate", str(path)],
            timeout=8,
        )
        for line in raw["stdout"].splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip()
            if value in {"(null)", ""}:
                continue
            if key == "kMDItemDateAdded":
                dates["date_added"] = value
            elif key == "kMDItemFSCreationDate":
                dates["fs_creation_date"] = value
            elif key == "kMDItemContentCreationDate":
                dates["content_created"] = value
    if "fs_creation_date" not in dates:
        try:
            stat = path.stat()
            created = getattr(stat, "st_birthtime", None) or stat.st_ctime
            dates["fs_creation_date"] = datetime.fromtimestamp(created, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S +0000")
        except OSError:
            pass
    created = dates.get("date_added") or dates.get("fs_creation_date") or dates.get("content_created")
    if created:
        dates["created"] = created
    return dates


def _bundle_metadata(path: Path, *, dates: bool = False) -> dict[str, Any]:
    plist_path = path / "Contents" / "Info.plist"
    metadata = {"path": str(path), "name": path.stem}
    if not plist_path.is_file():
        if dates:
            metadata.update(_mdls_dates(path))
        return metadata
    try:
        with plist_path.open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError):
        if dates:
            metadata.update(_mdls_dates(path))
        return metadata
    metadata.update({
        "bundle_id": info.get("CFBundleIdentifier"),
        "version": info.get("CFBundleShortVersionString") or info.get("CFBundleVersion"),
        "build": info.get("CFBundleVersion"),
        "display_name": info.get("CFBundleDisplayName") or info.get("CFBundleName") or path.stem,
    })
    if dates:
        metadata.update(_mdls_dates(path))
    return metadata


def _list_apps(limit: int) -> list[Path]:
    found: list[Path] = []
    for root in _app_roots():
        if not root.is_dir():
            continue
        try:
            children = sorted(root.iterdir(), key=lambda item: item.name.casefold())
        except OSError:
            continue
        for child in children:
            if child.suffix.casefold() == ".app" or detect().os != "macos":
                if detect().os == "macos" and child.suffix.casefold() != ".app":
                    continue
                found.append(child)
            if len(found) >= limit:
                return found
    return found


_SAFE_URL = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")


def _open_argv(app_path: str | None, url: str) -> list[str]:
    """Launch an app, optionally at a page, without going through a shell.

    Every part is a separate argument, so a crafted name or address cannot become
    another command.
    """

    if detect().os == "macos":
        if app_path and url:
            return ["open", "-a", app_path, url]
        return ["open", "-a", app_path] if app_path else ["open", url]
    if url:
        return ["xdg-open", url]
    return ["xdg-open", app_path or ""]


def execute(context: ToolContext, *, operation: str, name: str = "", url: str = "",
            limit: int = 40) -> dict[str, Any]:
    # A listing must not silently stop short: "show all my applications" answered
    # with the first 40 of 79 is a wrong answer, not a shortened one.
    cap = max(1, min(int(limit or 400), 400))
    needle = name.strip()
    if operation == "list" or (operation in {"find", "version", "metadata"} and not needle):
        apps = [_bundle_metadata(path) for path in _list_apps(cap)]
        if needle:
            apps = [item for item in apps if needle.casefold() in (item.get("name") or "").casefold()
                    or needle.casefold() in (item.get("display_name") or "").casefold()]
        return {
            "status": "success" if apps else "no_results", "operation": operation or "list",
            "query": needle or None, "applications": apps, "count": len(apps),
            "version": apps[0].get("version") if apps else None,
            "path": apps[0].get("path") if apps else None, "exit_code": 0,
        }
    if not needle:
        raise ToolFailure("application find/version/running require name.", code="invalid_arguments")
    apps = [_bundle_metadata(path, dates=operation == "metadata") for path in _find_apps(needle, cap)]
    suggestions: list[str] = []
    if not apps:
        # "flacon" is a typo for something installed; saying so beats a dead end.
        import difflib

        names = {item.stem.casefold(): item.stem for item in _list_apps(400)}
        suggestions = [names[key] for key in
                       difflib.get_close_matches(needle.casefold(), list(names), n=3, cutoff=0.6)]
    if operation in {"find", "version", "metadata"}:
        first = apps[0] if apps else {}
        return {
            "status": "success" if apps else "no_results",
            "operation": operation,
            "query": name,
            "applications": apps,
            "count": len(apps),
            "did_you_mean": suggestions or None,
            "version": first.get("version"),
            "path": first.get("path"),
            "created": first.get("created"),
            "fs_creation_date": first.get("fs_creation_date"),
            "date_added": first.get("date_added"),
            "exit_code": 0,
        }
    if operation == "signature":
        if not apps:
            return {"status": "no_results", "operation": operation, "query": name, "applications": [], "exit_code": 0}
        target = apps[0]["path"]
        raw = run_argv([which("codesign") or "codesign", "-dv", "--verbose=2", target], timeout=SPEC.timeout)
        text = (raw["stderr"] or raw["stdout"]).strip()[:4000]
        apps[0]["signature"] = text
        return {"status": "success", "operation": operation, "query": name, "applications": apps[:1],
                "signature": text, "path": target, "exit_code": raw["exit_code"]}
    if operation == "open":
        from .contracts import require_approval
        require_approval(
            context, "application.open",
            f"Run it through the reviewed lane: ti do open {name or url or '<app>'} — "
            f"or yourself: open " + (f"-a {name!r}" if name else str(url or "")) + ".")
        target = (url or "").strip()
        if target and not _SAFE_URL.match(target):
            raise ToolFailure(
                "Only http and https addresses can be opened, and they must contain no "
                "shell characters.", code="invalid_arguments")
        if not apps and not target:
            return {"status": "no_results", "operation": operation, "query": name,
                    "applications": [], "exit_code": 1}
        app_path = apps[0]["path"] if apps else None
        raw = run_argv(_open_argv(app_path, target), timeout=SPEC.timeout)
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "query": name, "url": target or None, "applications": apps[:1],
                "path": app_path, "opened": raw.get("command"), "exit_code": raw["exit_code"]}
    raw = run_argv(process_list_argv_with_header(), timeout=SPEC.timeout)
    needle = name.casefold().removesuffix(".app")
    running = [item for item in parse_ps(raw["stdout"])
               if needle in (item.get("command") or "").casefold()
               or needle in (item.get("executable") or "").casefold()]
    return {
        "status": "success" if running else "no_results",
        "operation": operation,
        "query": name,
        "applications": apps,
        "running": running[:cap],
        "count": min(len(running), cap),
        "exit_code": 0,
    }
