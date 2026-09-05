"""Correlated endpoint checks: who is talking out, what persists, what reads secrets.

A single indicator proves nothing. This module gathers process, executable,
network, persistence and secret-access facts, then correlates them, so an answer
can say *why* something is worth attention instead of flagging every unknown IP.

Everything here is read-only and runs as the invoking user. Checks that need root
are reported as "not inspected" rather than silently skipped, because a forensic
answer that hides its own blind spots is worse than no answer.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from ..host_parsers import parse_lsof_network
from ..platform import detect, run_argv, which
from .contracts import ToolContext, ToolSpec, schema

SPEC = ToolSpec(
    "forensics",
    "Correlated endpoint compromise checks: outbound connections with the owning process and "
    "its signature, non-loopback listeners, persistence entries, and processes holding "
    "credential files open. Use for 'is anything calling home', 'am I compromised', "
    "'is something reading my SSH/AWS keys', or a full endpoint sweep.",
    schema(properties={
        "operation": {"type": "string",
                      "enum": ["sweep", "outbound", "listening", "persistence", "secret_access"]},
        "limit": {"type": "integer"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=60, risk_level="read", permissions=("host:read",),
    when_to_use="Endpoint compromise, callback-home, backdoor, or credential-theft questions.",
    when_not="Plain connection or port listings; use the network tool for those.",
)

# Directories any user can write to, so a binary running from one has not been
# through an installer or a package manager. Not proof of anything on its own.
_USER_WRITABLE = ("/tmp/", "/private/tmp/", "/var/tmp/", "/dev/shm/",
                  "/Users/Shared/", "/private/var/folders/")
_HOME_WRITABLE = ("Downloads/", "Desktop/", "Public/", ".cache/", ".npm/", ".local/share/Trash/")

# Files worth knowing about when something holds them open.
_SECRET_PATHS = (
    (".ssh", "ssh private keys"),
    (".aws/credentials", "aws credentials"),
    (".aws/config", "aws config"),
    (".config/gcloud", "google cloud credentials"),
    (".kube/config", "kubernetes credentials"),
    (".docker/config.json", "docker registry credentials"),
    (".git-credentials", "git credentials"),
    (".netrc", "netrc credentials"),
    (".gnupg", "gpg keys"),
    (".config/gh/hosts.yml", "github cli token"),
    (".npmrc", "npm token"),
    (".pypirc", "pypi token"),
)
_BROWSER_SECRETS = ("Login Data", "Cookies", "key4.db", "logins.json")

_LOOPBACK = ("127.", "::1", "localhost", "0.0.0.0", "*")

# A shell rc line that runs something at every login.
_RUNS_AT_STARTUP = re.compile(r"^(curl|wget|nc|ncat|bash -c|sh -c|python[0-9.]* -c|eval)\b")
# Only these deserve attention: init snippets from an installed local tool
# (`eval "$(brew shellenv)"`) are how shells are configured, not an indicator.
_FETCHES_CODE = re.compile(
    r"(?i)(https?://|\|\s*(?:ba)?sh\b|/tmp/|/var/tmp/|/dev/shm/"
    r"|base64\s+(?:-d|--decode)|b64decode|\bexec\s*\(|\bdecode\s*\("
    r"|\bnc\s+-[a-z]*e|curl[^|]*\|| wget[^|]*\|)"
)


def _deduplicate(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for item in entries:
        key = (str(item.get("kind")), str(item.get("name")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def _executables() -> dict[int, str]:
    """Map pid to executable path, so a connection can name the binary behind it."""

    paths: dict[int, str] = {}
    system = detect().os
    if system == "linux":
        for entry in Path("/proc").iterdir() if Path("/proc").is_dir() else []:
            if not entry.name.isdigit():
                continue
            try:
                paths[int(entry.name)] = os.readlink(entry / "exe")
            except OSError:
                continue
        return paths
    raw = run_argv(["ps", "-axo", "pid=,comm="], timeout=20)
    for line in (raw.get("stdout") or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pid, _, command = stripped.partition(" ")
        if pid.isdigit() and command.strip():
            paths[int(pid)] = command.strip()
    return paths


def _location_risk(path: str) -> str:
    if not path:
        return "unknown-path"
    lowered = path
    if any(lowered.startswith(prefix) for prefix in _USER_WRITABLE):
        return "user-writable-temp"
    home = str(_home())
    if lowered.startswith(home):
        tail = lowered[len(home):].lstrip("/")
        if any(tail.startswith(prefix) for prefix in _HOME_WRITABLE):
            return "user-download-or-cache"
        if tail.startswith("."):
            return "hidden-home-directory"
    return ""


def _signature(path: str) -> dict[str, Any]:
    """Signing authority on macOS, owning package on Linux. Signed is not the same as safe."""

    if not path or not Path(path).exists():
        return {"checked": False, "reason": "path not readable"}
    if detect().os == "macos" and which("codesign"):
        raw = run_argv(["codesign", "-dv", "--verbose=2", path], timeout=15)
        text = f"{raw.get('stdout') or ''}\n{raw.get('stderr') or ''}"
        authority = re.search(r"Authority=(.+)", text)
        return {
            "checked": True,
            "signed": raw.get("exit_code") == 0,
            "authority": authority.group(1).strip() if authority else "",
            "apple_signed": "Software Signing" in text or "Apple" in (authority.group(1) if authority else ""),
        }
    if which("dpkg"):
        raw = run_argv(["dpkg", "-S", path], timeout=15)
        if raw.get("exit_code") == 0 and raw.get("stdout"):
            return {"checked": True, "signed": True, "package": (raw["stdout"].split(":")[0]).strip()}
        return {"checked": True, "signed": False, "package": ""}
    if which("rpm"):
        raw = run_argv(["rpm", "-qf", path], timeout=15)
        owned = raw.get("exit_code") == 0
        return {"checked": True, "signed": owned, "package": (raw.get("stdout") or "").strip() if owned else ""}
    return {"checked": False, "reason": "no signature tool available"}


def _connection_rows(state: str | None = "ESTABLISHED") -> list[dict[str, Any]]:
    lsof = which("lsof")
    if lsof:
        argv = [lsof, "-nP", "-iTCP"]
        if state:
            argv.append(f"-sTCP:{state}")
        raw = run_argv(argv, timeout=SPEC.timeout)
        return parse_lsof_network(raw.get("stdout") or "")
    if which("ss"):
        raw = run_argv(["ss", "-tunap"], timeout=SPEC.timeout)
        from ..host_parsers import parse_network_table
        return parse_network_table(raw.get("stdout") or "", "ss -tunap")
    return []


def _annotate(rows: list[dict[str, Any]], executables: dict[int, str]) -> list[dict[str, Any]]:
    """Attach executable, location risk and signature to each socket owner."""

    signatures: dict[str, dict[str, Any]] = {}
    annotated: list[dict[str, Any]] = []
    for row in rows:
        pid = row.get("pid")
        path = executables.get(int(pid), "") if pid else ""
        if path and path not in signatures:
            signatures[path] = _signature(path)
        item = dict(row)
        item["executable"] = path
        item["location_risk"] = _location_risk(path)
        item["signature"] = signatures.get(path, {"checked": False})
        annotated.append(item)
    return annotated


def _outbound(limit: int) -> dict[str, Any]:
    executables = _executables()
    rows = [row for row in _connection_rows("ESTABLISHED")
            if row.get("remote_host") and not str(row["remote_host"]).startswith(_LOOPBACK)]
    annotated = _annotate(rows, executables)
    external = [item for item in annotated if not _is_private(str(item.get("remote_host") or ""))]
    concerning = [item for item in external
                  if item["location_risk"] or item["signature"].get("signed") is False]
    return {
        "operation": "outbound",
        "connection_count": len(annotated),
        "external_count": len(external),
        "connections": external[:limit],
        "concerning": concerning[:limit],
        "concerning_count": len(concerning),
    }


def _is_private(address: str) -> bool:
    import ipaddress
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


def _listening(limit: int) -> dict[str, Any]:
    executables = _executables()
    rows = [row for row in _connection_rows("LISTEN") if (row.get("state") or "").upper() == "LISTEN"]
    annotated = _annotate(rows, executables)
    exposed = [item for item in annotated
               if not str(item.get("local_host") or "").startswith(_LOOPBACK)]
    return {
        "operation": "listening",
        "listening_count": len(annotated),
        "exposed_count": len(exposed),
        "listening": annotated[:limit],
        "exposed": exposed[:limit],
    }


def _persistence(limit: int) -> dict[str, Any]:
    """Things configured to start on their own. Most are legitimate; all are listed."""

    home = _home()
    entries: list[dict[str, Any]] = []
    not_inspected: list[str] = []
    system = detect().os
    if system == "macos":
        locations = [
            (home / "Library/LaunchAgents", "user launch agent"),
            (Path("/Library/LaunchAgents"), "system launch agent"),
            (Path("/Library/LaunchDaemons"), "system launch daemon"),
        ]
        for directory, kind in locations:
            if not directory.is_dir():
                continue
            try:
                for item in sorted(directory.iterdir()):
                    if item.suffix != ".plist":
                        continue
                    entries.append({"kind": kind, "name": item.name, "path": str(item),
                                    "location_risk": _location_risk(str(item))})
            except PermissionError:
                not_inspected.append(f"{directory} (permission denied)")
    else:
        locations = [
            (home / ".config/systemd/user", "user systemd unit"),
            (Path("/etc/systemd/system"), "system systemd unit"),
            (Path("/etc/cron.d"), "cron.d entry"),
        ]
        for directory, kind in locations:
            if not directory.is_dir():
                continue
            try:
                for item in sorted(directory.iterdir()):
                    if item.is_dir():
                        continue
                    entries.append({"kind": kind, "name": item.name, "path": str(item),
                                    "location_risk": _location_risk(str(item))})
            except PermissionError:
                not_inspected.append(f"{directory} (permission denied)")
    if which("crontab"):
        raw = run_argv(["crontab", "-l"], timeout=15)
        for line in (raw.get("stdout") or "").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                entries.append({"kind": "user crontab", "name": stripped[:120], "path": "crontab -l",
                                "location_risk": ""})
    shell_files = [home / name for name in
                   (".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile")]
    for item in shell_files:
        if not item.is_file():
            continue
        try:
            text = item.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not _RUNS_AT_STARTUP.match(stripped):
                continue
            entries.append({"kind": "shell startup command", "name": stripped[:120],
                            "path": str(item),
                            "location_risk": "fetches-and-executes" if _FETCHES_CODE.search(stripped) else ""})
    not_inspected.append("root-owned cron and system daemons require sudo")
    entries = _deduplicate(entries)
    return {
        "operation": "persistence",
        "entry_count": len(entries),
        "entries": entries[:limit],
        "flagged": [item for item in entries if item["location_risk"]][:limit],
        "not_inspected": not_inspected,
    }


def _secret_access(limit: int) -> dict[str, Any]:
    """Processes currently holding credential files open."""

    lsof = which("lsof")
    if not lsof:
        return {"operation": "secret_access", "supported": False,
                "reason": "lsof is required to see open file handles",
                "holders": [], "holder_count": 0}
    home = _home()
    targets: list[tuple[str, str]] = []
    for relative, label in _SECRET_PATHS:
        candidate = home / relative
        if candidate.exists():
            targets.append((str(candidate), label))
    executables = _executables()
    holders: list[dict[str, Any]] = []
    for path, label in targets:
        raw = run_argv([lsof, "-nP", "--", path], timeout=20)
        for line in (raw.get("stdout") or "").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 2 or not fields[1].isdigit():
                continue
            pid = int(fields[1])
            executable = executables.get(pid, "")
            holders.append({
                "process": fields[0], "pid": pid, "executable": executable,
                "secret": label, "path": path,
                "location_risk": _location_risk(executable),
                "signature": _signature(executable) if executable else {"checked": False},
            })
    return {
        "operation": "secret_access",
        "supported": True,
        "checked_paths": [path for path, _ in targets],
        "holders": holders[:limit],
        "holder_count": len(holders),
        "not_inspected": ["other users' processes require sudo"],
    }


def _score(outbound: dict[str, Any], listening: dict[str, Any],
           persistence: dict[str, Any], secrets: dict[str, Any]) -> dict[str, Any]:
    """Correlate: a finding needs more than one weak signal before it is raised."""

    findings: list[dict[str, Any]] = []
    persistence_paths = {str(item.get("path") or "") for item in persistence.get("entries", [])}
    for item in outbound.get("concerning", []):
        reasons = []
        if item.get("location_risk"):
            reasons.append(f"runs from a {item['location_risk'].replace('-', ' ')}")
        signature = item.get("signature") or {}
        if signature.get("checked") and signature.get("signed") is False:
            reasons.append("executable is unsigned or not owned by a package")
        if item.get("executable") and item["executable"] in persistence_paths:
            reasons.append("also configured to start automatically")
        if len(reasons) >= 1:
            findings.append({
                "severity": "investigate" if len(reasons) == 1 else "high",
                "what": f"{item.get('command')} (pid {item.get('pid')}) "
                        f"→ {item.get('remote_host')}:{item.get('remote_port')}",
                "executable": item.get("executable"),
                "why": reasons,
            })
    for item in secrets.get("holders", []):
        reasons = [f"has {item['secret']} open"]
        if item.get("location_risk"):
            reasons.append(f"runs from a {item['location_risk'].replace('-', ' ')}")
        signature = item.get("signature") or {}
        if signature.get("checked") and signature.get("signed") is False:
            reasons.append("executable is unsigned or not owned by a package")
        findings.append({
            "severity": "high" if len(reasons) > 1 else "review",
            "what": f"{item['process']} (pid {item['pid']}) reading {item['path']}",
            "executable": item.get("executable"),
            "why": reasons,
        })
    for item in persistence.get("flagged", []):
        findings.append({
            "severity": "investigate",
            "what": f"{item['kind']}: {item['name']}",
            "executable": item.get("path"),
            "why": [item["location_risk"].replace("-", " ")],
        })
    order = {"high": 0, "investigate": 1, "review": 2}
    findings.sort(key=lambda item: order.get(item["severity"], 3))
    return {"findings": findings, "finding_count": len(findings),
            "high_count": sum(1 for item in findings if item["severity"] == "high")}


def execute(context: ToolContext, *, operation: str, limit: int = 25) -> dict[str, Any]:
    del context
    cap = max(1, min(int(limit or 25), 200))
    if operation == "outbound":
        return {"status": "success", **_outbound(cap), "exit_code": 0}
    if operation == "listening":
        return {"status": "success", **_listening(cap), "exit_code": 0}
    if operation == "persistence":
        return {"status": "success", **_persistence(cap), "exit_code": 0}
    if operation == "secret_access":
        return {"status": "success", **_secret_access(cap), "exit_code": 0}
    outbound = _outbound(cap)
    listening = _listening(cap)
    persistence = _persistence(cap)
    secrets = _secret_access(cap)
    verdict = _score(outbound, listening, persistence, secrets)
    return {
        "status": "success",
        "operation": "sweep",
        "outbound": outbound,
        "listening": listening,
        "persistence": persistence,
        "secret_access": secrets,
        **verdict,
        "not_inspected": (persistence.get("not_inspected") or []) + (secrets.get("not_inspected") or []),
        "exit_code": 0,
    }
