"""Workspace-owned background processes with loopback HTTP readiness checks."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..managed import atomic_json, workspace_key
from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "service_process", "Start, check, inspect logs, or stop a managed local HTTP server.",
    schema(properties={
        "operation": {"type": "string", "enum": ["start", "check", "logs", "stop"]},
        "executable": {"type": "string"}, "args": {"type": "array"}, "cwd": {"type": "string"},
        "service_id": {"type": "string"}, "health_url": {"type": "string"},
        "expected_status": {"type": "integer"}, "contains": {"type": "string"},
        "timeout": {"type": "integer"},
    }, required=("operation",)),
    schema(properties={"service_id": {"type": "string"}, "healthy": {"type": "boolean"},
                       "url": {"type": "string"}, "state": {"type": "string"}}),
    timeout=30, risk_level="execute", permissions=("workspace:read", "command:execute"), idempotent=False,
    when_to_use="Run a server in the background and prove an HTTP endpoint responds. Use a direct foreground server command; no fork/nohup wrappers.",
    when_not="Not for remote endpoints, system services, arbitrary PIDs, or one-shot checks (verify).",
)


_SUPERVISORS: dict[str, subprocess.Popen] = {}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def local_url(url: str) -> tuple[str, int]:
    try:
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as error:
        raise ToolFailure("Invalid health URL.", code="invalid_input") from error
    if (parts.scheme not in {"http", "https"} or parts.hostname not in {"127.0.0.1", "::1", "localhost"}
            or parts.username or parts.password or parts.fragment):
        raise ToolFailure("health_url must be HTTP(S) on 127.0.0.1, ::1 or localhost.", code="invalid_input")
    return parts.hostname, port


def probe(url: str, expected_status: int, contains: str) -> tuple[bool, str]:
    local_url(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(url, timeout=1) as response:
            text = response.read(65536).decode(errors="replace")
            ok = response.status == expected_status and (not contains or contains in text)
            return ok, f"HTTP {response.status}" + ("; expected content missing" if contains and contains not in text else "")
    except (OSError, urllib.error.URLError) as error:
        return False, str(error)[:300]


def _record(context: ToolContext, service_id: str) -> tuple[Path, dict]:
    if not re.fullmatch(r"[a-f0-9]{32}", service_id):
        raise ToolFailure("Use the service_id returned by start.", code="invalid_input")
    path = context.state_dir / "services" / workspace_key(context.workspace) / service_id / "record.json"
    try:
        return path, json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise ToolFailure("No managed service with that ID in this workspace.", code="not_found") from error


def _logs(path: Path) -> dict[str, str]:
    result = {}
    for name in ("stdout", "stderr"):
        try:
            with (path.parent / f"{name}.log").open("rb") as stream:
                stream.seek(max(0, stream.seek(0, 2) - 4000))
                result[name] = stream.read(4000).decode(errors="replace")
        except OSError:
            result[name] = ""
    return result


def execute(context: ToolContext, *, operation: str, executable: str = "", args: list[str] | None = None,
            cwd: str = ".", service_id: str = "", health_url: str = "", expected_status: int = 200,
            contains: str = "", timeout: int = 20) -> dict[str, Any]:
    import uuid

    if operation == "start":
        host, port = local_url(health_url)
        working = context.guarded_path(cwd)
        binary = executable if "/" in executable or "\\" in executable else shutil.which(executable)
        if not binary:
            raise ToolFailure(f"Command not found: {executable}", code="command_not_found")
        try:
            with socket.create_connection((host, port), timeout=0.3):
                raise ToolFailure("The health port is already occupied. Choose a free port; do not claim another server as this job.", code="port_in_use")
        except OSError:
            pass
        service_id = uuid.uuid4().hex
        path = context.state_dir / "services" / workspace_key(context.workspace) / service_id / "record.json"
        record = {"state": "starting", "command": [binary, *(args or [])], "cwd": str(working),
                  "url": health_url, "expected_status": expected_status, "contains": contains,
                  "heartbeat": time.time()}
        atomic_json(path, record)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2]) + os.pathsep + environment.get("PYTHONPATH", "")
        # The supervisor and child use real log files and no inherited terminal pipes.
        supervisor = subprocess.Popen([sys.executable, "-m", "tacu.managed", str(path)],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      start_new_session=os.name != "nt", env=environment)
        _SUPERVISORS[service_id] = supervisor
        deadline = time.monotonic() + max(1, min(timeout, 60))
        detail = "server did not become ready"
        while time.monotonic() < deadline:
            _, record = _record(context, service_id)
            if record["state"] in {"error", "exited"}:
                break
            if record["state"] == "running":
                healthy, detail = probe(health_url, expected_status, contains)
                if healthy:
                    return {"service_id": service_id, "state": "running", "healthy": True,
                            "url": health_url, "check": detail, "log_directory": str(path.parent)}
            time.sleep(0.1)
        (path.parent / "stop").touch()
        try:
            supervisor.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return {"status": "error", "service_id": service_id, "healthy": False,
                "error": record.get("error") or detail, **_logs(path)}

    path, record = _record(context, service_id)
    if operation == "stop":
        (path.parent / "stop").touch()
        deadline = time.monotonic() + 5
        while record["state"] in {"starting", "running"} and time.monotonic() < deadline:
            time.sleep(0.1)
            _, record = _record(context, service_id)
        supervisor = _SUPERVISORS.pop(service_id, None)
        if supervisor is not None:
            try:
                supervisor.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _SUPERVISORS[service_id] = supervisor
        return {"service_id": service_id, "state": record["state"], "healthy": False,
                "stopped": record["state"] in {"exited", "error"}}
    if operation == "logs":
        return {"service_id": service_id, "state": record["state"], **_logs(path)}
    if operation != "check":
        raise ToolFailure("Unknown service operation.", code="invalid_input")
    healthy = False
    detail = "managed process is not running"
    if record["state"] == "running" and time.time() - record["heartbeat"] < 5:
        healthy, detail = probe(record["url"], record["expected_status"], record["contains"])
    return {"service_id": service_id, "state": record["state"], "url": record["url"],
            "healthy": healthy, "check": detail, **({} if healthy else _logs(path))}
