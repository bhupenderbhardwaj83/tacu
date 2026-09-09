"""Inspect local Docker Engine with argument-safe recipes (no empty argv tokens)."""

from __future__ import annotations

from typing import Any

from ..platform import run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, require_approval, require_named_target, schema

SPEC = ToolSpec(
    "docker",
    "Inspect and control Docker containers, images, networks, volumes, daemon info, "
    "disk usage, processes and ports. Prefer this over invented docker flags. Anything "
    "that changes state — start, stop, restart, kill, pause, rm, rmi, pull, prune, exec — "
    "requires review.",
    schema(properties={
        "operation": {"type": "string", "enum": [
            # Reading
            "ps", "containers", "images", "logs", "inspect", "stats", "networks", "volumes",
            "info", "version", "disk_usage", "top", "port", "history", "events", "compose_ps",
            # Changing — reviewed only
            "start", "stop", "rm", "rmi", "pull", "restart", "kill", "pause", "unpause",
            "prune", "exec",
        ]},
        "all_containers": {"type": "boolean"},
        "name": {"type": "string"},
        "limit": {"type": "integer"},
        "command": {"type": "string"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)

_MUTATE = frozenset({"start", "stop", "rm", "rmi", "pull", "restart", "kill",
                     "pause", "unpause", "prune", "exec"})
# A command run inside a container is arbitrary code, so it is split on the
# harness side and never handed to a shell as one string.
_EXEC_UNSAFE = ("&&", "||", ";", "|", "`", "$(", ">", "<")
_INSPECT_FORMAT = (
    "{{.Name}}\t{{.Config.Image}}\t{{.State.Status}}\t{{.Id}}\t"
    "{{range $n, $c := .NetworkSettings.Networks}}{{$n}}={{if $c.IPAddress}}{{$c.IPAddress}}{{else}}-{{end}} {{end}}"
)
_PS_FORMAT = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Networks}}"


def _need_docker() -> None:
    if not which("docker"):
        raise ToolFailure("docker is not installed or not on PATH.", code="unavailable")


def _parse_inspect(stdout: str, fallback: str) -> dict[str, Any]:
    parts = stdout.strip().split("\t")
    networks = (parts[4].strip() if len(parts) > 4 else "") or None
    return {
        "name": parts[0].lstrip("/") if parts else fallback,
        "image": parts[1] if len(parts) > 1 else None,
        "status": parts[2] if len(parts) > 2 else None,
        "id": parts[3] if len(parts) > 3 else None,
        "network": networks,
    }


def _inspect_one(needle: str, timeout: int) -> dict[str, Any]:
    raw = run_argv(["docker", "inspect", "--format", _INSPECT_FORMAT, needle], timeout=timeout)
    info = _parse_inspect(raw["stdout"], needle)
    info["exit_code"] = raw["exit_code"]
    info["stderr"] = (raw.get("stderr") or "")[-500:]
    return info


def _list_containers(*, all_containers: bool, cap: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    argv = ["docker", "ps", "--format", _PS_FORMAT]
    if all_containers:
        argv.insert(2, "-a")
    raw = run_argv(argv, timeout=SPEC.timeout)
    rows: list[dict[str, Any]] = []
    for line in raw["stdout"].splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            rows.append({
                "id": parts[0], "name": parts[1], "image": parts[2], "status": parts[3],
                "ports": parts[4] if len(parts) > 4 else "",
                "network": parts[5] if len(parts) > 5 else "",
            })
    return rows[:cap], raw


def execute(context: ToolContext, *, operation: str, command: str | None = None, all_containers: bool = False,
            name: str | None = None, limit: int = 20) -> dict[str, Any]:
    _need_docker()
    cap = max(1, min(int(limit or 20), 80))
    if operation in _MUTATE:
        require_approval(
            context, f"docker.{operation}",
            f"Run it through the reviewed lane: ti do docker {operation}"
            + (f" {name}" if name else "")
            + f" — or yourself: docker {operation}" + (f" {name}" if name else "") + ".")
        if operation == "prune":
            # Never `-a`: pruning images that merely have no container attached
            # deletes work people expect to still be there.
            argv = ["docker", "system", "prune", "-f"]
            raw = run_argv(argv, timeout=300)
            return {"status": "success" if raw["exit_code"] == 0 else "error",
                    "operation": operation, "reclaimed": (raw["stdout"] or "").strip()[-2000:],
                    "exit_code": raw["exit_code"], "stderr": raw.get("stderr", "")[-2000:],
                    "recipe": argv}
        needle = require_named_target(name, f"docker.{operation}")
        if operation == "exec":
            wanted = (command or "").strip()
            if not wanted:
                raise ToolFailure("docker.exec requires command.", code="invalid_arguments")
            if any(token in wanted for token in _EXEC_UNSAFE):
                raise ToolFailure(
                    "docker.exec runs one argument-safe command; shell operators are not "
                    "passed through. Run them as separate steps.", code="invalid_arguments")
            import shlex

            try:
                words = shlex.split(wanted)
            except ValueError as error:
                raise ToolFailure(f"docker.exec could not read the command: {error}",
                                  code="invalid_arguments") from error
            if not words:
                raise ToolFailure("docker.exec requires command.", code="invalid_arguments")
            argv = ["docker", "exec", needle, *words]
            raw = run_argv(argv, timeout=SPEC.timeout)
            return {"status": "success" if raw["exit_code"] == 0 else "error",
                    "operation": operation, "name": needle, "command": wanted,
                    "stdout": (raw["stdout"] or "").strip()[-4000:],
                    "exit_code": raw["exit_code"], "stderr": raw.get("stderr", "")[-2000:],
                    "recipe": argv}
        timeout = 600 if operation == "pull" else SPEC.timeout
        argv = ["docker", "pull" if operation == "pull" else operation, needle]
        raw = run_argv(argv, timeout=timeout)
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "name": needle, "exit_code": raw["exit_code"], "stderr": raw.get("stderr", "")[-2000:],
                "recipe": argv}
    if operation in {"info", "version", "disk_usage", "events"}:
        argv = {"info": ["docker", "info", "--format", "{{json .}}"],
                "version": ["docker", "version", "--format", "{{json .}}"],
                "disk_usage": ["docker", "system", "df"],
                "events": ["docker", "events", "--since", "30m", "--until", "0s"]}[operation]
        raw = run_argv(argv, timeout=SPEC.timeout)
        body = (raw["stdout"] or "").strip()
        payload: Any = body
        if operation in {"info", "version"} and body.startswith("{"):
            import json as _json

            try:
                payload = _json.loads(body)
            except ValueError:
                payload = body
        key = {"info": "info", "version": "version",
               "disk_usage": "disk_usage", "events": "events"}[operation]
        if operation in {"disk_usage", "events"}:
            payload = [line for line in body.splitlines() if line.strip()][:cap]
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                key: payload, "exit_code": raw["exit_code"],
                "stderr": raw.get("stderr", "")[-1000:], "recipe": argv}
    if operation in {"ps", "containers"}:
        rows, raw = _list_containers(all_containers=all_containers or operation == "containers", cap=cap)
        needle = (name or "").strip().casefold()
        if needle:
            rows = [
                item for item in rows
                if needle in (item.get("name") or "").casefold()
                or needle in (item.get("id") or "").casefold()
            ]
        return {"status": "success" if raw["exit_code"] == 0 else "error",
                "operation": "containers" if operation == "containers" else "ps",
                "containers": rows, "count": len(rows), "exit_code": raw["exit_code"],
                "stderr": raw.get("stderr", ""), "recipe": raw.get("command")}
    if operation == "images":
        raw = run_argv(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}"],
                       timeout=SPEC.timeout)
        rows = []
        for line in raw["stdout"].splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                rows.append({"image": parts[0], "id": parts[1], "size": parts[2]})
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "images": rows[:cap], "count": min(len(rows), cap), "exit_code": raw["exit_code"],
                "stderr": raw.get("stderr", "")}
    if operation == "networks":
        raw = run_argv(["docker", "network", "ls", "--format", "{{.Name}}\t{{.Driver}}\t{{.Scope}}"],
                       timeout=SPEC.timeout)
        rows = []
        for line in raw["stdout"].splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                rows.append({"name": parts[0], "driver": parts[1], "scope": parts[2] if len(parts) > 2 else ""})
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "networks": rows[:cap], "count": min(len(rows), cap), "exit_code": raw["exit_code"]}
    if operation == "volumes":
        raw = run_argv(["docker", "volume", "ls", "--format", "{{.Name}}\t{{.Driver}}"], timeout=SPEC.timeout)
        rows = []
        for line in raw["stdout"].splitlines():
            parts = line.split("\t")
            if len(parts) >= 1 and parts[0]:
                rows.append({"name": parts[0], "driver": parts[1] if len(parts) > 1 else ""})
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "volumes": rows[:cap], "count": min(len(rows), cap), "exit_code": raw["exit_code"]}
    if operation == "compose_ps":
        argv = ["docker", "compose", "ps", "--format", "{{.Name}}\t{{.Service}}\t{{.Status}}"]
        raw = run_argv(argv, timeout=SPEC.timeout)
        rows = []
        for line in raw["stdout"].splitlines():
            parts = line.split("\t")
            if parts and parts[0].strip():
                rows.append({"name": parts[0],
                             "service": parts[1] if len(parts) > 1 else "",
                             "status": parts[2] if len(parts) > 2 else ""})
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "services": rows[:cap], "count": len(rows), "exit_code": raw["exit_code"],
                "stderr": raw.get("stderr", "")[-1000:], "recipe": argv}
    needle = (name or "").strip()
    if operation == "inspect":
        if needle:
            info = _inspect_one(needle, SPEC.timeout)
            return {"status": "success" if info.get("exit_code") == 0 else "error", "operation": operation,
                    "containers": [info], "inspect": info, "count": 1, "exit_code": info.get("exit_code")}
        rows, raw = _list_containers(all_containers=False, cap=cap)
        infos = [_inspect_one(item.get("id") or item.get("name") or "", SPEC.timeout)
                 for item in rows if item.get("id") or item.get("name")]
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "containers": infos, "count": len(infos), "exit_code": raw["exit_code"]}
    if not needle:
        raise ToolFailure(f"docker.{operation} requires name.", code="invalid_arguments")
    if operation in {"top", "port", "history"}:
        argv = {"top": ["docker", "top", needle],
                "port": ["docker", "port", needle],
                "history": ["docker", "history", "--no-trunc", needle]}[operation]
        raw = run_argv(argv, timeout=SPEC.timeout)
        rows = [line.rstrip() for line in raw["stdout"].splitlines() if line.strip()][:cap]
        key = {"top": "processes", "port": "ports", "history": "layers"}[operation]
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "name": needle, key: rows, "count": len(rows), "exit_code": raw["exit_code"],
                "stderr": raw.get("stderr", "")[-1000:], "recipe": argv}
    if operation == "logs":
        raw = run_argv(["docker", "logs", "--tail", str(cap), needle], timeout=SPEC.timeout)
        lines = raw["stdout"].splitlines()[-cap:]
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "name": needle, "logs": lines, "count": len(lines), "exit_code": raw["exit_code"],
                "stderr": raw.get("stderr", "")[-1000:]}
    raw = run_argv(["docker", "stats", "--no-stream", "--format",
                    "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}", needle], timeout=SPEC.timeout)
    parts = raw["stdout"].strip().split("\t")
    stats = {"name": parts[0] if parts else needle, "cpu": parts[1] if len(parts) > 1 else None,
             "memory": parts[2] if len(parts) > 2 else None, "memory_percent": parts[3] if len(parts) > 3 else None}
    return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
            "stats": stats, "containers": [stats], "exit_code": raw["exit_code"]}
