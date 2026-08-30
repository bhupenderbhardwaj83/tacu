"""Inspect local OS processes with platform-native recipes and Python ranking."""

from __future__ import annotations

from typing import Any

from ..host_parsers import parse_ps, sort_processes
from ..platform import process_list_argv_with_header, run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "process",
    "Inspect and manage local OS processes. Use for CPU/RAM usage, PID lookup, process details, "
    "and controlled termination. Prefer this over shell for process-related questions.",
    schema(properties={
        "operation": {"type": "string", "enum": ["top_cpu", "top_memory", "list", "find", "inspect",
                                                 "tree", "open_files", "kill"]},
        "limit": {"type": "integer"},
        "pid": {"type": "integer"},
        "query": {"type": "string"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"},
                       "processes": {"type": "array"}, "count": {"type": "integer"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)


def _list_processes() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = run_argv(process_list_argv_with_header(), timeout=SPEC.timeout)
    if raw["exit_code"] in {126, 127}:
        raise ToolFailure(raw["stderr"] or "ps is unavailable", code="unavailable")
    if raw["exit_code"] not in {0, 1}:
        raise ToolFailure(raw["stderr"] or "ps failed", code="failed")
    processes = parse_ps(raw["stdout"])
    return processes, raw


def execute(context: ToolContext, *, operation: str, limit: int = 10, pid: int | None = None,
            query: str | None = None) -> dict[str, Any]:
    from .contracts import require_approval

    cap = max(1, min(int(limit or 10), 50))
    if operation == "kill":
        require_approval(context, "process.kill")
        if pid is None:
            raise ToolFailure("kill requires pid.", code="invalid_arguments")
        import os
        import signal
        try:
            os.kill(int(pid), signal.SIGTERM)
        except ProcessLookupError as error:
            raise ToolFailure(f"No process with pid {pid}.", code="not_found") from error
        except PermissionError as error:
            raise ToolFailure(f"Permission denied killing pid {pid}.", code="permission") from error
        return {"status": "success", "operation": "kill", "pid": int(pid), "signal": "SIGTERM", "exit_code": 0}
    processes, raw = _list_processes()
    if operation == "open_files":
        if pid is None:
            raise ToolFailure("open_files requires pid.", code="invalid_arguments")
        lsof = which("lsof") or "lsof"
        opened = run_argv([lsof, "-nP", "-p", str(pid)], timeout=SPEC.timeout)
        rows = [line for line in opened["stdout"].splitlines()[1:] if line.strip()][:cap]
        return {"status": "success" if opened["exit_code"] in {0, 1} else "error", "operation": operation,
                "pid": pid, "open_files": rows, "count": len(rows), "exit_code": 0 if opened["exit_code"] in {0, 1} else opened["exit_code"]}
    if operation == "tree":
        by_pid = {item.get("pid"): item for item in processes if item.get("pid") is not None}
        children: dict[int, list[dict[str, Any]]] = {}
        for item in processes:
            parent = item.get("ppid")
            if isinstance(parent, int):
                children.setdefault(parent, []).append(item)
        root_pid = pid if pid is not None else 1
        nodes = []
        def walk(current: int, depth: int) -> None:
            item = by_pid.get(current)
            if not item or depth > 6 or len(nodes) >= cap:
                return
            nodes.append({"pid": current, "ppid": item.get("ppid"), "command": item.get("command"), "depth": depth})
            for child in children.get(current, [])[:12]:
                child_pid = child.get("pid")
                if isinstance(child_pid, int):
                    walk(child_pid, depth + 1)
        if root_pid in by_pid:
            walk(root_pid, 0)
        elif pid is not None:
            match = by_pid.get(pid)
            if match:
                nodes.append({"pid": pid, "ppid": match.get("ppid"), "command": match.get("command"), "depth": 0})
        return {"status": "success" if nodes else "no_results", "operation": operation, "pid": root_pid,
                "processes": nodes, "count": len(nodes), "exit_code": 0}
    if operation == "inspect":
        if pid is None:
            raise ToolFailure("inspect requires pid.", code="invalid_arguments")
        matches = [item for item in processes if item.get("pid") == pid]
        return {"status": "success" if matches else "no_results", "operation": operation,
                "processes": matches, "count": len(matches), "recipe": raw.get("command"),
                "exit_code": 0}
    if operation == "find":
        needle = (query or "").strip().casefold()
        if not needle:
            raise ToolFailure("find requires query.", code="invalid_arguments")
        matches = [item for item in processes
                   if needle in (item.get("command") or "").casefold()
                   or needle in (item.get("executable") or "").casefold()
                   or needle == str(item.get("pid"))]
        return {"status": "success" if matches else "no_results", "operation": operation,
                "query": query, "processes": matches[:cap], "count": min(len(matches), cap),
                "recipe": raw.get("command"), "exit_code": 0}
    key = "memory" if operation == "top_memory" else "cpu"
    ranked = processes if operation == "list" else sort_processes(processes, key=key, limit=cap)
    if operation == "list":
        ranked = ranked[:cap]
    status = "success" if ranked else "no_results"
    return {
        "status": status,
        "operation": operation,
        "metric": key if operation.startswith("top_") else "list",
        "processes": ranked,
        "count": len(ranked),
        "top": ranked[0] if ranked else None,
        "recipe": raw.get("command"),
        "exit_code": 0,
    }
