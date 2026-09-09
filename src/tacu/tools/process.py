"""Inspect local OS processes with platform-native recipes and Python ranking."""

from __future__ import annotations

from typing import Any

from .. import procgraph
from ..host_parsers import parse_lsof_network, parse_ps, sort_processes
from ..platform import process_list_argv, process_list_argv_with_header, run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "process",
    "Inspect and manage local OS processes. Use for CPU/RAM usage, PID lookup, process details, "
    "and controlled termination. Prefer this over shell for process-related questions.",
    schema(properties={
        "operation": {"type": "string", "enum": ["top_cpu", "top_memory", "list", "find", "inspect",
                                                 "tree", "open_files", "kill", "graph"]},
        "limit": {"type": "integer"},
        "pid": {"type": "integer"},
        "port": {"type": "integer"},
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


def _graph(*, pid: int | None, port: int | None, query: str | None,
           limit: int) -> dict[str, Any]:
    """Every running process, joined with its lineage and its sockets."""

    raw = run_argv(process_list_argv(), timeout=SPEC.timeout)
    processes = parse_ps(raw["stdout"])
    listening: list[dict[str, Any]] = []
    established: list[dict[str, Any]] = []
    if which("lsof"):
        listen_raw = run_argv([which("lsof") or "lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
                              timeout=SPEC.timeout)
        listening = parse_lsof_network(listen_raw.get("stdout") or "")
        active_raw = run_argv([which("lsof") or "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"],
                              timeout=SPEC.timeout)
        established = parse_lsof_network(active_raw.get("stdout") or "")
    nodes = procgraph.build(processes, listening, established)
    by_pid = {int(item["pid"]): item for item in nodes if item.get("pid") is not None}

    selected = nodes
    focus = "everything"
    widened = ""
    if pid is not None:
        selected = [item for item in nodes if item.get("pid") == pid]
        focus = f"pid {pid}"
    elif port is not None:
        selected = [item for item in nodes
                    if any(entry["port"] == port for entry in item.get("listening") or [])]
        focus = f"port {port}"
    elif query:
        # A guessed value may order these; it may never delete them. The words
        # come from regex over the question, so returning nothing would say the
        # guess matched nothing — never that nothing is running. Six Python
        # servers were listening when the filter "python servers" reported none.
        ranked = [(procgraph.match_detail(item, query), item) for item in nodes]
        best = max((hits for (_score, hits), _item in ranked), default=0)
        focus = query
        if best:
            # Everything answering as many of the asked-for words as the best
            # answer does: a tier, not a threshold. No absolute cut-off that one
            # stray word in the question could push a real match below.
            selected = [item for (_score, hits), item in
                        sorted(ranked, key=lambda row: (-row[0][0],
                                                        int(row[1].get("pid") or 0)))
                        if hits == best]
            answered = procgraph.answered_words(selected[0], query) if selected else []
            missing = [word for word in procgraph.query_words(query) if word not in answered]
            if missing:
                # Eleven processes matching "servers" is not eleven Python
                # servers. Say which half of the question these answer, so a
                # partial match cannot be reported as a whole one.
                widened = (f"nothing matches all of \u201c{query}\u201d; these match "
                           + ", ".join(f"\u201c{word}\u201d" for word in answered)
                           + " but nothing here is named "
                           + " or ".join(f"\u201c{word}\u201d" for word in missing))
        else:
            serving = [item for item in nodes if item.get("listening")]
            selected = serving or nodes
            widened = ("nothing is named like that; these are the processes that "
                       "are listening" if serving else
                       "nothing is named like that; these are all the processes")
    else:
        # With nothing named, the useful answer is what is serving.
        selected = [item for item in nodes if item.get("listening")]
        focus = "listening processes"

    for item in selected[:limit]:
        item["ancestry"] = [
            {"pid": parent.get("pid"), "label": parent.get("label"),
             "command": parent.get("command")}
            for parent in procgraph.ancestry(item, by_pid)
        ]
        item["child_processes"] = [
            {"pid": child, "label": (by_pid.get(child) or {}).get("label")}
            for child in (item.get("children") or [])[:12]
        ]
    servers = [item for item in nodes if item.get("listening")]
    return {
        "status": "success" if selected else "no_results",
        "operation": "graph",
        "focus": focus,
        # Say when the answer is a wider view than the question asked for, so
        # nothing downstream can present it as a match.
        "widened": widened,
        "processes": selected[:limit],
        "count": len(selected),
        "total_processes": len(nodes),
        "server_count": len(servers),
        "recipe": raw.get("command"),
        "exit_code": 0,
    }


def execute(context: ToolContext, *, operation: str, limit: int = 10, pid: int | None = None,
            port: int | None = None, query: str | None = None) -> dict[str, Any]:
    from .contracts import require_approval

    cap = max(1, min(int(limit or 10), 50))
    if operation == "graph":
        return _graph(pid=pid, port=port, query=query, limit=max(1, min(int(limit or 10), 60)))
    if operation == "find" and not (query or "").strip() and pid is None:
        raise ToolFailure(
            "find needs a name to look for, as query. To look one up by number, "
            "use operation inspect with pid.", code="invalid_arguments")
    if operation in {"inspect", "open_files", "tree"} and pid is None:
        raise ToolFailure(f"{operation} requires pid.", code="invalid_arguments")
    if operation == "kill":
        if pid is None:
            raise ToolFailure("kill requires pid.", code="invalid_arguments")
        require_approval(
            context, "process.kill",
            f"Check what it is first: ti ask what is process {pid}. "
            f"Then stop it through the reviewed lane: ti do kill process {pid} — "
            f"or yourself: kill {pid}, and kill -9 {pid} if it ignores that.")
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
        if not needle and pid is not None:
            # A caller that knows the pid but reached for find still means "this one".
            needle = str(pid)
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
