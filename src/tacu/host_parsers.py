"""Deterministic parsers for host inspection commands (ps, lsof, netstat, ollama)."""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from typing import Any


def _header_columns(header: str) -> list[tuple[str, int]]:
    return [(match.group(0), match.start()) for match in re.finditer(r"\S+", header)]


def _row_fields(line: str, columns: list[tuple[str, int]]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for index, (name, start) in enumerate(columns):
        end = columns[index + 1][1] if index + 1 < len(columns) else len(line)
        fields[name.casefold()] = line[start:end].strip()
    return fields


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(re.sub(r"[^\d-]", "", value) or 0)
    except ValueError:
        return None


def _float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value.replace("%", "").strip())
    except ValueError:
        return None


def looks_like_ps(text: str, command: str = "") -> bool:
    lowered = (command + "\n" + text[:400]).casefold()
    if re.search(r"(^|[/\s])ps(\s|$)", command.casefold()) or "tasklist" in command.casefold():
        return True
    return bool(re.search(r"(?im)^(?:USER\s+PID|PID\s+PPID|Image Name,PID)\b", text))


def looks_like_network_table(text: str, command: str = "") -> bool:
    lowered = command.casefold()
    if any(name in lowered for name in ("lsof", "netstat", " ss ", "\nss ", "ss -")):
        return True
    return bool(re.search(r"(?im)^(COMMAND\s+PID\s+USER|Proto\s+Recv-Q|State\s+Recv-Q|Active Internet connections)", text))


def parse_ps(text: str) -> list[dict[str, Any]]:
    """Parse BSD/GNU `ps` tables or Windows `tasklist /FO CSV` into process objects."""

    stripped = text.strip()
    if not stripped:
        return []
    first = stripped.splitlines()[0]
    if first.lstrip().startswith('"') or (first.count(",") >= 4 and "PID" in first):
        windows = _parse_tasklist_csv(stripped)
        if windows:
            return windows
    lines = [line for line in stripped.splitlines() if line.strip()]
    if not lines:
        return []
    header = lines[0]
    if not re.search(r"(?i)\bpid\b", header):
        return []
    bsd = re.compile(
        r"^\s*(\d+)\s+(\d+)\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+(\d+)\s+(.*\S)\s*$"
    )
    gnu_aux = re.compile(
        r"^\s*(\S+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+\d+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(.*\S)\s*$"
    )
    processes: list[dict[str, Any]] = []
    header_l = header.casefold()
    use_gnu = "user" in header_l and header_l.strip().startswith("user") and "vsz" in header_l
    for line in lines[1:]:
        if use_gnu:
            match = gnu_aux.match(line)
            if not match:
                continue
            user, pid, cpu, mem, rss, command = match.groups()
            ppid = None
        else:
            match = bsd.match(line)
            if not match:
                continue
            pid, ppid, user, cpu, mem, rss, command = match.groups()
        processes.append({
            "pid": int(pid),
            "ppid": int(ppid) if ppid is not None else None,
            "user": user,
            "cpu_percent": _float(cpu),
            "memory_percent": _float(mem),
            "rss_bytes": int(rss) * 1024,
            "rss_kib": int(rss),
            "command": command.strip(),
            "executable": command.split()[0] if command.strip() else "",
        })
    return processes


def _parse_tasklist_csv(text: str) -> list[dict[str, Any]]:
    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error:
        return []
    processes: list[dict[str, Any]] = []
    for row in reader:
        pid = _int(row.get("PID") or row.get("pid"))
        if pid is None:
            continue
        mem = row.get("Mem Usage") or row.get("Memory Usage") or ""
        kib = _int(mem.replace(",", "").replace("K", "").replace("k", ""))
        processes.append({
            "pid": pid,
            "ppid": None,
            "user": row.get("User Name") or row.get("Username") or "",
            "cpu_percent": None,
            "memory_percent": None,
            "rss_bytes": kib * 1024 if kib is not None else None,
            "rss_kib": kib,
            "command": row.get("Image Name") or row.get("ImageName") or "",
            "executable": row.get("Image Name") or "",
        })
    return processes


def sort_processes(processes: list[dict[str, Any]], *, key: str, limit: int = 10) -> list[dict[str, Any]]:
    if key == "memory":
        ranked = sorted(processes, key=lambda item: (item.get("rss_bytes") or 0, item.get("memory_percent") or 0), reverse=True)
    else:
        ranked = sorted(processes, key=lambda item: (item.get("cpu_percent") or 0, item.get("rss_bytes") or 0), reverse=True)
    return ranked[: max(1, min(limit, 50))]


def _split_hostport(value: str) -> tuple[str | None, int | None]:
    text = value.strip().strip("[]")
    if not text or text in {"*", "0.0.0.0", "::", "::1"} and ":" not in value and "." not in value:
        return (text or None, None)
    if text.count(":") > 1:
        if text.startswith("[") and "]:" in value:
            host, _, port = value.partition("]:")
            return host.strip("[]"), _int(port)
        host, _, port = text.rpartition(":")
        return host or None, _int(port)
    if ":" in text:
        host, _, port = text.rpartition(":")
        return host or None, _int(port)
    match = re.match(r"^(.+)\.(\d+)$", text)
    if match and match.group(1).count(".") >= 1:
        return match.group(1), _int(match.group(2))
    return text, None


# lsof right-aligns PID and USER, so a wide pid or a long username overflows the
# slice implied by the header and silently corrupts both (2758 -> 758). Every field
# up to NAME is whitespace-delimited and lsof escapes spaces in COMMAND as \x20,
# so anchoring on the pid is exact where fixed-width slicing is not.
_LSOF_ROW = re.compile(
    r"^(?P<command>\S.*?)\s+(?P<pid>\d+)\s+(?P<user>\S+)\s+(?P<fd>\S+)\s+(?P<type>\S+)"
    r"\s+(?P<device>\S+)\s+(?P<size>\S+)\s+(?P<node>\S+)\s+(?P<name>\S.*)$"
)


def _lsof_fields(line: str, columns: Any) -> dict[str, str] | None:
    match = _LSOF_ROW.match(line.rstrip())
    if match:
        return {key: value.strip() for key, value in match.groupdict().items()}
    return None


def parse_lsof_network(text: str) -> list[dict[str, Any]]:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    header = lines[0]
    if "COMMAND" not in header.upper() or "NAME" not in header.upper():
        return []
    columns = _header_columns(header)
    connections: list[dict[str, Any]] = []
    for line in lines[1:]:
        fields = _lsof_fields(line, columns) or _row_fields(line, columns)
        name = fields.get("name") or ""
        state_match = re.search(r"\(([^)]+)\)\s*$", name)
        state = (state_match.group(1) if state_match else "").upper() or None
        endpoint = name[:state_match.start()].strip() if state_match else name
        local_raw, remote_raw = (endpoint.split("->", 1) + [""])[:2]
        local_host, local_port = _split_hostport(local_raw.replace("TCP ", "").replace("UDP ", "").strip())
        remote_host, remote_port = _split_hostport(remote_raw.strip()) if remote_raw else (None, None)
        protocol = "tcp" if "TCP" in name.upper() or "TCP" in (fields.get("node") or "").upper() else "udp"
        if "TCP" in line.upper():
            protocol = "tcp"
        connections.append({
            "command": fields.get("command") or "",
            "pid": _int(fields.get("pid")),
            "user": fields.get("user") or "",
            "protocol": protocol,
            "state": state,
            "local_host": local_host,
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "name": name,
        })
    return connections


def parse_netstat(text: str) -> list[dict[str, Any]]:
    connections: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = re.match(
            r"^(tcp\d*|udp\d*|tcp|udp|tcp6|udp6)\s+\S+\s+\S+\s+(\S+)\s+(\S+)(?:\s+(\S+))?",
            line.strip(), re.I,
        )
        if not match:
            continue
        protocol, local_raw, remote_raw, state = match.group(1).lower(), match.group(2), match.group(3), (match.group(4) or "").upper()
        if remote_raw in {"*.*", "*:*", "0.0.0.0:*"} and not state:
            state = "LISTEN"
        local_host, local_port = _split_hostport(local_raw)
        remote_host, remote_port = _split_hostport(remote_raw)
        if remote_raw in {"*.*", "*:*"}:
            remote_host, remote_port = None, None
            state = state or "LISTEN"
        connections.append({
            "command": "",
            "pid": None,
            "user": "",
            "protocol": "tcp" if protocol.startswith("tcp") else "udp",
            "state": state or None,
            "local_host": local_host,
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "name": line.strip(),
        })
    return connections


def parse_network_table(text: str, command: str = "") -> list[dict[str, Any]]:
    if looks_like_network_table(text, command) or "COMMAND" in text[:80].upper():
        parsed = parse_lsof_network(text)
        if parsed:
            return parsed
    return parse_netstat(text)


def summarize_destination_ports(connections: list[dict[str, Any]], *,
                                state: str | None = "ESTABLISHED", limit: int = 10) -> list[dict[str, Any]]:
    wanted = [item for item in connections
              if item.get("remote_port")
              and (state is None or (item.get("state") or "").upper() == state.upper())]
    counts: Counter[int] = Counter(int(item["remote_port"]) for item in wanted if item.get("remote_port"))
    ranked: list[dict[str, Any]] = []
    for port, count in counts.most_common(max(1, min(limit, 50))):
        hosts = []
        for item in wanted:
            if int(item["remote_port"]) != port:
                continue
            host = item.get("remote_host")
            if host and host not in hosts:
                hosts.append(host)
        ranked.append({"port": port, "count": count, "hosts": hosts[:8], "host_count": len(hosts)})
    return ranked


def parse_ollama_table(text: str) -> list[dict[str, Any]]:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    columns = _header_columns(lines[0])
    names = [name.casefold() for name, _ in columns]
    if "name" not in names:
        return []
    rows: list[dict[str, Any]] = []
    for line in lines[1:]:
        fields = _row_fields(line, columns)
        name = fields.get("name") or ""
        if not name:
            continue
        rows.append({
            "name": name,
            "id": fields.get("id") or "",
            "size": fields.get("size") or "",
            "processor": fields.get("processor") or fields.get("processor ") or "",
            "until": fields.get("until") or "",
            "parameter_size": fields.get("parameter size") or fields.get("params") or "",
        })
    return rows
