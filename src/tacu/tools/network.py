"""Inspect local network interfaces, sockets, and destination-port rankings."""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.request
from typing import Any

from ..companion import extract_facts
from ..host_parsers import parse_network_table, summarize_destination_ports
from ..platform import listening_tcp_argv, run_argv, tcp_connections_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, schema

SPEC = ToolSpec(
    "network",
    "Inspect local network interfaces, sockets, listening ports, established connections, "
    "routes, public IP, and port ownership. Prefer this over shell for networking inspection.",
    schema(properties={
        "operation": {"type": "string",
                      "enum": ["interfaces", "primary_ip", "public_ip", "listening_ports", "connections",
                               "connections_by_port", "port_owner", "routes", "dns", "arp", "resolve"]},
        "limit": {"type": "integer"},
        "port": {"type": "integer"},
        "state": {"type": "string"},
        "protocol": {"type": "string"},
        "host": {"type": "string"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"}}),
    timeout=20, risk_level="read", permissions=("host:read",),
)

PUBLIC_IP_ENDPOINTS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)


def _public_ip_lookup() -> dict[str, Any]:
    """Bounded GET to an allowlisted echo service. No cookies, no request body, tiny response."""

    last_error = "no echo service responded"
    for url in PUBLIC_IP_ENDPOINTS:
        try:
            request = urllib.request.Request(
                url, method="GET",
                headers={"User-Agent": "TACU/1.2", "Accept": "text/plain"},
            )
            with urllib.request.urlopen(request, timeout=8) as response:
                body = response.read(64).decode("ascii", "ignore").strip().split()[0]
            address = ipaddress.ip_address(body)
            return {
                "status": "success",
                "operation": "public_ip",
                "public_ip": str(address),
                "source": url,
                "exit_code": 0,
            }
        except (urllib.error.URLError, TimeoutError, ValueError, OSError, IndexError) as error:
            last_error = str(error) or type(error).__name__
    raise ToolFailure(f"Could not determine the public IP: {last_error}", code="public_ip_unavailable")


def _connections(*, port: int | None = None, state: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = run_argv(tcp_connections_argv(port=port, state=state), timeout=SPEC.timeout)
    parsed = parse_network_table(raw["stdout"], " ".join(raw.get("command") or []))
    if not parsed and which("netstat"):
        fallback = run_argv([which("netstat") or "netstat", "-an"], timeout=SPEC.timeout)
        parsed = parse_network_table(fallback["stdout"], "netstat -an")
        raw = fallback
    return parsed, raw


def execute(context: ToolContext, *, operation: str, limit: int = 10, port: int | None = None,
            state: str | None = None, protocol: str | None = None, host: str | None = None) -> dict[str, Any]:
    del context
    cap = max(1, min(int(limit or 10), 50))
    if operation == "routes":
        argv = [which("netstat") or "netstat", "-rn"]
        raw = run_argv(argv, timeout=SPEC.timeout)
        rows = [line.strip() for line in raw["stdout"].splitlines() if line.strip()][: cap + 8]
        return {"status": "success" if raw["exit_code"] == 0 else "error", "operation": operation,
                "routes": rows, "count": len(rows), "exit_code": raw["exit_code"], "recipe": raw.get("command")}
    if operation == "dns":
        if which("scutil"):
            raw = run_argv(["scutil", "--dns"], timeout=SPEC.timeout)
            text = "\n".join(raw["stdout"].splitlines()[:60])
            return {"status": "success", "operation": operation, "dns": text, "exit_code": 0,
                    "recipe": raw.get("command")}
        raw = run_argv(["cat", "/etc/resolv.conf"], timeout=SPEC.timeout)
        return {"status": "success", "operation": operation, "dns": raw["stdout"][:2000], "exit_code": 0}
    if operation == "arp":
        raw = run_argv([which("arp") or "arp", "-a"], timeout=SPEC.timeout)
        rows = [line.strip() for line in raw["stdout"].splitlines() if line.strip()][:cap]
        return {"status": "success" if rows else "no_results", "operation": operation, "arp": rows,
                "count": len(rows), "exit_code": 0, "recipe": raw.get("command")}
    if operation == "resolve":
        target = (host or "").strip()
        if not target:
            raise ToolFailure("resolve requires host.", code="invalid_arguments")
        reverse = False
        try:
            ipaddress.ip_address(target)
            reverse = True
        except ValueError:
            pass
        if reverse:
            if which("dig"):
                raw = run_argv(["dig", "+short", "-x", target], timeout=SPEC.timeout)
            elif which("dscacheutil"):
                raw = run_argv(["dscacheutil", "-q", "host", "-a", "ip_address", target], timeout=SPEC.timeout)
            else:
                raw = run_argv([which("host") or "host", target], timeout=SPEC.timeout)
        elif which("dscacheutil"):
            raw = run_argv(["dscacheutil", "-q", "host", "-a", "name", target], timeout=SPEC.timeout)
        else:
            raw = run_argv([which("dig") or "dig", "+short", target], timeout=SPEC.timeout)
        records = raw["stdout"].strip()[:2000]
        return {"status": "success" if records else "no_results", "operation": operation,
                "host": target, "records": records, "reverse": reverse, "exit_code": raw["exit_code"]}
    if operation == "public_ip":
        return _public_ip_lookup()
    if operation in {"interfaces", "primary_ip"}:
        from ..platform import which as which_bin
        command = ["ifconfig"] if which_bin("ifconfig") else (["ip", "-json", "address"] if which_bin("ip") else ["ipconfig"])
        raw = run_argv(command, timeout=SPEC.timeout)
        facts = extract_facts(raw["stdout"], " ".join(command)) or {}
        interfaces = facts.get("interfaces") or []
        primary = facts.get("primary")
        return {
            "status": "success" if interfaces else "no_results",
            "operation": operation,
            "primary": primary,
            "interfaces": interfaces,
            "interface_count": len(interfaces),
            "recipe": raw.get("command"),
            "exit_code": 0,
        }
    if operation == "listening_ports":
        raw = run_argv(listening_tcp_argv(), timeout=SPEC.timeout)
        rows = parse_network_table(raw["stdout"], " ".join(raw.get("command") or []))
        listening = [item for item in rows if (item.get("state") or "").upper() == "LISTEN"]
        if port:
            listening = [item for item in listening if item.get("local_port") == port]
        return {
            "status": "success" if listening else "no_results",
            "operation": operation,
            "listening": listening[:cap],
            "count": min(len(listening), cap),
            "recipe": raw.get("command"),
            "exit_code": 0,
        }
    if operation == "port_owner":
        if not port:
            raise ToolFailure("port_owner requires port.", code="invalid_arguments")
        rows, raw = _connections(port=port, state="LISTEN")
        owners = [item for item in rows if item.get("local_port") == port]
        if not owners:
            rows, raw = _connections(port=port)
            owners = [item for item in rows if item.get("local_port") == port]
        return {
            "status": "success" if owners else "no_results",
            "operation": operation,
            "port": port,
            "owners": owners[:cap],
            "count": min(len(owners), cap),
            "recipe": raw.get("command"),
            "exit_code": 0,
        }
    wanted_state = (state or "ESTABLISHED").upper().replace(" ", "_").replace("-", "_")
    if wanted_state in {"NOT_ESTABLISHED", "OTHER", "EXCEPT_ESTABLISHED"}:
        rows, raw = _connections(port=port, state=None)
        if protocol:
            rows = [item for item in rows if (item.get("protocol") or "").lower() == protocol.lower()]
        rows = [item for item in rows if (item.get("state") or "").upper() not in {"", "ESTABLISHED"}]
        ranked_ports = summarize_destination_ports(rows, state=None, limit=cap)
        return {
            "status": "success" if rows or ranked_ports else "no_results",
            "operation": operation,
            "state": "NOT_ESTABLISHED",
            "port": port,
            "connections": rows[: max(cap, 20)],
            "connection_count": len(rows),
            "destination_ports": ranked_ports,
            "top_destination_port": ranked_ports[0] if ranked_ports else None,
            "recipe": raw.get("command"),
            "exit_code": 0,
        }
    rows, raw = _connections(port=port, state=wanted_state if wanted_state != "ANY" else None)
    if protocol:
        rows = [item for item in rows if (item.get("protocol") or "").lower() == protocol.lower()]
    if wanted_state != "ANY":
        rows = [item for item in rows if (item.get("state") or "").upper() == wanted_state]
    ranked_ports = summarize_destination_ports(rows, state=None if wanted_state == "ANY" else wanted_state, limit=cap)
    return {
        "status": "success" if rows or ranked_ports else "no_results",
        "operation": operation,
        "state": wanted_state,
        "port": port,
        "connections": rows[: max(cap, 20)],
        "connection_count": len(rows),
        "destination_ports": ranked_ports,
        "top_destination_port": ranked_ports[0] if ranked_ports else None,
        "recipe": raw.get("command"),
        "exit_code": 0,
    }
