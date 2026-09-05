"""Inspect local network interfaces, sockets, and destination-port rankings."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
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


REVERSE_LOOKUP_CAP = 80
REVERSE_LOOKUP_TIMEOUT = 1.5


CERTIFICATE_PROBE_CAP = 12
CERTIFICATE_PROBE_TIMEOUT = 4.0
RESOLVE_ROUNDS = 3


def _host_addresses(host: str) -> list[str]:
    """Collect the host's addresses.

    A CDN or WAF answers with a rotating slice of its edge, so one lookup is a
    sample rather than the set. Asking a few times widens it cheaply.
    """

    found: list[str] = []
    for _ in range(RESOLVE_ROUNDS):
        try:
            info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError):
            break
        for entry in info:
            address = entry[4][0]
            if address and address not in found:
                found.append(address)
    return found


def _certificate_names(address: str, sni: str, port: int = 443) -> list[str]:
    """Names the endpoint at `address` serves, read from its TLS certificate.

    Behind a CDN or WAF the address belongs to the provider, so neither the
    address nor its PTR record names the site. The certificate does. Only
    addresses this machine is already connected to are dialled.
    """

    context = ssl.create_default_context()
    context.check_hostname = False  # dialling by address on purpose; the SAN list is the answer
    try:
        with socket.create_connection((address, port), timeout=CERTIFICATE_PROBE_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=sni) as secure:
                certificate = secure.getpeercert() or {}
    except (OSError, ssl.SSLError, ValueError):
        return []
    return [value for key, value in certificate.get("subjectAltName", ()) if key == "DNS"]


def _certificate_map(addresses: list[str], sni: str) -> dict[str, list[str]]:
    targets = addresses[:CERTIFICATE_PROBE_CAP]
    if not targets:
        return {}
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        names = pool.map(lambda address: (address, _certificate_names(address, sni)), targets)
    return {address: found for address, found in names if found}


def _is_private(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


def _covers(names: list[str], wanted: str) -> bool:
    for name in names:
        candidate = name.casefold().strip(".")
        if candidate == wanted:
            return True
        if candidate.startswith("*.") and wanted.endswith(candidate[1:]):
            return True
        if wanted.endswith("." + candidate):
            return True
    return False


def _reverse_names(addresses: list[str]) -> dict[str, str]:
    """Reverse-resolve remote addresses; a CDN edge usually still carries the name."""

    def lookup(address: str) -> tuple[str, str]:
        try:
            return address, socket.gethostbyaddr(address)[0]
        except (OSError, UnicodeError):
            return address, ""

    targets = addresses[:REVERSE_LOOKUP_CAP]
    if not targets:
        return {}
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(REVERSE_LOOKUP_TIMEOUT)
    try:
        with ThreadPoolExecutor(max_workers=min(16, len(targets))) as pool:
            return {address: name for address, name in pool.map(lookup, targets) if name}
    finally:
        socket.setdefaulttimeout(previous)


def _host_matches(rows: list[dict[str, Any]], host: str) -> dict[str, Any]:
    """Decide, for one named host, exactly which connections belong to it."""

    wanted = host.strip().strip(".").casefold()
    addresses = _host_addresses(wanted)
    address_set = set(addresses)
    remote_addresses = []
    for row in rows:
        remote = row.get("remote_host")
        if remote and remote not in remote_addresses:
            remote_addresses.append(str(remote))
    names = _reverse_names(remote_addresses)

    def belongs(row: dict[str, Any]) -> str:
        remote = str(row.get("remote_host") or "")
        if remote and remote in address_set:
            return "address"
        resolved = names.get(remote, "").casefold().strip(".")
        if resolved and (resolved == wanted or resolved.endswith("." + wanted)):
            return "reverse-dns"
        text = f"{remote} {row.get('name') or ''}".casefold()
        if wanted and wanted in text:
            return "name"
        return ""

    matches: list[dict[str, Any]] = []
    unattributed: list[str] = []
    for row in rows:
        reason = belongs(row)
        if reason:
            item = dict(row)
            item["matched_by"] = reason
            item["remote_name"] = names.get(str(row.get("remote_host") or ""), "")
            matches.append(item)
        elif str(row.get("remote_port") or "") == "443":
            remote = str(row.get("remote_host") or "")
            if remote and remote not in unattributed and not _is_private(remote):
                unattributed.append(remote)

    # Behind a CDN or WAF the address and its PTR record name the provider, not the
    # site, so neither can answer the question. Ask the endpoints already connected
    # on 443 which names they serve.
    certificates = _certificate_map(unattributed, wanted) if wanted and unattributed else {}
    for row in rows:
        remote = str(row.get("remote_host") or "")
        served = certificates.get(remote) or []
        if served and _covers(served, wanted):
            item = dict(row)
            item["matched_by"] = "tls-certificate"
            item["remote_name"] = names.get(remote, "")
            item["certificate_names"] = served[:12]
            matches.append(item)
    return {"host": host, "host_addresses": addresses, "host_matches": matches,
            "match_count": len(matches), "host_connected": bool(matches),
            "resolved": bool(addresses),
            "certificate_checked": len(certificates),
            "unattributed_tls": len(unattributed)}


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
    if host:
        verdict = _host_matches(rows, host)
        return {
            "status": "success",
            "operation": operation,
            "state": wanted_state,
            "port": port,
            "connections": verdict["host_matches"][: max(cap, 20)],
            "connection_count": verdict["match_count"],
            "recipe": raw.get("command"),
            "exit_code": 0,
            **verdict,
        }
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
