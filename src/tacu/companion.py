"""Deterministic facts and exact answers for common verbose terminal output."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from .host_parsers import (
    looks_like_network_table, looks_like_ps, parse_network_table, parse_ps,
    sort_processes, summarize_destination_ports,
)


def _block_text(block: dict[str, Any]) -> str:
    kind = block.get("type")
    if kind == "text": return str(block.get("text", ""))
    if kind == "json": return json.dumps(block.get("data"), ensure_ascii=False)
    if kind == "jsonl": return "\n".join(json.dumps(row, ensure_ascii=False) for row in block.get("rows", []))
    return json.dumps(block, ensure_ascii=False)


def _ipv4_network(address: str, mask: str) -> str | None:
    """Normalize hexadecimal, dotted, or prefix-length masks to CIDR."""

    try:
        normalized = str(ipaddress.IPv4Address(int(mask, 16))) if mask.casefold().startswith("0x") else mask
        return str(ipaddress.IPv4Network(f"{address}/{normalized}", strict=False))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return None


def _interfaces(text: str) -> list[dict[str, Any]]:
    """Parse macOS/Linux ifconfig and Windows ipconfig into compact interface facts."""

    interfaces: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    # macOS/BSD/Linux ifconfig.
    for line in text.splitlines():
        header = re.match(r"^([A-Za-z0-9_.:-]+):\s+(?:flags=|error fetching|<)", line)
        linux_header = re.match(r"^\d+:\s+([^:@]+)(?:@[^:]+)?:\s+<([^>]*)>", line)
        if linux_header:
            if current: interfaces.append(current)
            state = re.search(r"\bstate\s+(\w+)", line)
            current = {"name": linux_header.group(1), "ipv4": [], "ipv4_networks": [], "ipv6": [],
                       "status": "active" if state and state.group(1).upper() == "UP" else "unknown",
                       "flags": linux_header.group(2).split(",")}
            continue
        if header:
            if current: interfaces.append(current)
            current = {"name": header.group(1), "ipv4": [], "ipv4_networks": [], "ipv6": [], "status": "unknown",
                       "flags": re.search(r"<([^>]*)>", line).group(1).split(",") if re.search(r"<([^>]*)>", line) else []}
            continue
        if current is None: continue
        value = line.strip()
        ip4 = re.match(r"inet (\d+(?:\.\d+){3})(?:/(\d{1,2}))?\b", value)
        ip6 = re.match(r"inet6 ([0-9a-fA-F:]+)(?:%[^ ]+)?\b", value)
        if ip4:
            try:
                address = ipaddress.IPv4Address(ip4.group(1))
                if not address.is_loopback:
                    current["ipv4"].append(str(address))
                    mask_match = re.search(r"\bnetmask\s+(\S+)", value)
                    mask = ip4.group(2) or (mask_match.group(1) if mask_match else "")
                    network = _ipv4_network(str(address), mask) if mask else None
                    if network and network not in current["ipv4_networks"]:
                        current["ipv4_networks"].append(network)
            except ipaddress.AddressValueError: pass
        elif ip6 and ip6.group(1) != "::1": current["ipv6"].append(ip6.group(1))
        elif value.startswith("ether "): current["mac"] = value.split()[1]
        elif value.startswith("status: "): current["status"] = value.split(":", 1)[1].strip()
        elif value.startswith("media: "): current["media"] = value.split(":", 1)[1].strip()
    if current: interfaces.append(current)
    if interfaces: return interfaces

    # Windows ipconfig.
    current = None
    for line in text.splitlines():
        adapter = re.match(r"^([^:]+ adapter [^:]+):\s*$", line.strip(), re.I)
        if adapter:
            if current: interfaces.append(current)
            current = {"name": adapter.group(1), "ipv4": [], "ipv4_networks": [], "ipv6": [], "status": "unknown", "flags": []}
            continue
        if current is None: continue
        if "Media disconnected" in line: current["status"] = "inactive"
        match = re.search(r"IPv4 Address[^:]*:\s*(\d+(?:\.\d+){3})", line, re.I)
        if match:
            current["ipv4"].append(match.group(1)); current["status"] = "active"
        mask = re.search(r"Subnet Mask[^:]*:\s*(\d+(?:\.\d+){3})", line, re.I)
        if mask and current["ipv4"]:
            network = _ipv4_network(current["ipv4"][-1], mask.group(1))
            if network and network not in current["ipv4_networks"]:
                current["ipv4_networks"].append(network)
        match = re.search(r"Physical Address[^:]*:\s*([A-F0-9-]{17})", line, re.I)
        if match: current["mac"] = match.group(1)
    if current: interfaces.append(current)
    return interfaces


def _json_interfaces(value: Any) -> list[dict[str, Any]]:
    """Parse `ip -json address` without depending on platform-specific Python bindings."""

    if not isinstance(value, list) or not value or not isinstance(value[0], dict) or "ifname" not in value[0]:
        return []
    interfaces: list[dict[str, Any]] = []
    for item in value:
        addresses = item.get("addr_info") or []
        ipv4 = [address.get("local") for address in addresses
                if address.get("family") == "inet" and address.get("local") and not str(address["local"]).startswith("127.")]
        ipv6 = [address.get("local") for address in addresses if address.get("family") == "inet6" and address.get("local")]
        networks = [network for address in addresses
                    if address.get("family") == "inet" and address.get("local") and address.get("prefixlen") is not None
                    for network in [_ipv4_network(str(address["local"]), str(address["prefixlen"]))] if network]
        interfaces.append({"name": item.get("ifname", "unknown"), "ipv4": ipv4,
                           "ipv4_networks": networks, "ipv6": ipv6,
                           "status": "active" if item.get("operstate") == "UP" else "unknown",
                           "flags": item.get("flags") or [], "mac": item.get("address")})
    return interfaces


def _primary_interface(interfaces: list[dict[str, Any]]) -> dict[str, Any] | None:
    viable = [item for item in interfaces if item.get("ipv4")]
    if not viable: return None
    def score(item: dict[str, Any]) -> int:
        name = item["name"].lower(); points = 0
        if item.get("status") == "active": points += 100
        if {"UP", "RUNNING"}.issubset(set(item.get("flags", []))): points += 50
        if name in {"en0", "eth0", "wlan0", "wi-fi", "ethernet"}: points += 40
        if any(ipaddress.IPv4Address(value).is_private for value in item["ipv4"]): points += 20
        if name.startswith(("lo", "utun", "awdl", "llw", "bridge", "docker", "veth")): points -= 100
        return points
    return max(viable, key=score)


def _json_values(text: str) -> list[Any]:
    decoder = json.JSONDecoder(); values: list[Any] = []
    for match in re.finditer(r"(?m)^[ \t]*([\[{])", text):
        try:
            value, _ = decoder.raw_decode(text, match.start(1))
        except json.JSONDecodeError:
            continue
        values.append(value)
    return values


def _docker_summary(value: Any) -> dict[str, Any] | None:
    records = value if isinstance(value, list) else [value]
    if not records or not isinstance(records[0], dict): return None
    item = records[0]
    if not any(key in item for key in ("Config", "NetworkSettings", "HostConfig")): return None
    config = item.get("Config") or {}; state = item.get("State") or {}; host = item.get("HostConfig") or {}
    networks = (item.get("NetworkSettings") or {}).get("Networks") or {}
    ports: list[str] = []
    for container_port, bindings in ((item.get("NetworkSettings") or {}).get("Ports") or {}).items():
        for binding in bindings or []:
            ports.append(f"{binding.get('HostIp') or '0.0.0.0'}:{binding.get('HostPort')} → {container_port}")
    network_facts = [{"name": name, "ip": details.get("IPAddress"), "gateway": details.get("Gateway")}
                     for name, details in networks.items()]
    descriptor = item.get("ImageManifestDescriptor") or {}; platform = descriptor.get("platform") or {}
    labels = config.get("Labels") or {}
    return {
        "kind": "docker_container", "name": str(item.get("Name", "")).lstrip("/"), "id": item.get("Id"),
        "image": config.get("Image") or item.get("Image"), "image_digest": item.get("Image"),
        "image_title": labels.get("org.opencontainers.image.title"),
        "image_version": labels.get("org.opencontainers.image.version"),
        "status": state.get("Status"), "running": state.get("Running"), "platform": item.get("Platform"),
        "architecture": platform.get("architecture"), "ports": ports, "networks": network_facts,
        "restart_policy": (host.get("RestartPolicy") or {}).get("Name"), "privileged": host.get("Privileged"),
        "mounts": [{"type": mount.get("Type"), "source": mount.get("Source"),
                    "destination": mount.get("Destination"), "writable": mount.get("RW")}
                   for mount in item.get("Mounts") or []],
    }


def _dns_summary(text: str, command: str = "") -> dict[str, Any] | None:
    """Extract common nslookup, dig, and host answers without a model call."""

    lowered = (command + "\n" + text).casefold()
    named_tool = any(tool in lowered for tool in ("nslookup", " dig ", "\ndig ", "host "))
    output_signature = bool(re.search(
        r"(?mi)(^Server:\s*\S+|mail exchanger\s*=|\sIN\s+(?:MX|TXT|A|AAAA)\s+|"
        r"^\S+\s+text\s*=|^Name:\s*\S+)",
        text,
    ))
    if not named_tool and not output_signature:
        return None
    type_match = re.search(r"(?:-type=|-query=|\btype=)(A|AAAA|MX|TXT|CNAME|NS)\b", command, re.I)
    query_type = type_match.group(1).upper() if type_match else None
    resolver_match = re.search(r"(?mi)^Server:\s*(\S+)", text)
    resolver = resolver_match.group(1) if resolver_match else None
    answers: list[dict[str, Any]] = []

    mx_patterns = (
        r"(?mi)^(\S+)\s+mail exchanger\s*=\s*(\d+)\s+(\S+)\.?\s*$",
        r"(?mi)^(\S+)\.?\s+\d+\s+IN\s+MX\s+(\d+)\s+(\S+)\.?\s*$",
    )
    for pattern in mx_patterns:
        for domain, priority, host in re.findall(pattern, text):
            answer = {"type": "MX", "domain": domain.rstrip("."), "priority": int(priority),
                      "value": host.rstrip(".")}
            if answer not in answers:
                answers.append(answer)
    if answers:
        query_type = "MX"

    txt_patterns = (
        r'(?mi)^(\S+)\s+text\s*=\s*"([^"]*)"',
        r'(?mi)^(\S+)\.?\s+\d+\s+IN\s+TXT\s+"([^"]*)"',
    )
    for pattern in txt_patterns:
        for domain, value in re.findall(pattern, text):
            answer = {"type": "TXT", "domain": domain.rstrip("."), "value": value}
            if answer not in answers:
                answers.append(answer)
    if any(answer["type"] == "TXT" for answer in answers):
        query_type = query_type or "TXT"

    for name, address in re.findall(
        r"(?mi)^Name:\s*(\S+)\s*$\s*^Address(?:es)?:\s*([^\s#]+)", text
    ):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        answer_type = "AAAA" if parsed.version == 6 else "A"
        answers.append({"type": answer_type, "domain": name.rstrip("."), "value": str(parsed)})
        query_type = query_type or answer_type

    if not answers:
        return None
    return {
        "kind": "dns_lookup",
        "source": command or "captured DNS output",
        "query_type": query_type or "DNS",
        "resolver": resolver,
        "answers": answers,
        "method": "deterministic-dns-parser",
    }


def extract_facts(text: str, command: str = "", structured: Any = None) -> dict[str, Any] | None:
    dns = _dns_summary(text, command)
    if dns:
        return dns
    interfaces = _json_interfaces(structured) if structured is not None else []
    interfaces = interfaces or _interfaces(text)
    if interfaces:
        primary = _primary_interface(interfaces)
        return {"kind": "network_interfaces", "source": command or "captured output", "primary": primary,
                "interfaces": interfaces, "interface_count": len(interfaces),
                "method": "deterministic-ifconfig-parser"}
    candidates = ([structured] if structured is not None else []) + _json_values(text)
    for candidate in candidates:
        summary = _docker_summary(candidate)
        if summary:
            summary["method"] = "deterministic-docker-inspect-parser"
            return summary
    if looks_like_ps(text, command) or (isinstance(structured, dict) and structured.get("processes")):
        processes = (structured.get("processes") if isinstance(structured, dict) else None) or parse_ps(text)
        if processes:
            return {"kind": "processes", "source": command or "captured output",
                    "processes": processes[:20], "count": len(processes),
                    "top_cpu": (sort_processes(processes, key="cpu", limit=1) or [None])[0],
                    "top_memory": (sort_processes(processes, key="memory", limit=1) or [None])[0],
                    "method": "deterministic-ps-parser"}
    if looks_like_network_table(text, command) or (isinstance(structured, dict)
                                                   and (structured.get("connections") or structured.get("destination_ports"))):
        if isinstance(structured, dict) and (structured.get("connections") or structured.get("destination_ports")):
            connections = structured.get("connections") or []
            ports = structured.get("destination_ports") or summarize_destination_ports(connections)
        else:
            connections = parse_network_table(text, command)
            ports = summarize_destination_ports(connections)
        if connections or ports:
            return {"kind": "network_connections", "source": command or "captured output",
                    "connections": connections[:40], "connection_count": len(connections),
                    "destination_ports": ports, "top_destination_port": ports[0] if ports else None,
                    "method": "deterministic-network-parser"}
    return None


# Counting and naming what is already on the page is arithmetic, not reasoning.
# Asking a 12B model to retype 55 filenames took 342 seconds across three budgets
# and produced nothing; reading them takes no time and cannot be wrong.
_COUNT_ASK = re.compile(r"(?i)\bhow many\b|\bcount\b|\bnumber of\b")
_NAME_ASK = re.compile(
    r"(?i)\b(?:show|list|give|name|display|print|tell)\b[^?]{0,40}"
    r"\b(?:name|names|them|all|each|every|these|those|entries|files|lines|"
    r"folders?|directories|directory|dirs?|items)\b"
    r"|\btheir names\b|\bwhat are they\b")
# Any of these means the question is selective, and selecting needs the model.
_RESTRICTIVE = re.compile(
    r"(?i)\b(?:which|whose|only|except|excluding|containing|contains|matching|match|"
    r"with|without|where|that are|larger|bigger|smaller|older|newer|before|after|"
    r"greater|less|between|open|closed|failed|error|errors|database|from|starting|"
    r"ending|type|kind|sort|group|top|first|last|biggest|largest)\b")
# `ls -l` and friends: permissions, links, owner, group, size, date, then the name.
_LS_ROW = re.compile(r"^([-dlbcps])([rwxsStTX@+.-]{9})[@+.]*\s+\d+\s+\S+\s+\S+\s+\d+\s+"
                     r"(?:\S+\s+\S+\s+\S+)\s+(.+)$")


def _listing_entries(text: str) -> list[tuple[bool, str]] | None:
    """Names from an `ls -l` style listing, as (is_directory, name). None if not one."""

    rows: list[tuple[bool, str]] = []
    considered = 0
    for line in (text or "").splitlines():
        stripped = line.rstrip()
        if not stripped or stripped.startswith("total "):
            continue
        considered += 1
        match = _LS_ROW.match(stripped)
        if not match:
            continue
        name = match.group(3).strip()
        if name in {".", ".."}:
            continue
        # A symlink shows as "link -> target"; the name is the left side.
        name = name.split(" -> ", 1)[0]
        rows.append((match.group(1) == "d", name))
    if not rows or considered == 0 or len(rows) < considered * 0.6:
        return None
    return rows


# What the question is counting. Getting this wrong is worse than being slow:
# "how many folders not files" answered with the file list is a confident lie.
_ASKS_FILES = re.compile(r"(?i)\bfiles?\b")
_ASKS_DIRS = re.compile(
    r"(?i)\b(?:folders?|directories|directory|dirs?|subfolders?|subdirectories)\b")
_ASKS_ALL = re.compile(r"(?i)\b(?:entries|items|everything|rows|lines|contents)\b")
# "folders not files" excludes files; "files not folders" excludes folders.
_NOT_FILES = re.compile(r"(?i)\b(?:not|excluding|except|besides|rather than|instead of)\s+"
                        r"(?:the\s+)?files?\b")
_NOT_DIRS = re.compile(r"(?i)\b(?:not|excluding|except|besides|rather than|instead of)\s+"
                       r"(?:the\s+)?(?:folders?|directories|directory|dirs?)\b")


def _enumeration_target(question: str) -> str | None:
    """files, directories, entries — or None when the question does not say.

    Refusing is the safe answer. A question this cannot read confidently goes to
    the model, which is slower and right, rather than here, which is instant and
    guessing.
    """

    wants_files = bool(_ASKS_FILES.search(question))
    wants_dirs = bool(_ASKS_DIRS.search(question))
    wants_all = bool(_ASKS_ALL.search(question))

    if wants_files and wants_dirs:
        # Both named: the negated one is the one being excluded.
        if _NOT_FILES.search(question) and not _NOT_DIRS.search(question):
            return "directories"
        if _NOT_DIRS.search(question) and not _NOT_FILES.search(question):
            return "files"
        return None                      # "files and folders"? Ambiguous — ask the model.
    if wants_dirs:
        return "directories"
    if wants_files:
        return "files"
    if wants_all:
        return "entries"
    return None


def enumeration_answer(question: str, text: str) -> str | None:
    """Count and name what the piped text contains, without asking a model.

    Only for a question that wants everything of one clearly named kind. Anything
    selective — "which ports are open", "files larger than 1MB" — needs judgement
    and is left alone, and so is anything whose subject cannot be read plainly.
    """

    query = (question or "").strip()
    if not query or not text:
        return None
    wants_count = bool(_COUNT_ASK.search(query))
    wants_names = bool(_NAME_ASK.search(query))
    if not (wants_count or wants_names) or _RESTRICTIVE.search(query):
        return None
    target = _enumeration_target(query)
    if target is None:
        return None

    entries = _listing_entries(text)
    if entries is None:
        return None
    directories = [name for is_dir, name in entries if is_dir]
    files = [name for is_dir, name in entries if not is_dir]
    chosen = {"files": files, "directories": directories,
              "entries": [name for _is_dir, name in entries]}[target]
    other = {"files": (len(directories), "directories"),
             "directories": (len(files), "files"),
             "entries": (0, "")}[target]

    headline = f"There are {len(chosen)} {target} in the command output"
    if other[0]:
        headline += f" ({other[0]} {other[1]} are listed separately)"
    lines = [headline + "."]
    if wants_names:
        lines.append("")
        lines.extend(f"{index}. {name}" for index, name in enumerate(sorted(chosen), 1))
    return "\n".join(lines)


def exact_answer(question: str, evidence: dict[str, Any] | None) -> str | None:
    """Return a concise answer only when intent and deterministic facts both match."""

    if not evidence: return None
    counted = enumeration_answer(question, _block_text(evidence.get("result", {}).get("stdout", {})))
    if counted:
        return counted
    facts = evidence.get("facts")
    if not facts:
        block = evidence.get("result", {}).get("stdout", {})
        structured = block.get("data") if block.get("type") == "json" else None
        facts = extract_facts(_block_text(block), evidence.get("invocation", {}).get("command", ""), structured)
    if not facts: return None
    query = question.casefold()
    generic = ("exact" in query and "information" in query) or "concise facts" in query
    if facts["kind"] == "network_interfaces" and (generic or any(word in query for word in ("ip", "address", "interface", "network", "subnet"))):
        primary = facts.get("primary")
        if not primary or not primary.get("ipv4"): return None
        ip = primary["ipv4"][0]
        networks = primary.get("ipv4_networks") or []
        if ("subnet" in query or "network" in query) and networks:
            if "just" in query or "only" in query:
                return networks[0]
            return f"Primary interface: {primary['name']}\nIPv4 address: {ip}\nSubnet: {networks[0]}"
        if "just" in query or "only" in query:
            return ip
        return f"Primary interface: {primary['name']}\nIPv4 address: {ip}"
    if facts["kind"] == "dns_lookup":
        answers = facts.get("answers") or []
        if not answers:
            return None
        lines = [f"DNS record type: {facts.get('query_type') or 'unknown'}"]
        if facts.get("resolver"):
            lines.append(f"Resolver: {facts['resolver']}")
        mx = [answer for answer in answers if answer.get("type") == "MX"]
        txt = [answer for answer in answers if answer.get("type") == "TXT"]
        addresses = [answer for answer in answers if answer.get("type") in {"A", "AAAA"}]
        if mx:
            lines.append("Mail exchangers:")
            lines.extend(f"- {answer['value']} (priority {answer['priority']})" for answer in mx)
            lines.append("Lower priority numbers are preferred first.")
        if txt:
            lines.append("TXT records:")
            lines.extend(f"- {answer['value']}" for answer in txt)
        if addresses:
            lines.append("Addresses:")
            lines.extend(f"- {answer['domain']}: {answer['value']}" for answer in addresses)
        return "\n".join(lines)
    if facts["kind"] == "docker_container":
        broad_details = any(phrase in query for phrase in
                            ("basic details", "container details", "all details", "full details", "summary", "overview"))
        if "image" in query and not broad_details:
            return f"Docker image: {facts.get('image') or 'unknown'}"
        if generic or any(word in query for word in ("image", "docker", "container", "port", "status", "basic", "detail", "summary")):
            lines = [f"Container: {facts.get('name') or 'unknown'}", f"Image: {facts.get('image') or 'unknown'}",
                     f"Status: {facts.get('status') or 'unknown'}"]
            if facts.get("image_title"): lines.append(f"Image title: {facts['image_title']}")
            if facts.get("image_version"): lines.append(f"Image version: {facts['image_version']}")
            platform = "/".join(value for value in (facts.get("platform"), facts.get("architecture")) if value)
            if platform: lines.append(f"Platform: {platform}")
            if facts.get("ports"): lines.append("Ports: " + ", ".join(facts["ports"]))
            return "\n".join(lines)
    if facts["kind"] == "processes" and (generic or any(word in query for word in ("cpu", "ram", "memory", "process", "pid"))):
        return _process_answer(query, facts)
    if facts["kind"] == "network_connections" and (generic or any(word in query for word in (
            "port", "tcp", "udp", "connection", "destination", "outbound", "listen", "network"))):
        return _connection_answer(query, facts)
    from .ingest_filter import exact_filter_answer
    return exact_filter_answer(question, evidence)


# What an application question is actually after. A plan answers all of these with
# the same tool, so the shape of the reply has to come from the wording.
_APP_DATE_ASK = re.compile(
    r"(?i)\b(?:install(?:ation)? date|date of install\w*|creation date|"
    r"when (?:was|did|were)\b[^?]{0,40}\binstall)")
_APP_PRESENT_ASK = re.compile(
    r"(?i)\b(?:is|are|was|were)\b[^?]{0,40}\binstalled\b|\bdo i have\b|"
    r"\bhave i (?:got|installed)\b|\bis there\b|\bdo we have\b")
_APP_VERSION_ASK = re.compile(r"(?i)\b(?:version|build number|which release)\b")
_APP_PATH_ASK = re.compile(
    r"(?i)\b(?:full path|file path|where is|where's|located|location|installed (?:at|in))\b")


def _merge_app_results(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """One question about one application deserves one answer.

    A plan usually asks the same application several ways — find it, read its
    version, read its dates — and each call returns its own record. Merging them
    by path keeps the reply a single statement instead of three overlapping ones
    that appear to contradict each other.
    """

    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    suggestions: list[str] = []
    running: list[Any] = []
    for entry in entries:
        for item in entry.get("applications") or []:
            path = str(item.get("path") or item.get("name") or "")
            if path not in merged:
                merged[path] = {}
                order.append(path)
            for key, value in item.items():
                if value not in (None, "") and not merged[path].get(key):
                    merged[path][key] = value
        for name in entry.get("did_you_mean") or []:
            if str(name) not in suggestions:
                suggestions.append(str(name))
        for item in entry.get("running") or []:
            if item not in running:
                running.append(item)
    return {"applications": [merged[path] for path in order],
            "did_you_mean": suggestions, "running": running}


def _application_answer(question: str, query_name: str, merged: dict[str, Any]) -> list[str]:
    """Answer the question that was asked, not every fact the tool returned."""

    apps = merged.get("applications") or []
    if not apps:
        return [_no_app_line(query_name, merged)]
    top = apps[0]
    label = top.get("display_name") or top.get("name") or query_name
    wants_date = bool(_APP_DATE_ASK.search(question))
    wants_version = bool(_APP_VERSION_ASK.search(question))
    wants_path = bool(_APP_PATH_ASK.search(question))
    yes_no = bool(_APP_PRESENT_ASK.search(question)) and not wants_date

    created = top.get("fs_creation_date") or top.get("content_created") or top.get("created")
    added = top.get("date_added")
    lines: list[str] = []
    skip: set[str] = set()
    if wants_date and (created or added):
        lines.append(f"{label} was installed on this machine on {created or added}.")
        skip.add("created" if created else "added")
    elif wants_version and top.get("version"):
        build = top.get("build")
        suffix = f" (build {build})" if build and build != top["version"] else ""
        lines.append(f"{label} version {top['version']}{suffix}.")
        skip.add("version")
    elif wants_path and top.get("path"):
        lines.append(f"{label} is installed at `{top['path']}`.")
        skip.add("path")
    elif yes_no:
        lines.append(f"Yes — {label} is installed.")
    else:
        lines.append(f"{label} is installed.")

    if "path" not in skip and top.get("path"):
        lines.append(f"Path: `{top['path']}`")
    if "version" not in skip and top.get("version"):
        lines.append(f"Version: {top['version']}")
    if top.get("bundle_id"):
        lines.append(f"Bundle id: `{top['bundle_id']}`")
    if created and "created" not in skip:
        lines.append(f"Installed on this machine: {created}")
    if added and added != created and "added" not in skip:
        lines.append(f"Added (Spotlight record): {added}")
    if wants_date and not created and not added:
        lines.append("No installation date is recorded for this bundle.")
    if merged.get("running"):
        lines.append(f"Running: {_process_label(merged['running'][0])}")

    others = apps[1:]
    if others:
        lines.append(f"{len(others)} other match(es) for `{query_name}`:")
        lines.extend(f"- {item.get('display_name') or item.get('name')} ({item.get('path')})"
                     for item in others[:11])
    return lines


def _readable_duration(seconds: float) -> str:
    """Uptime the way a person says it: days and hours, not a float of seconds."""

    total = int(max(0, seconds))
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    parts: list[str] = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes and not days:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    return ", ".join(parts) or "less than a minute"


def _storage_headline(volumes: list[str]) -> str:
    """The number a disk question asks for, taken from the df row for `/`.

    A pasted df table is evidence, not an answer: the user asked how much space
    is free, so say that first and leave the table underneath.
    """

    for row in volumes:
        parts = row.split()
        if len(parts) >= 9 and parts[-1] == "/" and not parts[0].startswith("map"):
            size, used, available, capacity = parts[1], parts[2], parts[3], parts[4]
            return (f"{available} free of {size} on the startup disk "
                    f"({used} used, {capacity} full).")
    return ""


# Ollama settings people ask about by name, mapped to the variable that holds
# them, so "what is my keepalive" is answered with the keepalive.
_OLLAMA_SETTING_WORDS = (
    ("keep", "OLLAMA_KEEP_ALIVE"), ("alive", "OLLAMA_KEEP_ALIVE"),
    ("context", "OLLAMA_CONTEXT_LENGTH"), ("num_ctx", "OLLAMA_CONTEXT_LENGTH"),
    ("window", "OLLAMA_CONTEXT_LENGTH"), ("host", "OLLAMA_HOST"),
    ("port", "OLLAMA_HOST"), ("kv", "OLLAMA_KV_CACHE_TYPE"),
    ("cache", "OLLAMA_KV_CACHE_TYPE"), ("flash", "OLLAMA_FLASH_ATTENTION"),
    ("parallel", "OLLAMA_NUM_PARALLEL"), ("queue", "OLLAMA_MAX_QUEUE"),
    ("loaded", "OLLAMA_MAX_LOADED_MODELS"), ("debug", "OLLAMA_DEBUG"),
    ("where", "OLLAMA_MODELS"), ("stored", "OLLAMA_MODELS"),
)


def _ollama_settings_answer(query: str, data: dict[str, Any]) -> list[str]:
    """Answer with the setting that was asked about, then what actually applies.

    A setting can be stated in the environment and overridden by what TACU sends
    with each request. Reporting only the environment variable is how someone
    ends up trusting a value that never reaches the server.
    """

    environment = {item["variable"]: item for item in data.get("environment") or []}
    wanted = [name for word, name in _OLLAMA_SETTING_WORDS if word in query]
    lines: list[str] = []
    sent = data.get("tacu_request_options") or {}

    if wanted:
        for name in dict.fromkeys(wanted):
            item = environment.get(name)
            if not item:
                continue
            lines.append(f"{name}: {item['in_effect']} — {item['purpose']}.")
    else:
        lines.append(f"Active model: {data.get('active_model')}.")
        for item in data.get("environment") or []:
            if item.get("set"):
                lines.append(f"{item['variable']}: {item['value']} — {item['purpose']}.")
        unset = [item["variable"] for item in data.get("environment") or [] if not item.get("set")]
        if unset:
            lines.append("Not set (Ollama defaults apply): " + ", ".join(unset) + ".")
        lines.append("TACU sends with every request: "
                     + ", ".join(f"{key}={value}" for key, value in sent.items()) + ".")

    for clash in data.get("conflicts") or []:
        # The whole point of showing settings is catching this.
        lines.append(
            f"⚠ {clash['setting']}: your environment says {clash['environment']}, but TACU sends "
            f"{clash['tacu_sends']} with every request, so {clash['wins']} is what applies — "
            f"{clash['why']}.")
    if wanted and sent:
        lines.append("TACU's own request options: "
                     + ", ".join(f"{key}={value}" for key, value in sent.items()) + ".")
    return lines


def _no_app_line(query_name: str, data: dict) -> str:
    """Say nothing was found, and offer the closest installed names when we have them."""

    line = f"No installed application matching `{query_name}` was found."
    suggestions = data.get("did_you_mean") or []
    if suggestions:
        line += " Did you mean: " + ", ".join(str(item) for item in suggestions) + "?"
    return line


def _process_label(item: dict[str, Any] | None) -> str:
    if not item:
        return "unknown"
    command = str(item.get("command") or item.get("executable") or "unknown").strip()
    token = command.split()[0] if command else "unknown"
    name = Path(token).name or token
    return f"{name} (PID {item.get('pid')})"


def _graph_answer(facts: dict[str, Any]) -> str | None:
    """Name the process behind a port, a runtime or a role — and how to act on it."""

    if facts.get("operation") != "graph":
        return None
    nodes = facts.get("processes") or []
    focus = facts.get("focus") or "that"
    if not nodes:
        if str(focus).startswith("port "):
            return f"Nothing is listening on {focus}."
        return (f"No running process matches {focus}. "
                f"{facts.get('total_processes') or 0} processes were examined.")
    lines: list[str] = []
    total = int(facts.get("count") or len(nodes))
    # A wider view than the question asked for must announce itself. Reporting
    # eleven processes as matching "python servers" when only "servers" matched
    # is the same overclaim as reporting none at all, in the other direction.
    widened = str(facts.get("widened") or "")
    if widened:
        lines.append(f"{widened.capitalize()}.")
    elif total > 1:
        lines.append(f"{total} processes match {focus}, best first:")
    shown = min(len(nodes), 6)
    if total > shown:
        # Say what is not on screen rather than letting a count imply a listing.
        lines.append(f"Showing {shown} of {total}; ask for a specific one by name or port.")
    for node in nodes[:6]:
        ports = ", ".join(f"{entry['port']}" for entry in node.get("listening") or [])
        where = f" on port {ports}" if ports else ""
        lines.append(f"{node.get('label')} · PID {node.get('pid')} · {node.get('role')}{where}")
        command = str(node.get("command") or "")
        if command and command != node.get("label"):
            lines.append(f"    {command[:160]}")
        chain = node.get("ancestry") or []
        if chain:
            trail = " ← ".join(f"{item.get('label')} ({item.get('pid')})" for item in chain[:3])
            lines.append(f"    started by {trail}")
        kids = node.get("child_processes") or []
        if kids:
            lines.append(f"    {len(node.get('children') or [])} child process"
                         + ("es" if len(node.get("children") or []) != 1 else "")
                         + ": " + ", ".join(f"{item.get('label')} ({item.get('pid')})" for item in kids[:4]))
        if node.get("connections"):
            lines.append(f"    {node['connections']} established outbound connection"
                         + ("s" if node["connections"] != 1 else ""))
    leader = nodes[0]
    if leader.get("listening"):
        lines.append(f"To stop it: ti do kill process {leader.get('pid')}")
    return "\n".join(lines)


def _inspect_answer(facts: dict[str, Any]) -> str | None:
    """One named process: what it is, who owns it, and what it is running."""

    if facts.get("operation") != "inspect":
        return None
    processes = facts.get("processes") or []
    if not processes:
        return "No process is running with that PID."
    item = processes[0]
    lines = [f"{item.get('command') or 'unknown'} · PID {item.get('pid')}"]
    owner = item.get("user")
    parent = item.get("ppid")
    if owner or parent is not None:
        detail = f"Owned by {owner}" if owner else "Owner unknown"
        lines.append(f"{detail}{f', started by PID {parent}' if parent is not None else ''}.")
    cpu = item.get("cpu_percent")
    memory = item.get("memory_percent")
    rss = item.get("rss_bytes")
    usage = []
    if isinstance(cpu, (int, float)):
        usage.append(f"{cpu:.1f}% CPU")
    if isinstance(memory, (int, float)):
        readable = f" ({rss / 1024 ** 3:.1f} GB)" if isinstance(rss, int) and rss >= 1024 ** 3 else (
            f" ({rss / 1024 ** 2:.0f} MB)" if isinstance(rss, int) and rss else "")
        usage.append(f"{memory:.1f}% memory{readable}")
    if usage:
        lines.append("Using " + " and ".join(usage) + ".")
    executable = item.get("executable")
    if executable and executable != item.get("command"):
        lines.append(f"Executable: {executable}")
    return "\n".join(lines)


def _process_answer(query: str, facts: dict[str, Any]) -> str | None:
    graphed = _graph_answer(facts)
    if graphed:
        return graphed
    inspected = _inspect_answer(facts)
    if inspected:
        return inspected
    processes = facts.get("processes") or []
    if not processes:
        return "No processes were returned by the native process recipe."
    want_mem = any(word in query for word in ("ram", "memory", "rss"))
    want_cpu = "cpu" in query or not want_mem
    explicit = re.search(r"\b(?:top|first|highest)\s+(\d{1,3})\b", query)
    limit = int(explicit.group(1)) if explicit else 1
    limit = max(1, min(limit, 20))
    lines: list[str] = []

    def format_cpu(item: dict[str, Any]) -> str:
        cpu = item.get("cpu_percent")
        cpu_text = f"{cpu:.1f}%" if isinstance(cpu, (int, float)) else "unknown CPU"
        return f"{_process_label(item)} at {cpu_text}"

    def format_mem(item: dict[str, Any]) -> str:
        mem = item.get("memory_percent")
        rss = item.get("rss_bytes")
        extra = []
        if isinstance(mem, (int, float)):
            extra.append(f"{mem:.1f}% memory")
        if isinstance(rss, int):
            extra.append(f"{rss / (1024 ** 2):.0f} MB RSS")
        detail = " at " + ", ".join(extra) if extra else ""
        return f"{_process_label(item)}{detail}"

    if want_cpu:
        ranked = sort_processes(processes, key="cpu", limit=limit)
        if limit == 1 and ranked:
            lines.append(f"Highest CPU: {format_cpu(ranked[0])}.")
        elif ranked:
            lines.append(f"Top {len(ranked)} processes by CPU:")
            lines.extend(f"{index}. {format_cpu(item)}" for index, item in enumerate(ranked, 1))
    if want_mem:
        ranked = sort_processes(processes, key="memory", limit=limit)
        if limit == 1 and ranked:
            lines.append(f"Highest RAM: {format_mem(ranked[0])}.")
        elif ranked:
            lines.append(f"Top {len(ranked)} processes by RAM:")
            lines.extend(f"{index}. {format_mem(item)}" for index, item in enumerate(ranked, 1))
    return "\n".join(lines) if lines else None


# How a connection was tied to the asked name, strongest evidence first.
_MATCH_EVIDENCE = {
    "address": "address matches DNS",
    "reverse-dns": "reverse DNS",
    "tls-certificate": "TLS certificate names it",
    "name": "name seen in the socket",
}


def _host_connection_answer(facts: dict[str, Any]) -> str | None:
    """Answer "am I connected to X" with a verdict and the owning process."""

    host = facts.get("host")
    if not host or facts.get("host_connected") is None:
        return None
    matches = facts.get("host_matches") or []
    if not matches:
        lines = [f"No TCP connection to {host}."]
        if not facts.get("resolved"):
            lines.append(f"{host} did not resolve, so only its literal name could be compared.")
        probed = facts.get("certificate_checked") or 0
        outstanding = facts.get("unattributed_tls") or 0
        if outstanding:
            lines.append(f"Read certificates from {probed} of {outstanding} other TLS "
                         "endpoints; none serve that name.")
        return "\n".join(lines)
    owners: list[str] = []
    for item in matches:
        label = f"{item.get('command') or 'unknown'} (pid {item.get('pid')})"
        if label not in owners:
            owners.append(label)
    plural = "s" if len(matches) != 1 else ""
    lines = [f"Yes. {len(matches)} TCP connection{plural} to {host}, "
             f"owned by {', '.join(owners[:6])}."]
    for item in matches[:8]:
        evidence = _MATCH_EVIDENCE.get(item.get("matched_by") or "", item.get("matched_by") or "")
        name = item.get("remote_name")
        suffix = f" · {name}" if name and name != item.get("remote_host") else ""
        lines.append(f"- {item.get('command')} (pid {item.get('pid')}) → "
                     f"{item.get('remote_host')}:{item.get('remote_port')} "
                     f"{item.get('state') or ''}".rstrip() + suffix + f" [{evidence}]")
        served = item.get("certificate_names") or []
        if served:
            lines.append(f"    certificate serves: {', '.join(served[:5])}")
    if len(matches) > 8:
        lines.append(f"... and {len(matches) - 8} more.")
    return "\n".join(lines)


def _connection_answer(query: str, facts: dict[str, Any]) -> str | None:
    host_verdict = _host_connection_answer(facts)
    if host_verdict:
        return host_verdict
    ports = facts.get("destination_ports") or []
    connections = facts.get("connections") or []
    state = (facts.get("state") or "").upper()
    if state == "NOT_ESTABLISHED" or re.search(
            r"\b(?:not|other than|except)\b.{0,24}\bestablished\b|\bother(?:\s+\w+){0,3}\s+than\b.{0,20}\bestablished\b",
            query):
        if not connections:
            return "No TCP connections in a state other than ESTABLISHED were found."
        lines = [f"{len(connections)} TCP connection"
                 + ("s" if len(connections) != 1 else "")
                 + " in a state other than ESTABLISHED."]
        for item in connections[:12]:
            remote = item.get("remote_host")
            port = item.get("remote_port") or item.get("local_port")
            label = f"{remote}:{port}" if remote else str(port or "")
            lines.append(f"- {item.get('state') or 'UNKNOWN'} {label} ({item.get('command') or 'unknown'})")
        return "\n".join(lines)
    if "listen" in query:
        listening = [item for item in connections if (item.get("state") or "").upper() == "LISTEN"]
        if not listening:
            return "No listening TCP sockets were found."
        lines = [f"Found {len(listening)} listening TCP sockets."]
        for item in listening[:8]:
            owner = item.get("command") or "unknown"
            lines.append(f"- {owner} (PID {item.get('pid')}) on {item.get('local_host')}:{item.get('local_port')}")
        return "\n".join(lines)
    if ports and any(word in query for word in ("destination", "outbound", "port", "tcp", "top", "connection")):
        port_match = re.search(r"\b(\d{2,5})\b", query)
        wanted = int(port_match.group(1)) if port_match else None
        adjective = "established " if state in {"", "ESTABLISHED"} else f"{state.lower()} "
        if wanted and 1 <= wanted <= 65535:
            matching = [item for item in connections
                        if item.get("remote_port") == wanted or item.get("local_port") == wanted]
            hosts: list[str] = []
            for item in matching:
                host = item.get("remote_host")
                if host and host not in hosts:
                    hosts.append(str(host))
            lines = [f"{len(matching)} {adjective}TCP {wanted} destination"
                     + ("s" if len(matching) != 1 else "") + "."]
            if hosts:
                lines.append("Remote hosts: " + ", ".join(hosts[:8]))
            elif not matching:
                lines = [f"No {adjective}TCP {wanted} connections were found."]
            return "\n".join(lines)
        top = facts.get("top_destination_port") or ports[0]
        lines = [f"Top outbound destination port: {top['port']} ({top['count']} {adjective}connections)."]
        if top.get("hosts"):
            lines.append("Sample remote hosts: " + ", ".join(str(host) for host in top["hosts"][:5]))
        if len(ports) > 1:
            lines.append("Other destination ports:")
            lines.extend(f"- {item['port']}: {item['count']} connections" for item in ports[1:6])
        return "\n".join(lines)
    if not connections:
        return "No TCP connections were found."
    return f"{facts.get('connection_count') or len(connections)} TCP connections observed."


_SEVERITY_LABEL = {"high": "HIGH", "investigate": "INVESTIGATE", "review": "REVIEW"}


def _recon_answer(data: dict[str, Any]) -> str | None:
    """Render a recon result: findings first, then the score's working, then what went out.

    Nothing here is summarised into a verdict. A provider match shows the
    indicators that produced it; a risk level shows every contribution; a source
    that was not consulted is named as such. The reader can disagree with any
    line and see exactly what it rested on.
    """

    operation = data.get("operation")
    target = data.get("target") or ""
    lines: list[str] = []

    def waf_lines(waf: dict[str, Any], indent: str = "") -> None:
        providers = waf.get("providers") or []
        if not providers:
            lines.append(f"{indent}WAF/CDN: no indicators seen")
            return
        top = providers[0]
        lines.append(f"{indent}WAF/CDN: {top['provider']} · {top['confidence']}% confidence "
                     f"from {len(top['indicators'])} indicator"
                     f"{'s' if len(top['indicators']) != 1 else ''}")
        for item in top["indicators"]:
            lines.append(f"{indent}    {item['kind']:7} +{item['weight']:<3} {item['evidence'][:90]}")
        for other in providers[1:3]:
            lines.append(f"{indent}    also {other['provider']} at {other['confidence']}%")

    def risk_lines(risk: dict[str, Any]) -> None:
        lines.append(f"RISK {risk['score']:+d} · {risk['level']}")
        for item in risk.get("contributions") or []:
            lines.append(f"    {item['weight']:+4d}  {item['why']}")
        if not risk.get("contributions"):
            lines.append("    nothing observed that adds to or lowers the score")
        for note in risk.get("not_checked") or []:
            lines.append(f"    not checked: {note}")

    def asn_line(asn: dict[str, Any]) -> str:
        if not asn.get("asn"):
            return f"ASN: {asn.get('note') or 'unknown'}"
        return (f"AS{asn['asn']} {asn.get('owner') or ''} · {asn.get('prefix')} · "
                f"{asn.get('registry', '').upper()} {asn.get('country')} · allocated {asn.get('allocated')}")

    if operation == "sweep":
        lines.append(f"RECON {target}")
        subs = data.get("subdomains") or {}
        if subs:
            names = subs.get("subdomains") or []
            head = f"{subs.get('count', len(names))} name(s) beneath {target}"
            if not subs.get("ct_available"):
                head += " — certificate transparency was unavailable, so this is DNS only"
            lines.append(head + ":")
            for item in names[:12]:
                lines.append(f"    {item['name']}  ({', '.join(item['sources'])})")
            if subs.get("truncated") or len(names) > 12:
                lines.append(f"    … {max(0, subs.get('count', 0) - 12)} more; ask for subdomains with a higher limit")
        # Names that resolve come first and in full; names that do not are a
        # fact worth one line between them — a certificate was once issued for
        # a host that no longer answers — not a block each.
        hosts = data.get("hosts") or []
        live = [h for h in hosts if (h.get("dns") or {}).get("addresses")]
        dead = [h["host"] for h in hosts if not (h.get("dns") or {}).get("addresses")]
        if dead:
            lines.append(f"    no address today: {', '.join(dead[:8])}"
                         + (f" … +{len(dead) - 8}" if len(dead) > 8 else "")
                         + "  (in certificate logs, not in DNS)")
        for host in live[:4]:
            lines.append("")
            lines.append(f"{host['host']}")
            dns = host.get("dns") or {}
            addresses = ", ".join(a["ip"] + ("" if a["public"] else " (private)")
                                  for a in dns.get("addresses") or [])
            lines.append(f"    resolves to {addresses}")
            if dns.get("cname_chain"):
                lines.append(f"    via CNAME {' → '.join(dns['cname_chain'])}")
            if host.get("skipped"):
                lines.append(f"    {host['skipped']}")
                continue
            if host.get("asn"):
                lines.append(f"    {asn_line(host['asn'])}")
            tls = host.get("tls") or {}
            if tls.get("issuer"):
                lines.append(f"    TLS {tls.get('tls_version')} · issued by {_short_dn(tls['issuer'])} · "
                             f"valid to {str(tls.get('not_after', ''))[:10]}")
            elif tls.get("note"):
                lines.append(f"    TLS: {tls['note']}")
            http = host.get("http") or {}
            if http.get("status"):
                server = next((h.split(':', 1)[1].strip() for h in http.get("headers", [])
                               if h.casefold().startswith("server:")), "")
                lines.append(f"    HTTP {http['status']}" + (f" · server: {server}" if server else ""))
            if host.get("waf"):
                waf_lines(host["waf"], indent="    ")
        geo = data.get("geo") or {}
        if geo.get("country"):
            lines.append("")
            lines.append(f"Location of {geo.get('ip')}: {', '.join(p for p in (geo.get('city'), geo.get('region'), geo.get('country')) if p)}"
                         + (f" · {geo['org']}" if geo.get("org") else ""))
        rep = data.get("reputation") or {}
        if rep.get("abuseipdb") or rep.get("virustotal"):
            lines.append("")
            ab = rep.get("abuseipdb")
            if ab:
                lines.append(f"AbuseIPDB: {ab['confidence']}% abuse confidence from {ab['reports']} report(s)"
                             + (f", last {ab['last_reported'][:10]}" if ab.get('last_reported') else "")
                             + (" · Tor exit" if ab.get('tor') else ""))
            vt = rep.get("virustotal")
            if vt:
                lines.append(f"VirusTotal: {vt['malicious']} malicious, {vt['suspicious']} suspicious, "
                             f"{vt['harmless']} harmless, {vt['undetected']} undetected")
        if data.get("risk"):
            lines.append("")
            risk_lines(data["risk"])
    elif operation == "subdomains":
        names = data.get("subdomains") or []
        head = f"{data.get('count', len(names))} name(s) beneath {target}"
        if not data.get("ct_available"):
            head += " — certificate transparency was unavailable, so this is DNS only"
        lines.append(head + ":")
        for item in names:
            lines.append(f"    {item['name']}  ({', '.join(item['sources'])})")
        if data.get("truncated"):
            lines.append("    … more exist; raise the limit to see them")
    elif operation == "dns":
        lines.append(f"DNS for {target}:")
        for a in data.get("addresses") or []:
            lines.append(f"    {a['ip']}" + ("" if a["public"] else "  (private address)"))
        if data.get("cname_chain"):
            lines.append(f"    CNAME {' → '.join(data['cname_chain'])}")
        for key in ("ns", "mx", "txt", "ptr"):
            for value in (data.get(key) or [])[:6]:
                lines.append(f"    {key.upper():4} {value[:120]}")
    elif operation == "tls":
        lines.append(f"TLS certificate for {target}:")
        lines.append(f"    subject   {_short_dn(data.get('subject', ''))}")
        lines.append(f"    issuer    {_short_dn(data.get('issuer', ''))}")
        lines.append(f"    valid     {str(data.get('not_before', ''))[:10]} → {str(data.get('not_after', ''))[:10]}")
        lines.append(f"    protocol  {data.get('tls_version')} · {data.get('cipher')}")
        san = data.get("san") or []
        if san:
            lines.append(f"    SAN       {', '.join(san[:8])}" + (f" … +{len(san) - 8}" if len(san) > 8 else ""))
        lines.append(f"    sha256    {data.get('sha256', '')}")
    elif operation == "http":
        lines.append(f"HTTP {data.get('status')} from {data.get('url')}:")
        for header in (data.get("headers") or [])[:20]:
            lines.append(f"    {header[:140]}")
        if data.get("cookies"):
            lines.append(f"    cookies: {', '.join(c.split('=', 1)[0] for c in data['cookies'][:8])}")
    elif operation == "waf":
        lines.append(f"{target}:")
        waf_lines(data, indent="    ")
    elif operation == "asn":
        lines.append(f"{data.get('ip')}" + (f" (from {data['resolved_from']})" if data.get("resolved_from") else "") + ":")
        lines.append(f"    {asn_line(data)}")
    elif operation == "geo":
        where = ", ".join(p for p in (data.get("city"), data.get("region"), data.get("country")) if p)
        lines.append(f"{data.get('ip')}" + (f" (from {data['resolved_from']})" if data.get("resolved_from") else "") + f": {where or 'no location returned'}")
        if data.get("org"):
            lines.append(f"    {data['org']}")
        if data.get("hostname"):
            lines.append(f"    reverse name {data['hostname']}")
    elif operation == "reputation":
        lines.append(f"Reputation of {data.get('ip')}" + (f" (from {data['resolved_from']})" if data.get("resolved_from") else "") + ":")
        ab = data.get("abuseipdb")
        if ab:
            lines.append(f"    AbuseIPDB: {ab['confidence']}% abuse confidence from {ab['reports']} report(s)"
                         + (f", last {ab['last_reported'][:10]}" if ab.get('last_reported') else "")
                         + (f" · {ab['usage_type']}" if ab.get('usage_type') else ""))
        vt = data.get("virustotal")
        if vt:
            lines.append(f"    VirusTotal: {vt['malicious']} malicious, {vt['suspicious']} suspicious, "
                         f"{vt['harmless']} harmless, {vt['undetected']} undetected")
        for note in data.get("not_checked") or []:
            lines.append(f"    not checked: {note}")
        if not ab and not vt:
            lines.append("    No reputation source answered. Add keys with: ti config keys")
    else:
        return None

    contacted = data.get("contacted") or []
    if contacted:
        lines.append("")
        lines.append("Contacted: " + ", ".join(contacted))
    for note in data.get("notes") or []:
        lines.append(f"Note: {note}")
    return "\n".join(lines)


def _email_answer(data: dict[str, Any]) -> str | None:
    """Render an email analysis: the score and its reasons first, then the evidence.

    Every section shows what it rests on. The authentication block says *for
    whom* each check passed, because "SPF pass" for the attacker's domain is
    the most common shape a spoof takes, and reading it as reassurance is the
    mistake this tool exists to prevent.
    """

    operation = data.get("operation")
    lines: list[str] = []
    rule = "─" * 34

    def auth_block(auth: dict[str, Any], sender: dict[str, Any]) -> None:
        lines.append("Authentication")
        lines.append(rule)
        for method in ("spf", "dkim", "dmarc", "arc"):
            verdict = str(auth.get(method, "none")).upper()
            for_whom = ""
            if method == "spf" and auth.get("spf_domain"):
                for_whom = f"   for {auth['spf_domain']}"
            elif method == "dkim" and auth.get("dkim_domains"):
                for_whom = f"   for {', '.join(auth['dkim_domains'])}"
            elif method == "dmarc" and auth.get("dmarc_domain"):
                for_whom = f"   for {auth['dmarc_domain']}"
            lines.append(f"{method.upper():8} {verdict:8}{for_whom}")
        notes = [n for n in auth.get("notes") or [] if "not for the displayed" in n]
        if notes:
            lines.append("")
            lines.append("Important:")
            for note in notes:
                lines.append(f"  {note}")
            lines.append(f"  The passes above are not for the identity the recipient sees ({sender.get('address')}).")

    def hops_table(hops: list[dict[str, Any]], enriched: list[dict[str, Any]]) -> None:
        by_ip = {row["ip"]: row for row in enriched or []}
        lines.append("Received chain (oldest first)")
        lines.append(rule)
        lines.append(f"{'Hop':4} {'Source IP':16} {'PTR / relay':34} {'ASN':9} {'Country':7}")
        for hop in hops:
            ip = hop.get("ip") or "--"
            row = by_ip.get(hop.get("ip") or "")
            ptr = ""
            if row and row.get("ptr"):
                ptr = row["ptr"][0]
            elif hop.get("relay"):
                ptr = hop["relay"]
            else:
                ptr = hop.get("from") or "--"
            asn = f"AS{row['asn']['asn']}" if row and (row.get("asn") or {}).get("asn") else "--"
            country = (row or {}).get("asn", {}).get("country") or "--"
            if hop.get("ip") and not hop.get("ip_public"):
                asn, country = "--", "private"
            lines.append(f"{hop.get('hop', '?'):<4} {ip:16} {ptr[:34]:34} {asn:9} {country:7}")
        for row in enriched or []:
            rep = row.get("reputation") or {}
            ab, vt = rep.get("abuseipdb"), rep.get("virustotal")
            if ab or vt:
                lines.append(f"     {row['ip']}: "
                             + (f"AbuseIPDB {ab['confidence']}% from {ab['reports']} report(s)" if ab else "")
                             + (f"; VirusTotal {vt['malicious']} malicious" if vt else ""))

    if operation == "analyze":
        risk = data.get("risk") or {}
        headers = data.get("headers") or {}
        sender = headers.get("from") or {}
        lines.append(f"EMAIL RISK SCORE: {risk.get('score', 0)} / 100")
        lines.append(f"SEVERITY: {risk.get('level', 'NONE OBSERVED')}")
        lines.append("")
        lines.append(f"From:      {sender.get('display', '')} <{sender.get('address', '')}>".rstrip())
        if (headers.get("reply_to") or {}).get("address"):
            lines.append(f"Reply-To:  {headers['reply_to']['address']}")
        lines.append(f"Subject:   {headers.get('subject', '')}")
        if headers.get("date_utc"):
            lines.append(f"Date:      {headers['date_utc']}")
        lines.append("")
        lines.append("Primary reasons")
        lines.append(rule)
        for reason in risk.get("reasons") or []:
            lines.append(f"{reason['weight']:+4d}  {reason['why']}")
        if not risk.get("reasons"):
            lines.append("  nothing observed that adds to the score")
        lines.append("")
        auth_block(data.get("auth") or {}, sender)
        lines.append("")
        hops_table(headers.get("hops") or [], (data.get("enrichment") or {}).get("hops") or [])
        anomalies = [a for a in headers.get("anomalies") or [] if not a.startswith(("Reply-To", "display name"))]
        if anomalies:
            lines.append("")
            lines.append("Header anomalies")
            lines.append(rule)
            for item in anomalies:
                lines.append(f"  {item}")
        dns = (data.get("enrichment") or {}).get("sender_dns") or {}
        age = (data.get("enrichment") or {}).get("domain_age") or {}
        if dns or age:
            lines.append("")
            lines.append(f"Sender domain {sender.get('domain', '')}")
            lines.append(rule)
            if age.get("registered") is False:
                lines.append("  registration: none — the registry reports no such domain")
            elif age.get("created"):
                lines.append(f"  registered:   {str(age['created'])[:10]} ({age.get('age_days')} days ago)")
            elif age.get("note"):
                lines.append(f"  registration: {age['note']}")
            if dns:
                lines.append(f"  MX:           {', '.join(dns.get('mx') or []) or 'none'}")
                lines.append(f"  SPF record:   {dns.get('spf_record') or 'none'}")
                lines.append(f"  DMARC:        {(dns.get('dmarc_record') or 'none')[:80]}"
                             + (f"  (p={dns['dmarc_policy']})" if dns.get("dmarc_policy") else ""))
                for selector, state in (dns.get("dkim_selectors") or {}).items():
                    lines.append(f"  DKIM key:     {selector} {state}")
        iocs = data.get("iocs") or {}
        if iocs.get("urls") or iocs.get("anchors"):
            lines.append("")
            lines.append("Links (defanged; none were visited)")
            lines.append(rule)
            for anchor in iocs.get("anchors") or []:
                lines.append(f"  ! {anchor['finding']}")
            for url in (iocs.get("urls") or [])[:12]:
                flags = f"   ← {'; '.join(url['flags'])}" if url.get("flags") else ""
                lines.append(f"  {url['url'][:100]}{flags}")
            reps = (data.get("enrichment") or {}).get("urls") or {}
            for host, rep in list(reps.items())[:8]:
                if isinstance(rep, dict) and "malicious" in rep:
                    lines.append(f"     {host}: VirusTotal {rep['malicious']} malicious, {rep['harmless']} harmless")
        attachments = data.get("attachments") or []
        if attachments:
            lines.append("")
            lines.append("Attachments (typed by content; none were opened)")
            lines.append(rule)
            hashes = (data.get("enrichment") or {}).get("hashes") or {}
            for item in attachments:
                lines.append(f"  {item['filename']}  {item['size']:,} bytes · declared {item['declared_type']} · "
                             f"actually {item['actual_label']}")
                for flag in item.get("flags") or []:
                    lines.append(f"      ! {flag}")
                for entry in (item.get("archive") or {}).get("entries") or []:
                    lines.append(f"      ├ {entry['name']}  {entry['size']:,} bytes"
                                 + ("  (encrypted)" if entry.get("encrypted") else ""))
                if item.get("sha256"):
                    lines.append(f"      sha256 {item['sha256']}")
                    rep = hashes.get(item["sha256"])
                    if isinstance(rep, dict) and rep.get("known"):
                        lines.append(f"      VirusTotal: {rep['malicious']} malicious, {rep['suspicious']} suspicious")
        if risk.get("not_checked"):
            lines.append("")
            for note in risk["not_checked"]:
                lines.append(f"Not checked: {note}")
    elif operation in {"headers", "auth"}:
        headers = data.get("headers") or {}
        sender = headers.get("from") or data.get("from") or {}
        if headers:
            lines.append(f"From:      {sender.get('display', '')} <{sender.get('address', '')}>".rstrip())
            for key, label in (("reply_to", "Reply-To"), ("return_path", "Return-Path")):
                if (headers.get(key) or {}).get("address"):
                    lines.append(f"{label + ':':10} {headers[key]['address']}")
            lines.append(f"Message-ID: {headers.get('message_id', '')}")
            lines.append(f"Date:      {headers.get('date', '')}")
            if headers.get("user_agent"):
                lines.append(f"Mailer:    {headers['user_agent']}")
            for item in headers.get("anomalies") or []:
                lines.append(f"  ! {item}")
            lines.append("")
        auth_block(data.get("auth") or {}, sender)
        if operation == "headers" and headers.get("hops"):
            lines.append("")
            hops_table(headers["hops"], [])
    elif operation == "hops":
        hops_table(data.get("hops") or [], (data.get("enrichment") or {}).get("hops") or [])
    elif operation == "iocs":
        iocs = data.get("iocs") or {}
        for key in ("urls", "domains", "ips", "addresses", "attachment_hashes"):
            values = iocs.get(key) or []
            if not values:
                continue
            lines.append(f"{key.replace('_', ' ').upper()} ({len(values)})")
            for value in values[:40]:
                if isinstance(value, dict):
                    lines.append(f"  {value['url'][:110]}" + (f"   ← {'; '.join(value['flags'])}" if value.get("flags") else ""))
                else:
                    lines.append(f"  {_defang_text(value) if key in {'domains', 'ips'} else value}")
        for anchor in iocs.get("anchors") or []:
            lines.append(f"  ! {anchor['finding']}")
        lines.append("")
        lines.append("Defanged. Nothing above was visited or connected to.")
    elif operation == "attachments":
        for item in data.get("attachments") or []:
            lines.append(f"{item['filename']}  {item['size']:,} bytes · declared {item['declared_type']} · actually {item['actual_label']}")
            for flag in item.get("flags") or []:
                lines.append(f"    ! {flag}")
            for entry in (item.get("archive") or {}).get("entries") or []:
                lines.append(f"    ├ {entry['name']}  {entry['size']:,} bytes" + ("  (encrypted)" if entry.get("encrypted") else ""))
            if item.get("sha256"):
                lines.append(f"    sha256 {item['sha256']}")
        if not data.get("attachments"):
            lines.append("No attachments.")
    else:
        return None

    contacted = data.get("contacted") or []
    lines.append("")
    lines.append("Contacted: " + (", ".join(contacted) if contacted else "nothing — this was a static read"))
    return "\n".join(lines)


def _defang_text(value: str) -> str:
    return value.replace(".", "[.]")


def _short_dn(value: str) -> str:
    """'O=Sectigo Limited, CN=…' → the organisation, else the common name."""

    parts = dict(p.split("=", 1) for p in value.split(", ") if "=" in p) if value else {}
    return parts.get("organizationName") or parts.get("O") or parts.get("commonName") or parts.get("CN") or value[:60]


def _forensic_answer(data: dict[str, Any]) -> str | None:
    """Report what was found, why it matters, and what was not looked at."""

    operation = data.get("operation")
    if operation == "outbound":
        external = data.get("external_count") or 0
        concerning = data.get("concerning") or []
        lines = [f"{external} external outbound connection"
                 + ("s" if external != 1 else "") + "; "
                 + (f"{len(concerning)} worth a look." if concerning else "none stand out.")]
        for item in concerning[:8]:
            lines.append(f"- {item.get('command')} (pid {item.get('pid')}) → "
                         f"{item.get('remote_host')}:{item.get('remote_port')} · {item.get('executable') or 'path unknown'}")
        if not concerning:
            lines.append("Every connection belongs to a signed executable in a normal location.")
        return "\n".join(lines)
    if operation == "listening":
        exposed = data.get("exposed") or []
        lines = [f"{data.get('listening_count') or 0} listening socket"
                 + ("s" if (data.get('listening_count') or 0) != 1 else "")
                 + f"; {len(exposed)} reachable beyond loopback."]
        for item in exposed[:8]:
            lines.append(f"- {item.get('command')} (pid {item.get('pid')}) on "
                         f"{item.get('local_host')}:{item.get('local_port')}")
        if not exposed:
            lines.append("Everything listening is bound to loopback, so nothing is reachable from the network.")
        return "\n".join(lines)
    if operation == "persistence":
        flagged = data.get("flagged") or []
        lines = [f"{data.get('entry_count') or 0} things start automatically; "
                 + (f"{len(flagged)} worth a look." if flagged else "none look unusual.")]
        for item in flagged[:8]:
            lines.append(f"- {item.get('kind')}: {item.get('name')}")
        return "\n".join(lines)
    if operation == "secret_access":
        if data.get("supported") is False:
            return f"Could not check credential access: {data.get('reason')}"
        holders = data.get("holders") or []
        if not holders:
            return ("No process is currently holding your credential files open "
                    f"({len(data.get('checked_paths') or [])} checked).")
        lines = [f"{len(holders)} process"
                 + ("es" if len(holders) != 1 else "") + " currently hold credential files open:"]
        for item in holders[:10]:
            signature = item.get("signature") or {}
            trust = signature.get("authority") or signature.get("package") or (
                "unsigned" if signature.get("signed") is False else "signature not checked")
            lines.append(f"- {item.get('process')} (pid {item.get('pid')}) → {item.get('secret')} · {trust}")
        return "\n".join(lines)
    if operation != "sweep":
        return None
    findings = data.get("findings") or []
    outbound = data.get("outbound") or {}
    listening = data.get("listening") or {}
    if not findings:
        lines = ["Nothing correlated as suspicious."]
    else:
        high = data.get("high_count") or 0
        lines = [f"{len(findings)} finding" + ("s" if len(findings) != 1 else "")
                 + (f", {high} high severity." if high else ", none high severity.")]
        for item in findings[:10]:
            lines.append(f"[{_SEVERITY_LABEL.get(item['severity'], item['severity'].upper())}] {item['what']}")
            for reason in item.get("why", [])[:3]:
                lines.append(f"    - {reason}")
    lines.append(f"Checked: {outbound.get('external_count') or 0} external connections, "
                 f"{listening.get('exposed_count') or 0} exposed listeners, "
                 f"{(data.get('persistence') or {}).get('entry_count') or 0} startup entries, "
                 f"{(data.get('secret_access') or {}).get('holder_count') or 0} credential readers.")
    for note in data.get("not_inspected") or []:
        lines.append(f"Not inspected: {note}")
    return "\n".join(lines)


def _recipes_used(results: list[dict[str, Any]]) -> list[str]:
    """The actual OS commands behind an answer, in the order they were run.

    TACU already records these — `ps -Ao …`, `lsof -nP -iTCP` — and never showed
    them, so "how can I look at this myself" needed three more questions to get
    an answer TACU held all along. Saying what was run also makes the answer
    checkable, which is worth more than the convenience.
    """

    import shlex

    seen: list[str] = []
    for item in results:
        recipe = ((item.get("result") or {}).get("data") or {}).get("recipe")
        if isinstance(recipe, str):
            recipe = [recipe]
        if not isinstance(recipe, list) or not recipe:
            continue
        rendered = " ".join(shlex.quote(str(part)) for part in recipe)
        if rendered not in seen:
            seen.append(rendered)
    return seen


def exact_host_answer(question: str, results: list[dict[str, Any]]) -> str | None:
    """Answer a host-ops intent from native tool results without a model call."""

    if not results:
        return None
    query = question.casefold()
    process_data: list[dict[str, Any]] = []
    network_data: list[dict[str, Any]] = []
    app_data: list[dict[str, Any]] = []
    ollama_data: list[dict[str, Any]] = []
    system_data: list[dict[str, Any]] = []
    docker_data: list[dict[str, Any]] = []
    git_data: list[dict[str, Any]] = []
    file_data: list[dict[str, Any]] = []
    service_data: list[dict[str, Any]] = []
    package_data: list[dict[str, Any]] = []
    security_data: list[dict[str, Any]] = []
    extra_net: list[dict[str, Any]] = []
    for item in results:
        result = item.get("result") or {}
        data = result.get("data") or {}
        tool = result.get("tool")
        if tool == "email" or data.get("message_sha256"):
            rendered = _email_answer(data)
            if rendered:
                return rendered
        if tool == "recon" or (data.get("contacted") is not None and data.get("kind") in {"domain", "ip"}):
            rendered = _recon_answer(data)
            if rendered:
                return rendered
        if data.get("operation") in {"sweep", "outbound", "listening", "persistence", "secret_access"} and (
                data.get("findings") is not None or data.get("holders") is not None
                or data.get("entries") is not None or data.get("concerning") is not None
                or data.get("exposed") is not None):
            forensic = _forensic_answer(data)
            if forensic:
                return forensic
        if data.get("processes") is not None or data.get("open_files") is not None:
            process_data.append(data)
        if (data.get("destination_ports") is not None or data.get("connections") is not None
                or data.get("listening") is not None or data.get("owners") is not None
                or data.get("primary") is not None or data.get("interfaces") is not None
                or data.get("public_ip") is not None):
            network_data.append(data)
        if (data.get("routes") is not None or data.get("dns") is not None or data.get("arp") is not None
                or data.get("records") is not None or data.get("operation") == "resolve"):
            extra_net.append(data)
        if data.get("applications") is not None or data.get("version"):
            app_data.append(data)
        docker_mutate = data.get("operation") in {"stop", "rm", "pull"} and (
            "docker" in query or "container" in query or "image" in query
        )
        ollama_mutate = data.get("operation") in {"pull", "rm", "stop"} and (
            "ollama" in query or ("model" in query and "container" not in query)
        )
        if tool == "ollama" or (tool is None and (
                data.get("models") is not None or data.get("info") is not None
                or data.get("operation") in {"model_info", "running_models",
                                             "installed_models", "settings", "version"}
                or ollama_mutate)):
            ollama_data.append(data)
        if data.get("system") is not None:
            system_data.append(data)
        if tool == "docker" or (tool is None and (
                data.get("containers") is not None or data.get("images") is not None
                or data.get("logs") is not None or data.get("stats") is not None
                or data.get("networks") is not None or data.get("volumes") is not None
                or data.get("operation") in {"start", "rmi", "ps", "inspect"}
                or docker_mutate)):
            docker_data.append(data)
        if (data.get("is_repo") is not None or data.get("repositories") is not None
                or data.get("commits") is not None or data.get("diff") is not None
                or data.get("branches") is not None or data.get("remotes") is not None
                or data.get("changes") is not None
                or data.get("operation") in {"add", "commit", "push", "status", "log", "diff", "branch", "remote"}):
            git_data.append(data)
        if (data.get("matches") is not None or data.get("metadata") is not None
                or data.get("bytes_written") is not None or data.get("url")
                or data.get("deleted") is not None):
            file_data.append(data)
        if data.get("services") is not None:
            service_data.append(data)
        if data.get("packages") is not None:
            package_data.append(data)
        if data.get("signature") is not None or data.get("gatekeeper") is not None or data.get("quarantined") is not None or data.get("sha256") is not None:
            security_data.append(data)
    lines: list[str] = []
    hostname = next(((data.get("system") or {}).get("hostname") for data in system_data
                     if (data.get("system") or {}).get("hostname")), None)
    from .routing import intent_wants_dns_lookup
    wants_name = any(phrase in query for phrase in
                     ("hostname", "system name", "computer name", "machine name", "host name"))
    if wants_name and hostname and not intent_wants_dns_lookup(query):
        lines.append(f"System name: {hostname}")
    # A tool that matched nothing must not author the answer while another tool
    # in the same run did find something. "what is my primary ip address" plans
    # network.interfaces *and* a process.graph filtered on "primary ip address";
    # the graph matched nothing, spoke first, and the address TACU had already
    # read was never reported.
    #
    # Compared by identity, not by content: one result can land in two buckets —
    # operation "inspect" is both a process lookup and a Docker one — and a
    # record must never count as the other tool that found something.
    # "Widened" means the words did not match and a broader view was returned in
    # place of an answer. That is not a match, so it must not out-rank a tool
    # that did match: "what is my primary ip address" plans network.interfaces
    # and a process.graph on "primary ip address", and once the graph learned to
    # widen instead of returning nothing, the widened list started speaking
    # first — the same fault as before, wearing results.
    blank = {id(data) for data in process_data
             if (not data.get("processes") and data.get("open_files") is None)
             or data.get("widened")}
    if blank and any(id(data) not in blank
                     for bucket in (network_data, app_data, ollama_data, system_data,
                                    docker_data, git_data, file_data, service_data,
                                    package_data, security_data)
                     for data in bucket):
        process_data = [data for data in process_data if id(data) not in blank]
    if process_data:
        skip_process = any(word in query for word in ("ollama", "docker", "container"))
        opened = next((data for data in process_data if data.get("open_files") is not None), None)
        tree = next((data for data in process_data if data.get("operation") == "tree"), None)
        if skip_process and not opened and not tree:
            pass
        elif opened:
            rows = opened.get("open_files") or []
            lines.append(f"PID {opened.get('pid')} has {len(rows)} open file(s).")
            lines.extend(f"- {row}" for row in rows[:12])
        elif tree:
            nodes = tree.get("processes") or []
            lines.append(f"Process tree ({len(nodes)} node(s)):")
            lines.extend(
                f"{'  ' * int(item.get('depth') or 0)}- PID {item.get('pid')}: {item.get('command')}"
                for item in nodes[:20]
            )
        else:
            combined: list[dict[str, Any]] = []
            for data in process_data:
                combined.extend(data.get("processes") or [])
            graphed = next((data for data in process_data
                             if data.get("operation") == "graph"), None)
            inspected = next((data for data in process_data
                              if data.get("operation") == "inspect"), None)
            if graphed:
                answer = _graph_answer(graphed)
                if answer:
                    lines.append(answer)
                    return "\n".join(lines) if lines else None
            facts = {"kind": "processes", "processes": combined,
                     "operation": "inspect" if inspected else None,
                     "top_cpu": next((data.get("top") for data in process_data
                                      if data.get("operation") == "top_cpu" and data.get("top")), None),
                     "top_memory": next((data.get("top") for data in process_data
                                         if data.get("operation") == "top_memory" and data.get("top")), None)}
            if not facts["top_cpu"]:
                facts["top_cpu"] = (sort_processes(combined, key="cpu", limit=1) or [None])[0]
            if not facts["top_memory"]:
                facts["top_memory"] = (sort_processes(combined, key="memory", limit=1) or [None])[0]
            answer = _process_answer(query, facts)
            if answer:
                lines.append(answer)
    if network_data:
        data = network_data[0]
        public = next((item.get("public_ip") for item in network_data if item.get("public_ip")), None)
        if public and any(phrase in query for phrase in ("public", "external", "wan", "internet")):
            lines.append(f"Public IP: {public}")
        elif data.get("owners"):
            owner = data["owners"][0]
            lines.append(
                f"{owner.get('command') or 'unknown'} (PID {owner.get('pid')}) owns TCP port {data.get('port')}."
            )
        elif data.get("listening") is not None and "listen" in query:
            answer = _connection_answer(query, {"kind": "network_connections",
                                                "connections": data.get("listening") or [],
                                                "destination_ports": []})
            if answer:
                lines.append(answer)
        elif data.get("primary") is not None or data.get("interfaces"):
            if any(word in query for word in ("ip", "interface", "address", "hostname", "system name")):
                primary = data.get("primary") or {}
                ip = (primary.get("ipv4") or ["unknown"])[0]
                lines.append(f"Primary interface: {primary.get('name')}\nIPv4 address: {ip}")
        elif data.get("connections") is not None or data.get("destination_ports"):
            answer = _connection_answer(query, {
                "kind": "network_connections",
                "state": data.get("state"),
                "connections": data.get("connections") or [],
                "connection_count": data.get("connection_count") or len(data.get("connections") or []),
                "destination_ports": data.get("destination_ports") or [],
                "top_destination_port": data.get("top_destination_port"),
                # Carry the named-host verdict so "am I connected to X" stays a yes/no.
                "host": data.get("host"),
                "host_connected": data.get("host_connected"),
                "host_matches": data.get("host_matches"),
                "resolved": data.get("resolved"),
                "certificate_checked": data.get("certificate_checked"),
                "unattributed_tls": data.get("unattributed_tls"),
            })
            if answer:
                lines.append(answer)
    if app_data:
        named = [data for data in app_data if data.get("query")]
        listed = [data for data in app_data if not data.get("query")]
        by_query: dict[str, list[dict[str, Any]]] = {}
        for data in named:
            by_query.setdefault(str(data.get("query")), []).append(data)
        for query_name, entries in by_query.items():
            lines.extend(_application_answer(query, query_name, _merge_app_results(entries)))
        for data in listed:
            apps = data.get("applications") or []
            if apps:
                lines.append(f"{len(apps)} applications in /Applications:")
                lines.extend(f"- {item.get('display_name') or item.get('name')}" for item in apps[:20])
            if data.get("running") and not named:
                lines.append(f"Running: {_process_label(data['running'][0])}")
    if docker_data:
        data = next((item for item in docker_data if item.get("operation") == "inspect"), None) or docker_data[0]
        if data.get("logs"):
            lines.append(f"Recent logs for `{data.get('name')}`:")
            lines.extend(str(row) for row in data["logs"][-20:])
        elif data.get("stats"):
            stats = data["stats"]
            lines.append(f"Docker stats `{stats.get('name')}`: CPU {stats.get('cpu')}, memory {stats.get('memory')}")
        elif data.get("operation") in {"start", "stop", "rm", "rmi", "pull"}:
            label = data.get("name") or "target"
            verb = {"start": "Started", "stop": "Stopped", "rm": "Removed container",
                    "rmi": "Removed image", "pull": "Pulled"}[data["operation"]]
            if data.get("exit_code") not in (None, 0):
                lines.append(f"{verb} `{label}` failed: {(data.get('stderr') or 'error')[:300]}")
            else:
                lines.append(f"{verb} `{label}`.")
        elif data.get("networks") and not data.get("containers"):
            networks = data.get("networks") or []
            if not networks:
                lines.append("No Docker networks were listed.")
            else:
                lines.append(f"{len(networks)} Docker network(s):")
                lines.extend(f"- {item.get('name')} ({item.get('driver')})" for item in networks[:20])
        elif data.get("volumes") is not None:
            volumes = data.get("volumes") or []
            if not volumes:
                lines.append("No Docker volumes were listed.")
            else:
                lines.append(f"{len(volumes)} Docker volume(s):")
                lines.extend(f"- {item.get('name')}" for item in volumes[:20])
        else:
            containers = data.get("containers") or []
            images = data.get("images") or []
            if data.get("operation") == "images" or images and not containers:
                if not images:
                    lines.append("No Docker images were listed.")
                else:
                    lines.append(f"{len(images)} Docker image(s):")
                    lines.extend(f"- {item.get('image')} ({item.get('size')})" for item in images[:12])
            else:
                if not containers:
                    lines.append("No running Docker containers were found.")
                else:
                    lines.append(f"{len(containers)} Docker container(s):")
                    for item in containers[:20]:
                        network = item.get("network") or ""
                        extra = f" · {network.strip()}" if network else ""
                        lines.append(
                            f"- {item.get('name')} image={item.get('image')} "
                            f"{item.get('status') or ''}{extra}".rstrip()
                        )
    if git_data:
        data = git_data[0]
        if data.get("operation") in {"add", "commit", "push"}:
            verb = {"add": "Staged", "commit": "Committed", "push": "Pushed"}[data["operation"]]
            target = data.get("name") or data.get("message") or data.get("root")
            if data.get("exit_code") not in (None, 0):
                lines.append(f"{verb} failed: {(data.get('stderr') or 'error')[:300]}")
            else:
                lines.append(f"{verb} `{target}`.")
        elif data.get("commits") is not None:
            commits = data.get("commits") or []
            lines.append(f"{len(commits)} recent commit(s) in `{data.get('root')}`:")
            lines.extend(f"- {row}" for row in commits[:20])
        elif data.get("diff") is not None:
            lines.append(f"Git diff in `{data.get('root')}`:")
            lines.append(str(data.get("diff") or ""))
        elif data.get("branches") is not None:
            lines.append(f"Git branches in `{data.get('root')}`:")
            lines.extend(f"- {row}" for row in (data.get("branches") or [])[:20])
        elif data.get("remotes") is not None:
            remotes = data.get("remotes") or []
            if not remotes:
                lines.append(f"No Git remotes in `{data.get('root')}`.")
            else:
                lines.append(f"Git remotes in `{data.get('root')}`:")
                lines.extend(f"- {row}" for row in remotes[:12])
        elif data.get("changes") is not None or data.get("branch"):
            branch = data.get("branch") or "unknown"
            changes = data.get("changes") or []
            lines.append(f"`{data.get('root')}` · {branch}")
            if not changes:
                lines.append("Working tree clean.")
            else:
                lines.append(f"{len(changes)} changed path(s):")
                lines.extend(f"- {row}" for row in changes[:20])
        elif data.get("repositories") is not None:
            repos = data.get("repositories") or []
            if not repos:
                lines.append(f"No Git repositories were found under `{data.get('root')}`.")
            else:
                lines.append(f"Found {len(repos)} Git repositor" + ("y:" if len(repos) == 1 else "ies:"))
                lines.extend(f"- `{path}`" for path in repos[:20])
        elif "is_repo" in data:
            root = data.get("root") or "this directory"
            lines.append(f"`{root}` is a Git repository." if data.get("is_repo")
                         else f"`{root}` is not a Git repository.")
    if file_data:
        wrote = False
        for data in file_data:
            if data.get("deleted") is True:
                lines.append(f"Removed `{data.get('path')}`.")
                wrote = True
            elif data.get("deleted") is False:
                lines.append(f"`{data.get('path') or data.get('name')}` was not found.")
                wrote = True
            if data.get("bytes_written") is not None:
                lines.append(f"Created `{data.get('path')}` ({data.get('bytes_written')} bytes).")
                wrote = True
            if data.get("url"):
                lines.append(f"Local server: {data.get('url')} (PID {data.get('pid')}).")
                if data.get("opened"):
                    lines.append(f"Opened in {data.get('browser') or 'the browser'}.")
                if data.get("pid"):
                    lines.append(f"Stop it with: kill {data.get('pid')}")
                wrote = True
        if not wrote:
            data = file_data[0]
            matches = data.get("matches") or []
            if data.get("content"):
                path = data.get("path") or ((matches[0].get("path") if matches else None) or "file")
                lines.append(f"Contents of `{path}`:")
                lines.append(str(data["content"]))
                if data.get("truncated"):
                    lines.append("(preview truncated)")
            elif data.get("metadata"):
                meta = data["metadata"]
                lines.append(f"`{meta.get('path')}` · {meta.get('bytes')} bytes · mode {meta.get('permissions')}")
                if meta.get("sha256"):
                    lines.append(f"SHA-256: {meta['sha256']}")
                if meta.get("usage"):
                    lines.extend(str(row) for row in meta["usage"][:12])
            elif data.get("operation") == "open" and data.get("path"):
                lines.append(f"Opened `{data['path']}`." if data.get("exit_code") == 0
                             else f"Could not open `{data['path']}`.")
            elif not matches:
                lines.append(f"No files matching `{data.get('query') or 'the request'}` were found.")
            else:
                # A wider view than the question asked for announces itself, and
                # a listing that does not fit says so rather than letting the
                # count imply everything is on screen.
                widened = str(data.get("widened") or "")
                lines.append(f"{widened.capitalize()}." if widened
                             else f"Found {len(matches)} matching path(s):")
                lines.extend(f"- `{item.get('path')}`" for item in matches[:15])
                if len(matches) > 15:
                    lines.append(f"({len(matches) - 15} more not listed; "
                                 f"narrow it by name or directory.)")
    if ollama_data:
        data = next((item for item in ollama_data
                     if item.get("operation") in {"settings", "version"}), ollama_data[0])
        if data.get("operation") == "settings":
            lines.extend(_ollama_settings_answer(query, data))
        elif data.get("operation") == "version":
            lines.append(f"Ollama {data.get('version') or 'version unknown'}.")
        elif data.get("operation") in {"pull", "rm", "stop"}:
            verb = {"pull": "Pulled", "rm": "Removed", "stop": "Stopped"}[data["operation"]]
            if data.get("exit_code") not in (None, 0):
                lines.append(f"{verb} `{data.get('name')}` failed: {(data.get('stderr') or 'error')[:300]}")
            else:
                lines.append(f"{verb} `{data.get('name')}`.")
        elif data.get("info"):
            lines.append(f"Ollama model `{data.get('name')}`:")
            lines.append(str(data["info"])[:2000])
        else:
            models = data.get("models") or []
            if not models:
                lines.append("No Ollama models are currently loaded." if "running" in query
                             else "No installed Ollama models were listed.")
            else:
                label = "loaded" if data.get("operation") == "running_models" else "installed"
                lines.append(f"{len(models)} {label} Ollama model" + ("s:" if len(models) != 1 else ":"))
                for item in models[:40]:
                    size = item.get("size") or item.get("parameter_size") or ""
                    extra = f" · {size}" if size else ""
                    lines.append(f"- {item.get('name')}{extra}")
    if system_data:
        system = system_data[0].get("system") or {}
        if system.get("local_datetime"):
            zone = " ".join(part for part in (system.get("timezone") or "",
                                              f"({system['utc_offset']})" if system.get("utc_offset") else "")
                            if part)
            lines.append(f"{system.get('readable')} {zone}".strip())
        elif system.get("file_count") is not None or system.get("dir_count") is not None:
            files = system.get("file_count") or 0
            folders = system.get("dir_count") or 0
            lines.append(f"{files} files, {folders} folders in `{system.get('cwd') or 'the current directory'}` "
                         "('.' and '..' excluded).")
            if files + folders == 0:
                lines.append("The directory is empty.")
            workspace = system.get("workspace")
            if workspace and workspace != system.get("cwd"):
                lines.append(f"TACU workspace: `{workspace}`")
        elif system.get("cwd") and any(word in query for word in
                                       ("directory", "path", "pwd", "cwd", "where", "workspace")):
            lines.append(f"Current directory: `{system['cwd']}`")
            workspace = system.get("workspace")
            if workspace:
                lines.append(f"TACU workspace: `{workspace}`")
        elif wants_name and hostname:
            pass
        elif system.get("uptime_seconds") is not None:
            lines.append(f"This machine has been up for "
                         f"{_readable_duration(system['uptime_seconds'])}.")
        else:
            # Only lead with the platform when the platform is what was asked about;
            # a disk question answered with "macOS-26.6.2-arm64" answers nothing.
            platform_ask = any(word in query for word in
                               ("os ", "os version", "operating system", "macos", "platform",
                                "architecture", "what os", "system version", "hardware",
                                "machine model", "serial"))
            if platform_ask and system.get("mac_ver"):
                lines.append(f"macOS {system['mac_ver']} ({system.get('architecture')})")
            elif platform_ask and system.get("platform"):
                lines.append(str(system["platform"]))
            if system.get("memory_gib"):
                lines.append(f"Installed memory: {system['memory_gib']} GiB")
            if system.get("cpu_count"):
                lines.append(f"CPU count: {system['cpu_count']}")
            if system.get("volumes"):
                headline = _storage_headline([str(row) for row in system["volumes"]])
                if headline:
                    lines.append(headline)
                lines.append("Mounted volumes:")
                lines.extend(str(row) for row in system["volumes"][:8])
            if system.get("power"):
                lines.append(str(system["power"]).splitlines()[0])
            if system.get("hardware_profile"):
                lines.append(str(system["hardware_profile"]).strip().splitlines()[0])
    if extra_net:
        data = extra_net[0]
        if data.get("routes"):
            lines.append("Routing table:")
            lines.extend(str(row) for row in data["routes"][:12])
        elif data.get("dns"):
            lines.append("DNS configuration:")
            lines.extend(str(data["dns"]).splitlines()[:12])
        elif data.get("arp"):
            lines.append(f"{len(data['arp'])} ARP entries:")
            lines.extend(f"- {row}" for row in data["arp"][:10])
        elif data.get("operation") == "resolve" or data.get("records") is not None:
            host = data.get("host") or "that host"
            records = str(data.get("records") or "").strip()
            if records:
                lines.append(f"DNS records for `{host}`:")
                lines.append(records)
            else:
                kind = "PTR" if data.get("reverse") else "A/AAAA"
                lines.append(f"No {kind} record for `{host}`.")
    if service_data:
        data = service_data[0]
        services = data.get("services") or []
        if data.get("detail"):
            lines.append(f"Service `{data.get('label') or data.get('query')}`:")
            lines.append(str(data["detail"])[:1500])
        elif not services:
            lines.append("No matching services were found.")
        else:
            running = sum(1 for item in services if item.get("running"))
            lines.append(f"{len(services)} service(s) listed ({running} running):")
            lines.extend(f"- {item.get('label')} (PID {item.get('pid') or '-'})" for item in services[:15])
    if package_data:
        data = package_data[0]
        packages = data.get("packages") or []
        if not packages:
            lines.append("No matching packages were found.")
        else:
            lines.append(f"{len(packages)} package(s):")
            for item in packages[:15]:
                lines.append(f"- {item.get('name') or item.get('line')} {item.get('version') or item.get('desc') or ''}".rstrip())
    if security_data:
        data = security_data[0]
        if data.get("gatekeeper"):
            lines.append(f"Gatekeeper: {data['gatekeeper']}")
        if data.get("quarantined") is not None:
            lines.append(f"`{data.get('path')}` is {'quarantined' if data['quarantined'] else 'not quarantined'}.")
        if data.get("sha256"):
            lines.append(f"SHA-256 (`{data.get('path')}`): {data['sha256']}")
        signature = data.get("signature")
        if isinstance(signature, dict):
            lines.append(f"Signature for `{signature.get('path')}`: {signature.get('identifier') or signature.get('output', '')[:400]}")
        elif signature:
            lines.append(str(signature)[:800])
    if not lines:
        return None
    collapsed: list[str] = []
    for line in lines:
        if collapsed and collapsed[-1] == line:
            continue
        collapsed.append(line)
    text = "\n".join(collapsed)
    # Say what was actually run. It makes the answer checkable, and it answers
    # "how can I look at this myself" without a second round trip.
    recipes = _recipes_used(results)
    if recipes:
        text += "\n\nRead the same thing yourself with:\n" + "\n".join(
            f"  {command}" for command in recipes[:3])
    if docker_data or ollama_data or git_data:
        return text
    if "Next:" not in text:
        if any("directory" in line.casefold() or "files," in line for line in lines):
            text += "\n\nNext: Use this directory as the TACU workspace?"
        else:
            text += "\n\nNext: Inspect a specific PID, port, or application in more detail?"
    return text
