"""Hints for common terminal, pentest, and red-team tools."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ToolProfile:
    name: str
    aliases: tuple[str, ...]
    category: str
    output_hint: str


PROFILES = (
    ToolProfile("ifconfig", (), "network", "Interface state and addresses; TACU deterministically selects the strongest primary-interface candidate."),
    ToolProfile("ip", (), "network", "Linux links, addresses and routes; JSON output (-json) is preferred."),
    ToolProfile("ipconfig", (), "network", "Windows adapter addresses and connection state."),
    ToolProfile("docker", (), "containers", "Container/image state; docker inspect JSON is parsed into concise identity, image, status, ports and mounts."),
    ToolProfile("nmap", (), "recon", "Hosts, ports, services, versions, scripts and state; XML (-oX) is preferred."),
    ToolProfile("netexec", ("nxc", "crackmapexec"), "active-directory", "Host/protocol findings, authentication status, domains and shares."),
    ToolProfile("nuclei", (), "scanner", "Template findings with severity, matcher, host and evidence; JSONL (-jsonl) is preferred."),
    ToolProfile("sqlmap", (), "web", "Injection points, DBMS fingerprint, payloads and extracted database objects."),
    ToolProfile("ffuf", (), "web", "Discovered paths/parameters with HTTP status, size, words, lines and duration; JSON is preferred."),
    ToolProfile("gobuster", (), "web", "Discovered paths, DNS names or virtual hosts with status and size."),
    ToolProfile("feroxbuster", (), "web", "Recursive HTTP content discovery with status, size and URL; JSON is preferred."),
    ToolProfile("nikto", (), "web", "Web-server misconfigurations, outdated components and references."),
    ToolProfile("masscan", (), "recon", "High-volume host and open-port observations; JSON or list output is preferred."),
    ToolProfile("metasploit", ("msfconsole",), "exploitation", "Module/job/session output; separate validated results from candidate targets."),
    ToolProfile("hydra", (), "credentials", "Authentication attempts and confirmed service credentials."),
    ToolProfile("john", ("john-the-ripper",), "credentials", "Hash formats, cracking progress and recovered credentials."),
    ToolProfile("hashcat", (), "credentials", "Hash mode, device/progress metrics and recovered hash:plaintext pairs."),
    ToolProfile("tshark", ("wireshark",), "network", "Packets/flows and protocol fields; fields/JSON output is preferred over display text."),
    ToolProfile("responder", (), "active-directory", "Poisoning/listener events and captured challenge-response material."),
    ToolProfile("impacket", ("secretsdump.py", "psexec.py", "wmiexec.py", "getuserspns.py"), "active-directory", "Remote execution, Kerberos or credential material; identify the specific Impacket script."),
    ToolProfile("bloodhound", ("bloodhound-python", "rusthound"), "active-directory", "AD graph collection, object relationships and attack paths."),
    ToolProfile("enum4linux-ng", ("enum4linux",), "smb", "SMB/NetBIOS users, groups, shares, policies and domain metadata; JSON/YAML is preferred."),
    ToolProfile("subfinder", (), "recon", "Passive subdomain observations; JSONL is preferred."),
    ToolProfile("amass", (), "recon", "DNS enumeration and relationship observations; structured output is preferred."),
    ToolProfile("testssl.sh", ("testssl",), "tls", "TLS protocols, ciphers, certificate facts and vulnerability checks; JSON is preferred."),
    ToolProfile("trivy", (), "containers", "Package, image, config and secret findings with severity and fix availability; JSON is preferred."),
    ToolProfile("gophish", (), "phishing", "Campaign, listener and credential-harvest events from phishing infrastructure."),
    ToolProfile("searchsploit", (), "exploitation", "Offline Exploit-DB matches with path, CVE and platform; identify candidate exploits only."),
    ToolProfile("mimikatz", (), "credentials", "Windows credential material; treat output as highly sensitive evidence."),
    ToolProfile("seatbelt", (), "discovery", "Host safety-check findings for local Windows security posture."),
    ToolProfile("lynis", (), "discovery", "Linux audit warnings, suggestions and hardening compliance items."),
    ToolProfile("ligolo-ng", ("ligolo",), "c2", "TUN pivot and reverse-tunnel session state."),
    ToolProfile("rclone", (), "exfiltration", "Cloud sync transfers, remotes and copy/move results."),
    ToolProfile("bettercap", (), "impact", "MITM, spoofing and network-service disruption events."),
    ToolProfile("socat", (), "c2", "Bidirectional relay and tunnel endpoints."),
    ToolProfile("powercat", (), "collection", "PowerShell-native netcat-style listener or client output."),
)


def command_tool(command: str) -> str:
    """Best-effort extraction of the executable, including docker exec/run."""

    tokens = command.replace("\\", "/").split()
    if not tokens:
        return "unknown"
    names = [Path(token.strip("'\"")).name.lower() for token in tokens]
    if names[0] == "docker":
        for marker in ("exec", "run"):
            if marker in names:
                index = names.index(marker) + 1
                # Skip docker options and the container/image token.
                while index < len(names) and names[index].startswith("-"):
                    index += 1
                index += 1
                while index < len(names) and names[index].startswith("-"):
                    index += 1
                if index < len(names):
                    return names[index]
    return names[0]


def find_profile(command: str) -> ToolProfile | None:
    executable = command_tool(command)
    for profile in PROFILES:
        if executable == profile.name or executable in profile.aliases:
            return profile
    return None
