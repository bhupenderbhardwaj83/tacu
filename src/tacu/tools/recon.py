"""What is behind a domain or an address, with every claim tied to its evidence.

Subdomains from certificate transparency and DNS, the addresses they resolve
to, the certificate each one presents, the CDN or WAF in front of it, the
network that owns each address, where it sits, and what reputation sources say
about it. Then a score that shows its working.

Two rules shape everything here. A single indicator proves nothing: "Server:
cloudflare" is one signal, and five agreeing signals are a finding, so every
provider match carries the indicators that produced it. And a reputation source
is evidence, never a verdict: an address behind a CDN hosts thousands of
unrelated customers, so the raw findings are kept and the score is computed in
the open, with each contribution listed.

This is TACU's second outbound feature after `ti web`. Every result says which
external services were contacted, and a name that resolves to a private or
loopback address is reported and never probed — recon must not become a route
to an internal host.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..platform import run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, schema

OPERATIONS = ("sweep", "subdomains", "dns", "tls", "http", "waf", "asn", "geo", "reputation")

SPEC = ToolSpec(
    "recon",
    "External reconnaissance of a domain or IP address: subdomains from certificate "
    "transparency and DNS, address resolution, TLS certificate details, HTTP fingerprint, "
    "WAF/CDN detection scored across several indicators, ASN and network owner, "
    "geolocation, and reputation from AbuseIPDB and VirusTotal when keys are configured. "
    "Use for 'what is behind this domain', 'subdomains of', 'who hosts this', 'is this IP "
    "malicious', 'is it behind Cloudflare', or a full sweep with a risk score.",
    schema(properties={
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "target": {"type": "string"},
        "limit": {"type": "integer"},
        "bruteforce": {"type": "boolean"},
        "timeout": {"type": "integer"},
    }, required=("operation", "target")),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"},
                       "target": {"type": "string"}, "contacted": {"type": "array"}}),
    timeout=120, risk_level="read", permissions=("network:outbound",),
    when_to_use="Questions about a domain or public address you are checking: what is behind "
                "it, who hosts it, is it fronted by a CDN, what does its reputation look like.",
    when_not="Anything about this machine's own connections or listeners; use network or "
             "forensics for those.",
)

USER_AGENT = "TACU-recon/1.0"
MAX_SUBDOMAINS = 200
MAX_PROBED_HOSTS = 12
MAX_BODY_BYTES = 64_000

# Names worth trying when the user explicitly asks for a bruteforce pass. Bounded
# and dull on purpose: this is DNS only, and a long list is a different tool.
COMMON_SUBDOMAINS = (
    "www", "mail", "api", "app", "dev", "staging", "test", "vpn", "remote", "portal",
    "admin", "cdn", "static", "assets", "img", "media", "blog", "shop", "store", "docs",
    "help", "support", "status", "login", "auth", "sso", "id", "accounts", "m", "mobile",
    "beta", "demo", "sandbox", "gateway", "gw", "smtp", "imap", "pop", "ftp", "sftp",
    "git", "gitlab", "jenkins", "ci", "grafana", "kibana", "monitor", "metrics", "ns1",
    "ns2", "mx", "mx1", "autodiscover", "webmail", "owa", "exchange", "office", "intranet",
)

# Provider fingerprints. Each row is one indicator: where it is seen, what to
# match, and how much it is worth. A provider's confidence is the sum of the
# indicators that fired, capped — so a lone "Server:" header never reaches high
# confidence, and a CNAME plus headers plus the ASN does.
#   kind: cname | header | cookie | asn | issuer | body
_WAF_SIGNATURES: tuple[tuple[str, str, str, int], ...] = (
    ("Cloudflare", "header", r"^server:\s*cloudflare", 40),
    ("Cloudflare", "header", r"^cf-ray:", 45),
    ("Cloudflare", "header", r"^cf-cache-status:", 30),
    ("Cloudflare", "cookie", r"^__cf_bm=|^__cflb=|^cf_clearance=", 35),
    ("Cloudflare", "asn", r"^13335$", 40),
    ("Cloudflare", "cname", r"\.cdn\.cloudflare\.net\.?$", 45),
    ("Cloudflare", "issuer", r"Cloudflare", 20),
    ("Akamai", "cname", r"\.(?:edgesuite|edgekey|akamaiedge|akamaized|akamai)\.net\.?$", 55),
    ("Akamai", "header", r"^server:\s*akamai", 40),
    ("Akamai", "header", r"^x-akamai-", 40),
    ("Akamai", "asn", r"^(?:16625|20940|32787|35994|63949)$", 35),
    ("AWS CloudFront", "cname", r"\.cloudfront\.net\.?$", 55),
    ("AWS CloudFront", "header", r"^x-amz-cf-id:|^x-amz-cf-pop:", 45),
    ("AWS CloudFront", "header", r"^via:.*cloudfront", 40),
    ("AWS CloudFront", "asn", r"^(?:16509|14618)$", 25),
    ("AWS WAF", "header", r"^x-amzn-waf-", 50),
    ("Azure Front Door", "cname", r"\.(?:azurefd|azureedge|trafficmanager)\.net\.?$", 55),
    ("Azure Front Door", "header", r"^x-azure-ref:", 45),
    ("Azure Front Door", "asn", r"^8075$", 30),
    ("Fastly", "cname", r"\.fastly\.net\.?$|\.fastlylb\.net\.?$", 55),
    ("Fastly", "header", r"^x-served-by:\s*cache-", 40),
    ("Fastly", "header", r"^x-fastly-", 40),
    ("Fastly", "asn", r"^54113$", 40),
    ("Imperva", "cname", r"\.incapdns\.net\.?$", 55),
    ("Imperva", "header", r"^x-iinfo:|^x-cdn:\s*imperva", 45),
    ("Imperva", "cookie", r"^visid_incap_|^incap_ses_", 45),
    ("Imperva", "asn", r"^19551$", 35),
    ("F5", "cookie", r"^BIGipServer|^TS[0-9a-f]{6,}=", 45),
    ("F5", "header", r"^server:\s*big-?ip", 40),
    ("Sucuri", "header", r"^x-sucuri-id:|^server:\s*sucuri", 50),
    ("Sucuri", "cname", r"\.sucuri\.net\.?$", 50),
    ("Google Cloud", "header", r"^via:.*google|^server:\s*gws$", 30),
    ("Google Cloud", "asn", r"^(?:15169|396982)$", 30),
    ("GitHub Pages", "cname", r"\.github\.io\.?$", 55),
    ("GitHub", "header", r"^server:\s*github\.com", 45),
    ("GitHub", "asn", r"^36459$", 40),
    ("Netlify", "cname", r"\.netlify\.(?:app|com)\.?$", 55),
    ("Netlify", "header", r"^server:\s*netlify", 45),
    ("Vercel", "cname", r"\.vercel(?:-dns)?\.(?:app|com)\.?$", 55),
    ("Vercel", "header", r"^server:\s*vercel|^x-vercel-", 45),
)
_CDN_PROVIDERS = frozenset(("Cloudflare", "Akamai", "AWS CloudFront", "Azure Front Door",
                            "Fastly", "Imperva", "Sucuri", "GitHub Pages", "Netlify", "Vercel"))

# Risk contributions. Each is a fact and a weight; the answer lists every one
# that applied. The weights are the ones the user asked for, and they are meant
# to be read, argued with and tuned — not trusted as an oracle.
_RISK_WEIGHTS: dict[str, int] = {
    "virustotal_malicious": 30,
    "abuseipdb_high": 30,
    "recently_registered": 10,
    "suspicious_asn": 10,
    "known_cdn": -10,
    "long_lived_domain": -5,
}


class ReconError(ToolFailure):
    pass


@dataclass
class Evidence:
    """Everything a stage learned, and which external service it asked."""

    contacted: list[str] = field(default_factory=list)
    recipe: list[list[str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def contact(self, service: str) -> None:
        if service not in self.contacted:
            self.contacted.append(service)

    def ran(self, argv: list[str]) -> None:
        if argv and argv not in self.recipe:
            self.recipe.append(list(argv))

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)


# ---------------------------------------------------------------------------
# Transport: the only place that talks to the outside. Injected in tests.
# ---------------------------------------------------------------------------


class Transport:
    """DNS, HTTPS-JSON, TLS and HTTP probes, each bounded and each SSRF-guarded."""

    def __init__(self, timeout: int = 15) -> None:
        self.timeout = max(2, min(int(timeout or 15), 60))

    # -- DNS ------------------------------------------------------------------

    def dns(self, name: str, record: str, evidence: Evidence) -> list[str]:
        """Answers for one record type. `dig` when present, else A/AAAA via the resolver."""

        dig = which("dig")
        if dig:
            argv = [dig, "+short", "+time=5", "+tries=1", name, record]
            raw = run_argv(argv, timeout=self.timeout)
            evidence.ran(argv)
            if raw["exit_code"] in {0, 1, 9}:
                return [line.strip().rstrip(".") if record in {"CNAME", "NS", "MX", "PTR"}
                        else line.strip()
                        for line in (raw.get("stdout") or "").splitlines() if line.strip()]
            return []
        if record not in {"A", "AAAA"}:
            evidence.note(f"{record} records were not checked: dig is not installed")
            return []
        family = socket.AF_INET if record == "A" else socket.AF_INET6
        try:
            found = socket.getaddrinfo(name, None, family=family, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        evidence.ran(["getaddrinfo", name])
        seen: list[str] = []
        for _family, _type, _proto, _canon, sockaddr in found:
            if sockaddr[0] not in seen:
                seen.append(sockaddr[0])
        return seen

    # -- HTTPS JSON (public, GET-only, guarded) --------------------------------

    def get_json(self, url: str, evidence: Evidence, *, service: str,
                 headers: dict[str, str] | None = None) -> Any:
        status, response_headers, body = self._request(url, evidence, headers=headers,
                                                       service=service)
        if status == 429:
            raise ReconError(f"{service} rate-limited this lookup; try again shortly.",
                             code="rate_limited", retryable=True)
        if status in {401, 403}:
            raise ReconError(f"{service} rejected the request ({status}): check the key.",
                             code="unauthorised")
        if status != 200:
            raise ReconError(f"{service} returned HTTP {status}.", code="upstream")
        if not body.strip():
            raise ReconError(f"{service} returned an empty body.", code="upstream", retryable=True)
        try:
            return json.loads(body.decode("utf-8", errors="replace"))
        except ValueError as error:
            raise ReconError(f"{service} returned something that was not JSON.",
                             code="upstream", retryable=True) from error

    # -- HTTP probe (headers only, same-origin, guarded) -----------------------

    def probe(self, host: str, evidence: Evidence) -> dict[str, Any]:
        """One GET to https://host/ recording status, headers and cookies."""

        url = f"https://{host}/"
        try:
            status, headers, body = self._request(url, evidence, service=f"https://{host}",
                                                  max_bytes=MAX_BODY_BYTES)
        except ReconError as error:
            if error.code == "not_public":
                raise
            # Fall back to plain HTTP once: some hosts only speak it.
            url = f"http://{host}/"
            status, headers, body = self._request(url, evidence, service=f"http://{host}",
                                                  max_bytes=MAX_BODY_BYTES)
        cookies = []
        for key, value in headers:
            if key == "set-cookie":
                cookies.append(value.split(";", 1)[0])
        # Header values can carry the same session material; keep set-cookie
        # to its name in what leaves this function.
        headers = [(key, (value.split("=", 1)[0] + "=…") if key == "set-cookie" else value)
                   for key, value in headers]
        return {"url": url, "status": status,
                "headers": [f"{key}: {value}" for key, value in headers],
                "cookies": [c.split("=", 1)[0] + "=…" for c in cookies],
                "body_sample": body[:400].decode("utf-8", errors="replace")}

    # -- TLS -------------------------------------------------------------------

    def tls(self, host: str, evidence: Evidence, port: int = 443) -> dict[str, Any]:
        endpoints = _public_endpoints(host, port)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE   # we are describing the cert, not trusting it
        last: OSError | None = None
        for family, socktype, proto, sockaddr in endpoints:
            raw = socket.socket(family, socktype, proto)
            raw.settimeout(self.timeout)
            try:
                raw.connect(sockaddr)
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    evidence.contact(f"tls://{host}:{port}")
                    der = tls.getpeercert(binary_form=True) or b""
                    return _describe_certificate(tls, der)
            except OSError as error:
                last = error
                raw.close()
                continue
        raise ReconError(f"No TLS handshake with {host}:{port}: {last}", code="unreachable")

    # -- internals -----------------------------------------------------------------

    def _request(self, url: str, evidence: Evidence, *, service: str,
                 headers: dict[str, str] | None = None,
                 max_bytes: int = 2_000_000) -> tuple[int, list[tuple[str, str]], bytes]:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        endpoints = _public_endpoints(host, port)
        connection: http.client.HTTPConnection
        if parsed.scheme == "https":
            connection = _PinnedHTTPS(host, port, endpoints, self.timeout)
        else:
            connection = _PinnedHTTP(host, port, endpoints, self.timeout)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        sent = {"User-Agent": USER_AGENT, "Accept": "application/json, text/html;q=0.5, */*;q=0.1",
                "Accept-Encoding": "identity"}
        sent.update(headers or {})
        try:
            connection.request("GET", path, headers=sent)
            response = connection.getresponse()
            evidence.contact(service)
            body = response.read(max_bytes + 1)[:max_bytes]
            return response.status, [(k.casefold(), v) for k, v in response.getheaders()], body
        except (socket.timeout, TimeoutError) as error:
            raise ReconError(f"{service} did not answer within {self.timeout}s.",
                             code="timeout", retryable=True) from error
        except (ssl.SSLError, http.client.HTTPException, OSError) as error:
            raise ReconError(f"Could not reach {service}: {error}", code="unreachable") from error
        finally:
            connection.close()


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, endpoints: list, timeout: int) -> None:
        super().__init__(host, port, timeout=timeout)
        self._endpoints = endpoints

    def connect(self) -> None:
        self.sock = _connect_pinned(self._endpoints, self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, endpoints: list, timeout: int) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._endpoints = endpoints

    def connect(self) -> None:
        raw = _connect_pinned(self._endpoints, self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _connect_pinned(endpoints: list, timeout: float | None) -> socket.socket:
    last: OSError | None = None
    for family, socktype, proto, sockaddr in endpoints:
        candidate = socket.socket(family, socktype, proto)
        candidate.settimeout(timeout)
        try:
            candidate.connect(sockaddr)
            return candidate
        except OSError as error:
            last = error
            candidate.close()
    raise OSError(str(last) if last else "no endpoint accepted the connection")


def is_public_address(value: str) -> bool:
    """The same rule `ti web` applies: only the public internet is a destination."""

    from ..web import _is_public

    try:
        return _is_public(ipaddress.ip_address(value))
    except ValueError:
        return False


def _public_endpoints(host: str, port: int) -> list:
    """Resolve once and pin the sockets, refusing anything not on the public internet."""

    try:
        literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not is_public_address(host):
        raise ReconError(f"{host} is not a public address; recon does not probe private "
                         f"or loopback hosts.", code="not_public")
    try:
        raw = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ReconError(f"{host} does not resolve: {error}", code="unresolved") from error
    endpoints = []
    for family, socktype, proto, _canon, sockaddr in raw:
        if not is_public_address(sockaddr[0]):
            raise ReconError(f"{host} resolves to {sockaddr[0]}, which is not public; recon "
                             f"does not probe private or loopback hosts.", code="not_public")
        endpoints.append((family, socktype, proto, sockaddr))
    if not endpoints:
        raise ReconError(f"No usable address for {host}.", code="unresolved")
    return endpoints


def _describe_certificate(tls: ssl.SSLSocket, der: bytes) -> dict[str, Any]:
    """Issuer, subject, SANs, validity and fingerprint from a live handshake."""

    # getpeercert() with verification off returns {}, so parse what we can from
    # the DER via a second, non-verifying decode using the ssl helpers.
    info: dict[str, Any] = {"tls_version": tls.version(), "cipher": (tls.cipher() or ("",))[0],
                            "sha256": hashlib.sha256(der).hexdigest() if der else ""}
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        parsed = _parse_pem_certificate(pem)
    except Exception:   # a malformed cert is still a fact worth reporting
        parsed = {}
    info.update(parsed)
    return info


def _parse_pem_certificate(pem: str) -> dict[str, Any]:
    """Decode subject, issuer, SANs and validity without a dependency.

    `ssl` will decode a certificate it loads from a file, so write the PEM to a
    temporary file and ask it. Not elegant; entirely standard library.
    """

    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
        handle.write(pem)
        path = handle.name
    try:
        decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    def flatten(name: Any) -> str:
        parts = []
        for rdn in name or ():
            for key, value in rdn:
                parts.append(f"{key}={value}")
        return ", ".join(parts)
    sans = [value for kind, value in decoded.get("subjectAltName", ()) if kind == "DNS"]
    return {
        "subject": flatten(decoded.get("subject")),
        "issuer": flatten(decoded.get("issuer")),
        "san": sans,
        "not_before": _iso(decoded.get("notBefore")),
        "not_after": _iso(decoded.get("notAfter")),
        "serial": decoded.get("serialNumber", ""),
    }


def _iso(value: Any) -> str:
    if not value:
        return ""
    try:
        return datetime.strptime(str(value), "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc).isoformat()
    except ValueError:
        return str(value)


# ---------------------------------------------------------------------------
# Stages. Each takes what it needs and records what it did.
# ---------------------------------------------------------------------------


def normalise_target(value: str) -> tuple[str, str]:
    """('domain'|'ip', cleaned target). Strips schemes, paths, ports and trailing dots."""

    text = (value or "").strip()
    if not text:
        raise ReconError("recon needs a domain or an IP address as target.", code="invalid_arguments")
    if "://" in text:
        text = urllib.parse.urlsplit(text).hostname or ""
    text = text.split("/", 1)[0].rstrip(".").casefold()
    if re.fullmatch(r"\[?[0-9a-f:]+\]?", text) and ":" in text:
        text = text.strip("[]")
    elif ":" in text:
        text = text.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(text)
        return "ip", text
    except ValueError:
        pass
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", text):
        raise ReconError(f"{value!r} is not a domain name or an IP address.", code="invalid_arguments")
    return "domain", text


def discover_subdomains(domain: str, transport: Transport, evidence: Evidence, *,
                        bruteforce: bool = False, limit: int = MAX_SUBDOMAINS) -> dict[str, Any]:
    """Names beneath a domain, each tagged with where it was seen."""

    found: dict[str, list[str]] = {}

    def add(name: str, source: str) -> None:
        name = name.strip().rstrip(".").casefold()
        if name.startswith("*."):
            name = name[2:]
        if not name.endswith("." + domain) and name != domain:
            return
        found.setdefault(name, [])
        if source not in found[name]:
            found[name].append(source)

    ct_error = ""
    for attempt in range(2):   # crt.sh answers empty now and then; one retry is cheap
        try:
            rows = transport.get_json(
                f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json",
                evidence, service="crt.sh")
            for row in rows if isinstance(rows, list) else []:
                for name in str(row.get("name_value") or "").splitlines():
                    add(name, "certificate transparency")
            ct_error = ""
            break
        except ReconError as error:
            ct_error = str(error)
            if not error.retryable:
                break
    if ct_error:
        evidence.note(f"certificate transparency was not available: {ct_error}")

    add(domain, "the domain itself")
    for record in ("NS", "MX"):
        for answer in transport.dns(domain, record, evidence):
            host = answer.split()[-1] if record == "MX" else answer
            if host.endswith(domain):
                add(host, f"{record} record")
    if bruteforce:
        for label in COMMON_SUBDOMAINS:
            candidate = f"{label}.{domain}"
            if candidate in found:
                continue
            if transport.dns(candidate, "A", evidence) or transport.dns(candidate, "AAAA", evidence):
                add(candidate, "name list")
        evidence.note(f"{len(COMMON_SUBDOMAINS)} common names were tried by DNS")

    names = sorted(found)
    return {"domain": domain, "subdomains": [{"name": n, "sources": found[n]} for n in names[:limit]],
            "count": len(names), "truncated": len(names) > limit,
            "ct_available": not ct_error}


def resolve(name: str, transport: Transport, evidence: Evidence) -> dict[str, Any]:
    """Addresses and the CNAME chain, with a public/private judgement on each."""

    chain: list[str] = []
    current = name
    for _ in range(6):
        targets = transport.dns(current, "CNAME", evidence)
        if not targets:
            break
        chain.append(targets[0])
        current = targets[0]
    addresses = []
    for record in ("A", "AAAA"):
        for value in transport.dns(name, record, evidence):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            addresses.append({"ip": value, "public": is_public_address(value)})
    result = {"name": name, "cname_chain": chain, "addresses": addresses,
              "ns": transport.dns(name, "NS", evidence), "mx": transport.dns(name, "MX", evidence),
              "txt": transport.dns(name, "TXT", evidence)}
    ptr = []
    for entry in addresses[:4]:
        if entry["public"]:
            ptr.extend(transport.dns(_reverse_name(entry["ip"]), "PTR", evidence))
    result["ptr"] = ptr
    return result


def _reverse_name(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    return address.reverse_pointer


def lookup_asn(ip: str, transport: Transport, evidence: Evidence) -> dict[str, Any]:
    """Origin AS, prefix and registry from Team Cymru, over DNS — keyless and canonical."""

    address = ipaddress.ip_address(ip)
    if isinstance(address, ipaddress.IPv4Address):
        query = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = address.exploded.replace(":", "")
        query = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
    answers = transport.dns(query, "TXT", evidence)
    evidence.contact("asn.cymru.com (DNS)")
    if not answers:
        return {"ip": ip, "asn": "", "prefix": "", "country": "", "registry": "",
                "allocated": "", "owner": "", "note": "no origin AS answer"}
    # "36459 | 140.82.112.0/20 | US | arin | 2018-04-25" — the most specific prefix
    # is the most useful, so keep the longest.
    best: dict[str, str] = {}
    for line in answers:
        parts = [p.strip() for p in line.strip('"').split("|")]
        if len(parts) < 5:
            continue
        row = {"asn": parts[0].split()[0], "prefix": parts[1], "country": parts[2],
               "registry": parts[3], "allocated": parts[4]}
        if not best or _prefix_length(row["prefix"]) > _prefix_length(best["prefix"]):
            best = row
    owner = ""
    if best.get("asn"):
        for line in transport.dns(f"AS{best['asn']}.asn.cymru.com", "TXT", evidence):
            parts = [p.strip() for p in line.strip('"').split("|")]
            if len(parts) >= 5:
                owner = parts[4]
                break
    return {"ip": ip, **best, "owner": owner}


def _prefix_length(prefix: str) -> int:
    try:
        return int(prefix.rsplit("/", 1)[1])
    except (IndexError, ValueError):
        return -1


def lookup_geo(ip: str, transport: Transport, evidence: Evidence) -> dict[str, Any]:
    """Country, region, city and organisation from ipinfo.io's keyless tier."""

    data = transport.get_json(f"https://ipinfo.io/{urllib.parse.quote(ip)}/json", evidence,
                              service="ipinfo.io")
    if not isinstance(data, dict):
        raise ReconError("ipinfo.io returned an unexpected shape.", code="upstream")
    return {"ip": ip, "hostname": data.get("hostname", ""), "city": data.get("city", ""),
            "region": data.get("region", ""), "country": data.get("country", ""),
            "org": data.get("org", ""), "timezone": data.get("timezone", ""),
            "loc": data.get("loc", "")}


def reputation_keys() -> dict[str, str]:
    """AbuseIPDB and VirusTotal keys from the environment or config — never from argv."""

    from ..configuration import load_config

    stored = load_config().get("recon") or {}
    if not isinstance(stored, dict):
        stored = {}
    return {
        "abuseipdb": (os.environ.get("TACU_ABUSEIPDB_KEY") or str(stored.get("abuseipdb_key") or "")).strip(),
        "virustotal": (os.environ.get("TACU_VIRUSTOTAL_KEY") or str(stored.get("virustotal_key") or "")).strip(),
    }


def lookup_reputation(ip: str, transport: Transport, evidence: Evidence,
                      keys: dict[str, str] | None = None) -> dict[str, Any]:
    """What AbuseIPDB and VirusTotal report — raw, with 'not checked' when there is no key."""

    keys = keys if keys is not None else reputation_keys()
    out: dict[str, Any] = {"ip": ip, "abuseipdb": None, "virustotal": None, "not_checked": []}
    if keys.get("abuseipdb"):
        try:
            data = transport.get_json(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}"
                f"&maxAgeInDays=90&verbose=", evidence, service="AbuseIPDB",
                headers={"Key": keys["abuseipdb"], "Accept": "application/json"})
            row = (data or {}).get("data") or {}
            out["abuseipdb"] = {
                "confidence": int(row.get("abuseConfidenceScore") or 0),
                "reports": int(row.get("totalReports") or 0),
                "last_reported": row.get("lastReportedAt") or "",
                "usage_type": row.get("usageType") or "",
                "isp": row.get("isp") or "",
                "is_public": row.get("isPublic"),
                "tor": bool(row.get("isTor")),
            }
        except ReconError as error:
            out["not_checked"].append(f"AbuseIPDB: {error}")
    else:
        out["not_checked"].append("AbuseIPDB: no key (set TACU_ABUSEIPDB_KEY or ti config keys)")
    if keys.get("virustotal"):
        try:
            data = transport.get_json(
                f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}",
                evidence, service="VirusTotal",
                headers={"x-apikey": keys["virustotal"], "Accept": "application/json"})
            attrs = ((data or {}).get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            out["virustotal"] = {
                "malicious": int(stats.get("malicious") or 0),
                "suspicious": int(stats.get("suspicious") or 0),
                "harmless": int(stats.get("harmless") or 0),
                "undetected": int(stats.get("undetected") or 0),
                "reputation": attrs.get("reputation"),
                "as_owner": attrs.get("as_owner") or "",
            }
        except ReconError as error:
            out["not_checked"].append(f"VirusTotal: {error}")
    else:
        out["not_checked"].append("VirusTotal: no key (set TACU_VIRUSTOTAL_KEY or ti config keys)")
    return out


def detect_waf(*, cname_chain: list[str], headers: list[str], cookies: list[str],
               asn: str, issuer: str) -> dict[str, Any]:
    """Which provider fronts this host, and every indicator that says so.

    Confidence is the capped sum of the indicators that fired. One header is
    weak on its own; a CNAME, two headers, a cookie and the ASN agreeing is not.
    """

    hits: dict[str, list[dict[str, str]]] = {}
    fields = {
        "cname": cname_chain, "header": headers, "cookie": cookies,
        "asn": [asn] if asn else [], "issuer": [issuer] if issuer else [],
    }
    for provider, kind, pattern, weight in _WAF_SIGNATURES:
        for value in fields.get(kind, []):
            if re.search(pattern, value, re.I):
                # A cookie's name is the indicator; its value is a session token
                # and has no place in an answer or a log.
                shown = value.split("=", 1)[0] + "=…" if kind == "cookie" else value[:160]
                hits.setdefault(provider, []).append(
                    {"kind": kind, "evidence": shown, "weight": weight})
                break
    ranked = []
    for provider, indicators in hits.items():
        confidence = min(98, sum(item["weight"] for item in indicators))
        ranked.append({"provider": provider, "confidence": confidence,
                       "cdn": provider in _CDN_PROVIDERS, "indicators": indicators})
    ranked.sort(key=lambda item: -item["confidence"])
    return {"providers": ranked,
            "verdict": (f"{ranked[0]['provider']} ({ranked[0]['confidence']}% confidence, "
                        f"{len(ranked[0]['indicators'])} indicator"
                        f"{'s' if len(ranked[0]['indicators']) != 1 else ''})")
            if ranked else "no CDN or WAF indicators seen"}


def score_risk(*, reputation: dict[str, Any] | None, asn: dict[str, Any] | None,
               tls: dict[str, Any] | None, waf: dict[str, Any] | None,
               registered: str = "") -> dict[str, Any]:
    """A score that lists its own contributions, never a bare verdict."""

    contributions: list[dict[str, Any]] = []

    def add(key: str, why: str) -> None:
        contributions.append({"factor": key, "weight": _RISK_WEIGHTS[key], "why": why})

    vt = (reputation or {}).get("virustotal") or {}
    if vt.get("malicious", 0) > 0:
        add("virustotal_malicious", f"{vt['malicious']} engine(s) flag it malicious")
    ab = (reputation or {}).get("abuseipdb") or {}
    if ab.get("confidence", 0) > 80:
        add("abuseipdb_high", f"abuse confidence {ab['confidence']}% from {ab.get('reports', 0)} report(s)")
    allocated = (asn or {}).get("allocated") or registered
    if allocated and _days_since(allocated) is not None and _days_since(allocated) < 90:
        add("recently_registered", f"allocated {allocated}, under 90 days ago")
    owner = ((asn or {}).get("owner") or "").casefold()
    if owner and any(word in owner for word in ("bulletproof", "offshore", "anonymous")):
        add("suspicious_asn", f"AS owner '{(asn or {}).get('owner')}'")
    providers = (waf or {}).get("providers") or []
    if providers and providers[0].get("cdn") and providers[0].get("confidence", 0) >= 60:
        add("known_cdn", f"fronted by {providers[0]['provider']}: the address is shared "
                         f"with many unrelated customers")
    not_before = (tls or {}).get("not_before")
    if not_before and (_days_since(not_before) or 0) > 365:
        add("long_lived_domain", f"certificate history since {not_before[:10]}")

    total = sum(item["weight"] for item in contributions)
    if total >= 60:
        level = "HIGH"
    elif total >= 30:
        level = "MEDIUM"
    elif total > 0:
        level = "LOW"
    else:
        level = "NONE OBSERVED"
    not_checked = list((reputation or {}).get("not_checked") or [])
    return {"score": total, "level": level, "contributions": contributions,
            "not_checked": not_checked,
            "caveat": ("A score is only as complete as the sources behind it"
                       + (": " + "; ".join(not_checked) if not_checked else "") + ".")}


def _days_since(value: str) -> int | None:
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            when = datetime.strptime(value[:len("2026-09-09T00:00:00+00:00")], fmt)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - when).days
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def sweep(target: str, transport: Transport, evidence: Evidence, *, bruteforce: bool,
          limit: int, keys: dict[str, str] | None = None) -> dict[str, Any]:
    """The whole pipeline, correlated: discover → resolve → tls → http → waf → asn → geo → reputation → score."""

    kind, target = normalise_target(target)
    report: dict[str, Any] = {"target": target, "kind": kind}
    hosts: list[str]
    if kind == "domain":
        report["subdomains"] = discover_subdomains(target, transport, evidence,
                                                   bruteforce=bruteforce, limit=limit)
        hosts = [target] + [item["name"] for item in report["subdomains"]["subdomains"]
                            if item["name"] != target][:MAX_PROBED_HOSTS - 1]
    else:
        hosts = [target]

    findings: list[dict[str, Any]] = []
    asn_cache: dict[str, dict[str, Any]] = {}
    for host in hosts:
        entry: dict[str, Any] = {"host": host}
        if kind == "domain":
            entry["dns"] = resolve(host, transport, evidence)
            public = [a["ip"] for a in entry["dns"]["addresses"] if a["public"]]
            private = [a["ip"] for a in entry["dns"]["addresses"] if not a["public"]]
            if private:
                entry["skipped"] = f"resolves to non-public {', '.join(private)}; not probed"
        else:
            public = [target]
        if public:
            ip = public[0]
            if ip not in asn_cache:
                try:
                    asn_cache[ip] = lookup_asn(ip, transport, evidence)
                except ReconError as error:
                    asn_cache[ip] = {"ip": ip, "note": str(error)}
            entry["asn"] = asn_cache[ip]
            if kind == "domain" and not entry.get("skipped"):
                try:
                    entry["tls"] = transport.tls(host, evidence)
                except ReconError as error:
                    entry["tls"] = {"note": str(error)}
                try:
                    entry["http"] = transport.probe(host, evidence)
                except ReconError as error:
                    entry["http"] = {"note": str(error)}
                entry["waf"] = detect_waf(
                    cname_chain=entry["dns"]["cname_chain"],
                    headers=entry.get("http", {}).get("headers", []),
                    cookies=entry.get("http", {}).get("cookies", []),
                    asn=entry["asn"].get("asn", ""),
                    issuer=entry.get("tls", {}).get("issuer", ""))
        findings.append(entry)

    # Enrich the primary address only: geo and reputation are per-IP and cost a
    # request each, and the first host is the one the question was about.
    primary = next((f for f in findings if f.get("asn", {}).get("asn")), findings[0] if findings else {})
    primary_ip = primary.get("asn", {}).get("ip") or (target if kind == "ip" else "")
    if primary_ip:
        try:
            report["geo"] = lookup_geo(primary_ip, transport, evidence)
        except ReconError as error:
            report["geo"] = {"ip": primary_ip, "note": str(error)}
        report["reputation"] = lookup_reputation(primary_ip, transport, evidence, keys)
        report["risk"] = score_risk(reputation=report["reputation"], asn=primary.get("asn"),
                                    tls=primary.get("tls"), waf=primary.get("waf"))
    report["hosts"] = findings
    return report


def execute(context: ToolContext, *, operation: str, target: str, limit: int = 50,
            bruteforce: bool = False, timeout: int = 15) -> dict[str, Any]:
    transport = Transport(timeout=timeout)
    evidence = Evidence()
    cap = max(1, min(int(limit or 50), MAX_SUBDOMAINS))
    kind, cleaned = normalise_target(target)
    data: dict[str, Any]
    if operation == "sweep":
        data = sweep(cleaned, transport, evidence, bruteforce=bool(bruteforce), limit=cap)
    elif operation == "subdomains":
        if kind != "domain":
            raise ReconError("subdomains needs a domain, not an IP address.", code="invalid_arguments")
        data = discover_subdomains(cleaned, transport, evidence, bruteforce=bool(bruteforce), limit=cap)
    elif operation == "dns":
        data = resolve(cleaned, transport, evidence) if kind == "domain" else {
            "name": cleaned, "ptr": transport.dns(_reverse_name(cleaned), "PTR", evidence)}
    elif operation == "tls":
        if kind != "domain":
            raise ReconError("tls needs a host name to present in the handshake.", code="invalid_arguments")
        data = {"host": cleaned, **transport.tls(cleaned, evidence)}
    elif operation == "http":
        data = transport.probe(cleaned, evidence)
    elif operation == "waf":
        dns = resolve(cleaned, transport, evidence) if kind == "domain" else {"cname_chain": [], "addresses": [{"ip": cleaned, "public": is_public_address(cleaned)}]}
        public = [a["ip"] for a in dns["addresses"] if a["public"]]
        asn = lookup_asn(public[0], transport, evidence) if public else {}
        tls = {}
        http: dict[str, Any] = {}
        if kind == "domain" and public:
            try:
                tls = transport.tls(cleaned, evidence)
            except ReconError as error:
                tls = {"note": str(error)}
        if public:
            try:
                http = transport.probe(cleaned, evidence)
            except ReconError as error:
                http = {"note": str(error)}
        data = {"host": cleaned, **detect_waf(cname_chain=dns["cname_chain"],
                                              headers=http.get("headers", []),
                                              cookies=http.get("cookies", []),
                                              asn=asn.get("asn", ""), issuer=tls.get("issuer", ""))}
    elif operation in {"asn", "geo", "reputation"}:
        if kind == "domain":
            dns = resolve(cleaned, transport, evidence)
            public = [a["ip"] for a in dns["addresses"] if a["public"]]
            if not public:
                raise ReconError(f"{cleaned} resolves to no public address.", code="not_public")
            ip = public[0]
        else:
            if not is_public_address(cleaned):
                raise ReconError(f"{cleaned} is not a public address.", code="not_public")
            ip = cleaned
        if operation == "asn":
            data = lookup_asn(ip, transport, evidence)
        elif operation == "geo":
            data = lookup_geo(ip, transport, evidence)
        else:
            data = lookup_reputation(ip, transport, evidence)
        data.setdefault("resolved_from", cleaned if kind == "domain" else "")
    else:
        raise ReconError(f"Unknown operation {operation!r}.", code="invalid_arguments")
    return {"status": "success", "operation": operation, "target": cleaned, "kind": kind,
            **data, "contacted": evidence.contacted, "recipe": evidence.recipe[:6],
            "notes": evidence.notes, "exit_code": 0}
