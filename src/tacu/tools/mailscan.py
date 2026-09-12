"""Email forensics that never executes, renders, browses or detonates anything.

An .eml is parsed for what it *says* — headers, the path it claims to have
taken, who authenticated for which identity, every indicator it carries, and
what each attachment actually is — and then scored in the open, with every
contribution listed.

Two boundaries are properties of the code, not promises:

  parse_message(raw)             has no transport and cannot reach the network
  enrich(iocs: strings, transport) receives only strings; no message, no bytes

The parser cannot make a request; the enricher cannot touch an attachment. That
is the honest form of "parser container, enrichment worker" for a tool with no
containers: separation by interface, and a test that holds it.

Nothing in the mail is ever contacted. URLs are analysed as text and defanged
in output; addresses from the mail get lookups *about* them from third parties,
never a packet *to* them. Attachments are hashed and typed in memory, archives
are inventoried from their central directory, and nothing is written to disk.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import io
import ipaddress
import re
import struct
import zipfile
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

from ..platform import run_argv, which
from .contracts import ToolContext, ToolFailure, ToolSpec, schema
from . import recon

OPERATIONS = ("analyze", "headers", "auth", "hops", "iocs", "attachments")

SPEC = ToolSpec(
    "email",
    "Static forensics of an .eml / RFC 822 message: headers, the Received chain normalised into "
    "hops with PTR/ASN/country, SPF/DKIM/DMARC/ARC results and whether they align with the "
    "displayed sender, DNS posture of the sender domain, every URL/domain/IP/address/hash it "
    "carries (defanged, never visited), attachments typed by magic bytes with archive inventory "
    "(never opened or run), passive reputation, and a risk score that lists its reasons. Use for "
    "'is this email phishing', 'analyse this eml', 'check the headers of this email', 'where did "
    "this email really come from'.",
    schema(properties={
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "path": {"type": "string"},
        "content": {"type": "string"},
        "enrich": {"type": "boolean"},
        "timeout": {"type": "integer"},
    }, required=("operation",)),
    schema(properties={"status": {"type": "string"}, "operation": {"type": "string"},
                       "contacted": {"type": "array"}}),
    timeout=180, risk_level="read", permissions=("workspace:read", "network:outbound"),
    when_to_use="A message file to judge: phishing, spoofing, a suspicious attachment, or "
                "working out which hop an email really entered at.",
    when_not="Sending, replying or reading a mailbox; this reads one saved message.",
)

MAX_MESSAGE_BYTES = 50_000_000
MAX_ATTACHMENT_HASH_BYTES = 25_000_000
MAX_ARCHIVE_ENTRIES = 200
MAX_IOCS = 200

# Scoring, as asked for. Read them, argue with them, tune them.
WEIGHTS: dict[str, int] = {
    "dmarc_fail": 30,
    "dkim_invalid": 20,
    "spf_fail": 15,
    "reply_to_mismatch": 15,
    "display_name_impersonation": 15,
    "lookalike_or_new_domain": 20,
    "malicious_url_reputation": 30,
    "bad_sender_ip_reputation": 25,
    "executable_attachment": 40,
    "extension_mime_mismatch": 25,
    "suspicious_archive": 20,
    # Not in the requested table, but too telling to leave unscored.
    "auth_for_other_identity": 20,     # SPF/DKIM passed, for someone else
    "link_text_lies": 15,              # anchor text names one host, href another
    "url_to_bare_ip": 10,
    "no_dmarc_record": 5,
}

# What a file *is*, from its first bytes. The declared type and the extension
# are claims; this is the fact they are checked against.
_MAGIC: tuple[tuple[bytes, str, str], ...] = (
    (b"MZ", "application/x-dosexec", "Windows executable (PE)"),
    (b"\x7fELF", "application/x-elf", "Linux executable (ELF)"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary", "macOS executable (Mach-O)"),
    (b"\xfe\xed\xfa\xcf", "application/x-mach-binary", "macOS executable (Mach-O)"),
    (b"\xca\xfe\xba\xbe", "application/x-mach-binary", "macOS universal binary"),
    (b"%PDF", "application/pdf", "PDF"),
    (b"PK\x03\x04", "application/zip", "ZIP container"),
    (b"Rar!\x1a\x07", "application/x-rar", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip archive"),
    (b"\x1f\x8b", "application/gzip", "gzip"),
    (b"BZh", "application/x-bzip2", "bzip2"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", "OLE compound document (legacy Office)"),
    (b"{\\rtf", "application/rtf", "RTF"),
    (b"\x89PNG", "image/png", "PNG image"),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG image"),
    (b"GIF8", "image/gif", "GIF image"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "application/x-ms-shortcut", "Windows shortcut (LNK)"),
    (b"#!", "text/x-script", "script with a shebang"),
    (b"<?xml", "text/xml", "XML"),
    (b"<html", "text/html", "HTML"),
    (b"<!DOCTYPE html", "text/html", "HTML"),
    (b"MSCF", "application/vnd.ms-cab-compressed", "Cabinet archive"),
    (b"\x00\x00\x00\x1cftyp", "video/mp4", "MP4"),
)
_EXECUTABLE_MAGIC = frozenset(("application/x-dosexec", "application/x-elf", "application/x-mach-binary",
                               "application/x-ms-shortcut", "text/x-script"))
_EXECUTABLE_EXTENSIONS = frozenset((
    "exe", "dll", "scr", "pif", "com", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "msi", "msp", "lnk", "jar", "app", "sh", "bash", "zsh", "command",
    "reg", "cpl", "inf", "iso", "img", "vhd", "vhdx", "apk", "deb", "rpm", "pkg", "dmg",
))
_MACRO_EXTENSIONS = frozenset(("docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"))
_ARCHIVE_MAGIC = frozenset(("application/zip", "application/x-rar", "application/x-7z-compressed",
                            "application/gzip", "application/x-bzip2", "application/vnd.ms-cab-compressed"))
# Extension → the magic families that are honest for it. Anything else is a mismatch.
_EXPECTED_FOR_EXTENSION: dict[str, tuple[str, ...]] = {
    "pdf": ("application/pdf",),
    "zip": ("application/zip",),
    "docx": ("application/zip",), "xlsx": ("application/zip",), "pptx": ("application/zip",),
    "docm": ("application/zip",), "xlsm": ("application/zip",), "pptm": ("application/zip",),
    "doc": ("application/x-ole-storage",), "xls": ("application/x-ole-storage",), "ppt": ("application/x-ole-storage",),
    "rtf": ("application/rtf",),
    "png": ("image/png",), "jpg": ("image/jpeg",), "jpeg": ("image/jpeg",), "gif": ("image/gif",),
    "exe": ("application/x-dosexec",), "dll": ("application/x-dosexec",), "scr": ("application/x-dosexec",),
    "rar": ("application/x-rar",), "7z": ("application/x-7z-compressed",), "gz": ("application/gzip",),
    "html": ("text/html",), "htm": ("text/html",), "xml": ("text/xml",),
}

_KNOWN_RELAYS: tuple[tuple[str, str], ...] = (
    (r"\.pphosted\.com$|\.proofpoint\.com$|proofpoint", "Proofpoint"),
    (r"\.outlook\.com$|\.office365\.com$|\.protection\.outlook\.com$|\.microsoft\.com$", "Microsoft 365"),
    (r"\.google\.com$|\.googlemail\.com$|mx\.google", "Google"),
    (r"\.mimecast\.com$|mimecast", "Mimecast"),
    (r"\.barracudanetworks\.com$|barracuda", "Barracuda"),
    (r"\.mailgun\.", "Mailgun"), (r"\.sendgrid\.net$", "SendGrid"), (r"\.amazonses\.com$", "Amazon SES"),
    (r"\.messagelabs\.com$", "Symantec"), (r"\.cisco\.com$|ironport", "Cisco"),
    (r"\.zoho\.", "Zoho"), (r"\.yahoo\.com$|\.yahoodns\.net$", "Yahoo"), (r"\.icloud\.com$", "iCloud"),
)

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'()\[\]{}]+|\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>\"']*")
_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b")
_HASH_RE = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
_ANCHOR_RE = re.compile(r"(?is)<a\b[^>]*?href\s*=\s*[\"']?([^\"'\s>]+)[^>]*>(.*?)</a\s*>")
_TAG_RE = re.compile(r"(?s)<(?:script|style)\b.*?</(?:script|style)\s*>|<[^>]+>")
_SHORTENERS = frozenset(("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
                         "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "lnkd.in", "t.ly"))
_SUSPICIOUS_TLDS = frozenset(("zip", "mov", "top", "xyz", "click", "link", "gq", "cf", "ml", "tk",
                              "work", "rest", "icu", "cam", "buzz", "monster", "quest", "cyou"))
_FREEMAIL = frozenset(("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com",
                       "icloud.com", "proton.me", "protonmail.com", "mail.com", "gmx.com", "yandex.com"))


class MailError(ToolFailure):
    pass


# ---------------------------------------------------------------------------
# 1. Safe parser — no transport, no network, no disk. Bytes in, facts out.
# ---------------------------------------------------------------------------


def parse_message(raw: bytes) -> dict[str, Any]:
    """Everything the message says about itself, and nothing it can do."""

    if len(raw) > MAX_MESSAGE_BYTES:
        raise MailError(f"Message is {len(raw):,} bytes; the limit is {MAX_MESSAGE_BYTES:,}.", code="too_large")
    try:
        message = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as error:  # a hostile message must fail loudly, not silently
        raise MailError(f"Could not parse the message: {error}", code="unparseable") from error

    headers = analyze_headers(message)
    auth = validate_auth(message, headers)
    bodies = _extract_bodies(message)
    attachments = inspect_attachments(message)
    iocs = extract_iocs(message, bodies, headers, attachments)
    return {"headers": headers, "auth": auth, "bodies": bodies,
            "attachments": attachments, "iocs": iocs,
            "structure": _mime_structure(message), "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def _mime_structure(message: EmailMessage) -> list[str]:
    out = []
    for part in message.walk():
        disposition = part.get_content_disposition() or ""
        name = part.get_filename() or ""
        out.append(part.get_content_type() + (f" [{disposition}]" if disposition else "")
                   + (f" {name}" if name else ""))
    return out[:60]


def _extract_bodies(message: EmailMessage) -> dict[str, Any]:
    """Text of the message. HTML is stripped to text, never rendered."""

    plain: list[str] = []
    html_text: list[str] = []
    anchors: list[dict[str, str]] = []
    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            continue
        kind = part.get_content_type()
        if kind not in {"text/plain", "text/html"}:
            continue
        try:
            text = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if not isinstance(text, str):
            continue
        if kind == "text/plain":
            plain.append(text)
        else:
            for href, inner in _ANCHOR_RE.findall(text):
                shown = _html_to_text(inner).strip()
                anchors.append({"href": href.strip(), "text": shown[:200]})
            html_text.append(_html_to_text(text))
    return {"plain": "\n".join(plain)[:200_000], "html_as_text": "\n".join(html_text)[:200_000],
            "anchors": anchors[:MAX_IOCS], "has_html": bool(html_text)}


def _html_to_text(html: str) -> str:
    import html as html_module

    return re.sub(r"[ \t]+", " ", html_module.unescape(_TAG_RE.sub(" ", html)))


# ---------------------------------------------------------------------------
# 2. Headers and the Received chain
# ---------------------------------------------------------------------------


def _address(value: Any) -> dict[str, str]:
    if value is None:
        return {"display": "", "address": "", "domain": ""}
    try:
        first = value.addresses[0] if getattr(value, "addresses", None) else None
    except Exception:
        first = None
    if first is not None:
        addr = first.addr_spec or ""
        return {"display": first.display_name or "", "address": addr,
                "domain": addr.rsplit("@", 1)[-1].casefold() if "@" in addr else ""}
    name, addr = email.utils.parseaddr(str(value))
    return {"display": name, "address": addr,
            "domain": addr.rsplit("@", 1)[-1].casefold() if "@" in addr else ""}


def analyze_headers(message: EmailMessage) -> dict[str, Any]:
    sender = _address(message.get("From"))
    reply_to = _address(message.get("Reply-To"))
    return_path = _address(message.get("Return-Path"))
    envelope_sender = _address(message.get("Sender"))
    message_id = str(message.get("Message-ID") or "").strip()
    message_id_domain = message_id.rsplit("@", 1)[-1].strip("<> ").casefold() if "@" in message_id else ""

    date_raw = str(message.get("Date") or "")
    parsed_date = None
    try:
        parsed_date = email.utils.parsedate_to_datetime(date_raw) if date_raw else None
    except Exception:
        parsed_date = None

    hops = parse_received(message.get_all("Received") or [])
    anomalies: list[str] = []
    if reply_to["domain"] and sender["domain"] and reply_to["domain"] != sender["domain"]:
        anomalies.append(f"Reply-To domain {reply_to['domain']} differs from From domain {sender['domain']}")
    if return_path["domain"] and sender["domain"] and return_path["domain"] != sender["domain"]:
        anomalies.append(f"Return-Path domain {return_path['domain']} differs from From domain {sender['domain']}")
    if message_id_domain and sender["domain"] and message_id_domain != sender["domain"] \
            and not message_id_domain.endswith("." + sender["domain"]):
        anomalies.append(f"Message-ID domain {message_id_domain} differs from From domain {sender['domain']}")
    impersonation = _display_name_impersonation(sender)
    if impersonation:
        anomalies.append(impersonation)
    if parsed_date is not None:
        if parsed_date.tzinfo is None:
            anomalies.append("Date header carries no timezone")
        first_hop_date = next((h["date"] for h in hops if h.get("date")), None)
        if first_hop_date:
            try:
                received_at = email.utils.parsedate_to_datetime(first_hop_date)
                delta = abs((received_at - parsed_date).total_seconds())
                if delta > 6 * 3600:
                    anomalies.append(f"Date header is {delta / 3600:.0f}h away from the first Received timestamp")
            except Exception:
                pass
        if parsed_date > datetime.now(timezone.utc).astimezone(parsed_date.tzinfo) if parsed_date.tzinfo else False:
            anomalies.append("Date header is in the future")
    elif date_raw:
        anomalies.append("Date header could not be parsed")

    security = {}
    for key, value in message.items():
        lowered = key.casefold()
        if lowered.startswith(("x-", "arc-")) or lowered in {"list-unsubscribe", "precedence", "auto-submitted"}:
            security.setdefault(key, str(value)[:300])
    originating_ip = ""
    for key in ("X-Originating-IP", "X-Sender-IP", "X-Original-Sender-IP"):
        value = str(message.get(key) or "").strip("[] ")
        if value:
            originating_ip = value
            break

    return {
        "from": sender, "reply_to": reply_to, "return_path": return_path, "sender": envelope_sender,
        "to": str(message.get("To") or "")[:300], "subject": str(message.get("Subject") or "")[:300],
        "message_id": message_id, "message_id_domain": message_id_domain,
        "date": date_raw, "date_utc": parsed_date.astimezone(timezone.utc).isoformat() if parsed_date and parsed_date.tzinfo else "",
        "hops": hops, "x_headers": security, "originating_ip": originating_ip,
        "user_agent": str(message.get("X-Mailer") or message.get("User-Agent") or "")[:120],
        "anomalies": anomalies,
    }


def _display_name_impersonation(sender: dict[str, str]) -> str:
    """A display name that carries a different address or a well-known brand."""

    display = sender.get("display") or ""
    domain = sender.get("domain") or ""
    embedded = _EMAIL_RE.search(display)
    if embedded:
        shown = embedded.group(0).rsplit("@", 1)[-1].casefold()
        if shown != domain:
            return f"display name shows {embedded.group(0)} but the address is at {domain}"
    tokens = [t for t in re.split(r"[^a-z0-9]+", display.casefold()) if len(t) > 3]
    registrable = _registrable(domain)
    for token in tokens:
        if token in {"support", "service", "billing", "invoice", "security", "admin", "team", "helpdesk"}:
            continue
        if domain and token not in registrable and any(token == _registrable(brand).split(".")[0]
                                                        for brand in _BRANDS):
            return f"display name names '{token}' but the address is at {domain}"
    return ""


_BRANDS = ("microsoft.com", "apple.com", "google.com", "amazon.com", "paypal.com", "netflix.com",
           "dhl.com", "fedex.com", "ups.com", "docusign.com", "dropbox.com", "adobe.com", "chase.com",
           "wellsfargo.com", "bankofamerica.com", "hsbc.com", "linkedin.com", "facebook.com",
           "instagram.com", "whatsapp.com", "office.com", "outlook.com", "icloud.com")


def _registrable(domain: str) -> str:
    parts = domain.casefold().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


_RECEIVED_FROM = re.compile(r"(?is)^\s*from\s+(\S+)(?:\s*\(([^)]*)\))?")
_RECEIVED_BY = re.compile(r"(?is)\bby\s+(\S+)")
_RECEIVED_WITH = re.compile(r"(?is)\bwith\s+(\S+)")
_RECEIVED_ID = re.compile(r"(?is)\bid\s+(\S+)")
_RECEIVED_FOR = re.compile(r"(?is)\bfor\s+<?([^\s>;]+)>?")


def parse_received(values: list[Any]) -> list[dict[str, Any]]:
    """Received headers, oldest first, as hops: from, by, the IP, the date."""

    hops: list[dict[str, Any]] = []
    # Headers are prepended as mail travels, so the last one is the first hop.
    for raw in reversed(values):
        text = " ".join(str(raw).split())
        body, _, date = text.rpartition(";")
        if not body:
            body, date = text, ""
        hop: dict[str, Any] = {"raw": text[:400], "from": "", "from_comment": "", "by": "",
                               "with": "", "id": "", "for": "", "date": date.strip(), "ip": ""}
        m = _RECEIVED_FROM.match(body)
        if m:
            hop["from"] = m.group(1).strip("[]()").rstrip(".")
            hop["from_comment"] = (m.group(2) or "").strip()
        for key, pattern in (("by", _RECEIVED_BY), ("with", _RECEIVED_WITH), ("id", _RECEIVED_ID), ("for", _RECEIVED_FOR)):
            found = pattern.search(body)
            if found:
                hop[key] = found.group(1).strip("[]()").rstrip(".")
        ips = _IPV4_RE.findall(hop["from_comment"]) or _IPV4_RE.findall(body[:200])
        public = [ip for ip in ips if recon.is_public_address(ip)]
        hop["ip"] = (public or ips or [""])[0]
        hop["ip_public"] = bool(public)
        # A row describes where the mail came *from* at that step. The receiver
        # is the next row's source — except for the last one, which nobody
        # handed on and so gets a row of its own: the mailbox side.
        hop["relay"] = _known_relay(hop["from"])
        hops.append(hop)
    if hops and hops[-1]["by"] and hops[-1]["by"].casefold() != hops[-1]["from"].casefold():
        final = hops[-1]["by"]
        hops.append({"raw": "", "from": final, "from_comment": "", "by": "", "with": "", "id": "",
                     "for": hops[-1]["for"], "date": hops[-1]["date"], "ip": "", "ip_public": False,
                     "relay": _known_relay(final), "final": True})
    for index, hop in enumerate(hops, 1):
        hop["hop"] = index
    return hops


def _known_relay(host: str) -> str:
    lowered = (host or "").casefold()
    for pattern, name in _KNOWN_RELAYS:
        if re.search(pattern, lowered):
            return name
    return ""


# ---------------------------------------------------------------------------
# 3. Authentication and alignment
# ---------------------------------------------------------------------------


def validate_auth(message: EmailMessage, headers: dict[str, Any]) -> dict[str, Any]:
    """SPF, DKIM, DMARC and ARC as the receiving side recorded them — and *for whom*.

    The result that matters is not "dkim=pass" but "dkim=pass for attacker.example
    while the From says company.com". Alignment is the finding; a pass for
    someone else's identity is how most spoofs read.
    """

    from_domain = headers["from"]["domain"]
    results = {"spf": [], "dkim": [], "dmarc": [], "arc": []}
    for raw in (message.get_all("Authentication-Results") or []) + (message.get_all("ARC-Authentication-Results") or []):
        text = " ".join(str(raw).split())
        for method in ("spf", "dkim", "dmarc", "arc"):
            for m in re.finditer(rf"(?i)\b{method}=(\w+)((?:\s+(?:\([^)]*\))?\s*[\w.]+=[^;\s]+)*)", text):
                verdict = m.group(1).casefold()
                props = dict(re.findall(r"([\w.]+)=([^;\s]+)", m.group(2) or ""))
                results[method].append({"result": verdict, **{k: v.strip("\"'") for k, v in props.items()}})
    signatures = []
    for raw in message.get_all("DKIM-Signature") or []:
        tags = dict(re.findall(r"(\w+)=([^;]*)", " ".join(str(raw).split())))
        signatures.append({"d": tags.get("d", "").strip().casefold(), "s": tags.get("s", "").strip(),
                           "a": tags.get("a", "").strip()})

    def verdict(method: str) -> str:
        found = results[method]
        if not found:
            return "none"
        if any(r["result"] == "fail" for r in found):
            return "fail"
        if all(r["result"] == "pass" for r in found):
            return "pass"
        return found[0]["result"]

    spf_domain = next((r.get("smtp.mailfrom", r.get("smtp.helo", "")).rsplit("@", 1)[-1].casefold()
                       for r in results["spf"] if r.get("smtp.mailfrom") or r.get("smtp.helo")), "")
    dkim_domains = [r.get("header.d", "").casefold() for r in results["dkim"] if r.get("header.d")] \
        or [s["d"] for s in signatures if s["d"]]
    dmarc_domain = next((r.get("header.from", "").casefold() for r in results["dmarc"] if r.get("header.from")), "")

    def aligned(candidate: str) -> bool:
        return bool(candidate and from_domain and (candidate == from_domain
                    or _registrable(candidate) == _registrable(from_domain)))

    alignment = {
        "spf_aligned": aligned(spf_domain) if spf_domain else None,
        "dkim_aligned": any(aligned(d) for d in dkim_domains) if dkim_domains else None,
    }
    notes: list[str] = []
    if verdict("spf") == "pass" and spf_domain and alignment["spf_aligned"] is False:
        notes.append(f"SPF passed for {spf_domain}, not for the displayed {from_domain}")
    if verdict("dkim") == "pass" and dkim_domains and alignment["dkim_aligned"] is False:
        notes.append(f"DKIM passed for {', '.join(sorted(set(dkim_domains)))}, not for the displayed {from_domain}")
    if verdict("dmarc") == "none" and not results["dmarc"]:
        notes.append("no DMARC result was recorded by the receiver")
    return {
        "spf": verdict("spf"), "dkim": verdict("dkim"), "dmarc": verdict("dmarc"), "arc": verdict("arc"),
        "spf_domain": spf_domain, "dkim_domains": sorted(set(dkim_domains)), "dmarc_domain": dmarc_domain,
        "signatures": signatures, "alignment": alignment, "notes": notes, "raw": results,
    }


# ---------------------------------------------------------------------------
# 5. IOC extraction — text in, strings out, defanged for display
# ---------------------------------------------------------------------------


def defang(value: str) -> str:
    return (value.replace("http://", "hxxp://").replace("https://", "hxxps://")
            .replace("ftp://", "fxp://").replace(".", "[.]"))


def extract_iocs(message: EmailMessage, bodies: dict[str, Any], headers: dict[str, Any],
                 attachments: list[dict[str, Any]]) -> dict[str, Any]:
    text = "\n".join((bodies.get("plain", ""), bodies.get("html_as_text", ""),
                      " ".join(a["href"] for a in bodies.get("anchors", []))))
    urls: list[str] = []
    for m in _URL_RE.finditer(text):
        value = m.group(0).rstrip(".,;:!?)")
        if value not in urls:
            urls.append(value)
    for anchor in bodies.get("anchors", []):
        href = anchor["href"]
        if href and href.casefold().startswith(("http", "ftp", "www")) and href not in urls:
            urls.append(href)
    addresses = sorted({m.group(0).casefold() for m in _EMAIL_RE.finditer(text)})
    ips = sorted({ip for ip in _IPV4_RE.findall(text) if recon.is_public_address(ip)})
    domains: set[str] = set()
    for url in urls:
        host = _url_host(url)
        if host and not _IPV4_RE.fullmatch(host):
            domains.add(host)
    for address in addresses:
        domains.add(address.rsplit("@", 1)[-1])
    for m in _DOMAIN_RE.finditer(text):
        candidate = m.group(0).casefold()
        if "." in candidate and not candidate.endswith((".png", ".jpg", ".gif", ".pdf", ".zip", ".exe", ".doc", ".docx", ".xls", ".xlsx")):
            domains.add(candidate)
    hashes = sorted({m.group(0).casefold() for m in _HASH_RE.finditer(text)})
    from_domain = headers["from"]["domain"]
    return {
        "urls": [analyze_url(url, from_domain) for url in urls[:MAX_IOCS]],
        "domains": sorted(domains)[:MAX_IOCS],
        "ips": ips[:MAX_IOCS],
        "addresses": addresses[:MAX_IOCS],
        "hashes_in_text": hashes[:50],
        "attachment_hashes": [a["sha256"] for a in attachments if a.get("sha256")],
        "anchors": _anchor_findings(bodies.get("anchors", [])),
    }


def _url_host(url: str) -> str:
    import urllib.parse

    candidate = url if "://" in url else "http://" + url
    try:
        return (urllib.parse.urlsplit(candidate).hostname or "").casefold().rstrip(".")
    except ValueError:
        return ""


def analyze_url(url: str, from_domain: str) -> dict[str, Any]:
    """What a URL looks like, without ever fetching it."""

    import urllib.parse

    candidate = url if "://" in url else "http://" + url
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return {"url": defang(url), "flags": ["unparseable"]}
    host = (parsed.hostname or "").casefold().rstrip(".")
    flags: list[str] = []
    if _IPV4_RE.fullmatch(host):
        flags.append("host is a bare IP address")
    if parsed.username or parsed.password:
        flags.append("credentials embedded before the host")
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("punycode host (internationalised characters)")
    if host in _SHORTENERS:
        flags.append("link shortener hides the destination")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in _SUSPICIOUS_TLDS:
        flags.append(f".{tld} is a TLD heavily used for abuse")
    if len(url) > 160:
        flags.append("unusually long")
    if re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}", url, re.I):
        flags.append("heavy percent-encoding")
    if "@" in parsed.netloc:
        flags.append("'@' in the authority: the real host is after it")
    if parsed.scheme == "http":
        flags.append("plain http")
    if from_domain and host and host != from_domain and not host.endswith("." + from_domain):
        look = lookalike(host, from_domain)
        if look:
            flags.append(look)
    if host and not _IPV4_RE.fullmatch(host):
        # micros0ft-billing.xyz resembles nothing about the sender; it resembles
        # Microsoft, and that is who the mail is dressed as.
        for brand in _BRANDS:
            if _registrable(host) == brand:
                break
            look = lookalike(host, brand)
            if look:
                flags.append(f"resembles {brand}: {look}")
                break
    return {"url": defang(url), "host": defang(host) if host else "", "scheme": parsed.scheme,
            "path": parsed.path[:120], "flags": flags}


def lookalike(candidate: str, reference: str) -> str:
    """Is this domain trying to look like that one? Homoglyphs, edits, extra labels."""

    if not candidate or not reference:
        return ""
    label = _registrable(candidate).split(".")[0]
    b = _registrable(reference).split(".")[0]
    if not label or not b or label == b:
        return ""
    if b in candidate.split(".") and _registrable(candidate) != _registrable(reference):
        return f"contains '{b}' as a label but is not {reference}"
    # microsoft-login, paypal-secure, micros0ft-billing: the brand is one
    # hyphenated token of the label, so judge each token as well as the whole.
    for token in dict.fromkeys([label, *label.split("-")]):
        if not token or len(token) < 4:
            continue
        if token == b and token != label:
            return f"'{label}' carries '{b}' as part of its name but is not {reference}"
        folded = token.translate(str.maketrans("0l1|5$", "oii1ss"))
        if folded == b and token != b:
            return f"'{token}' resembles '{b}' with substituted characters"
        if len(b) >= 5 and _edit_distance(token, b) <= 2 and token != b:
            return f"'{token}' is within two edits of '{b}'"
    return ""


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _anchor_findings(anchors: list[dict[str, str]]) -> list[dict[str, str]]:
    """Links whose visible text names a different host than their target."""

    out = []
    for anchor in anchors:
        shown = anchor.get("text", "")
        href_host = _url_host(anchor.get("href", ""))
        shown_host = _url_host(shown) if re.search(r"https?://|www\.|\.[a-z]{2,}", shown, re.I) else ""
        if href_host and shown_host and _registrable(href_host) != _registrable(shown_host):
            out.append({"text": defang(shown[:100]), "href": defang(anchor["href"][:200]),
                        "finding": f"text says {defang(shown_host)}, link goes to {defang(href_host)}"})
    return out[:40]


# ---------------------------------------------------------------------------
# 7. Attachments — typed in memory, never written, never opened
# ---------------------------------------------------------------------------


def magic_type(data: bytes) -> tuple[str, str]:
    head = data[:16]
    for signature, mime, label in _MAGIC:
        if head.startswith(signature):
            return mime, label
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return "application/x-ole-storage", "OLE compound document"
    sample = data[:512]
    if sample and all(32 <= b < 127 or b in (9, 10, 13) for b in sample):
        return "text/plain", "plain text"
    return "application/octet-stream", "unrecognised binary"


def inspect_attachments(message: EmailMessage) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for part in message.walk():
        disposition = part.get_content_disposition()
        filename = part.get_filename() or ""
        if disposition != "attachment" and not (disposition == "inline" and filename) and not filename:
            continue
        if part.get_content_maintype() == "multipart":
            continue
        payload = part.get_payload(decode=True) or b""
        declared = part.get_content_type()
        extension = filename.rsplit(".", 1)[-1].casefold() if "." in filename else ""
        # A second extension hiding before a harmless-looking one: invoice.pdf.exe
        inner_extension = filename.rsplit(".", 2)[-2].casefold() if filename.count(".") >= 2 else ""
        actual_mime, actual_label = magic_type(payload)
        entry: dict[str, Any] = {
            "filename": filename, "declared_type": declared, "actual_type": actual_mime,
            "actual_label": actual_label, "size": len(payload), "extension": extension,
            "sha256": hashlib.sha256(payload).hexdigest() if len(payload) <= MAX_ATTACHMENT_HASH_BYTES else "",
            "md5": hashlib.md5(payload).hexdigest() if len(payload) <= MAX_ATTACHMENT_HASH_BYTES else "",
            "flags": [],
        }
        if len(payload) > MAX_ATTACHMENT_HASH_BYTES:
            entry["flags"].append(f"larger than {MAX_ATTACHMENT_HASH_BYTES:,} bytes; not hashed")
        expected = _EXPECTED_FOR_EXTENSION.get(extension)
        if expected and actual_mime not in expected and actual_mime != "application/octet-stream":
            entry["flags"].append(f"extension .{extension} but content is {actual_label}")
            entry["mismatch"] = True
        if declared and actual_mime != "application/octet-stream" and declared != actual_mime \
                and not (declared.startswith("application/vnd.openxmlformats") and actual_mime == "application/zip") \
                and not (declared in {"application/msword", "application/vnd.ms-excel"} and actual_mime == "application/x-ole-storage") \
                and not (declared == "text/plain" and actual_mime == "text/x-script"):
            entry["flags"].append(f"declared {declared} but content is {actual_label}")
            entry["mismatch"] = True
        if actual_mime in _EXECUTABLE_MAGIC or extension in _EXECUTABLE_EXTENSIONS:
            entry["executable"] = True
            entry["flags"].append("executable content or extension")
        if inner_extension in _EXECUTABLE_EXTENSIONS or (inner_extension and extension in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"} and inner_extension in _EXECUTABLE_EXTENSIONS):
            entry["flags"].append(f"double extension: .{inner_extension}.{extension}")
            entry["executable"] = True
        if extension in _MACRO_EXTENSIONS:
            entry["flags"].append("macro-enabled Office format")
            entry["macro"] = True
        if actual_mime == "application/zip":
            entry["archive"] = inventory_zip(payload)
            names = [item["name"] for item in entry["archive"].get("entries", [])]
            if any(n.casefold().endswith("vbaproject.bin") for n in names):
                entry["flags"].append("contains a VBA macro project")
                entry["macro"] = True
            if entry["archive"].get("encrypted"):
                entry["flags"].append("password-protected archive: contents cannot be inspected")
                entry["suspicious_archive"] = True
            if any(_is_executable_name(n) for n in names):
                entry["flags"].append("archive contains an executable")
                entry["suspicious_archive"] = True
                entry["executable"] = True
            if entry["archive"].get("bomb_ratio", 0) > 100:
                entry["flags"].append(f"compression ratio {entry['archive']['bomb_ratio']:.0f}:1 — decompression bomb shape")
                entry["suspicious_archive"] = True
            if any(n.casefold().endswith((".lnk", ".iso", ".img", ".vhd")) for n in names):
                entry["flags"].append("archive contains a shortcut or disk image")
                entry["suspicious_archive"] = True
        elif actual_mime in _ARCHIVE_MAGIC:
            entry["archive"] = {"format": actual_label, "entries": [], "note": "inventory needs zip; other formats are typed only"}
            if extension in {"rar", "7z", "iso", "img"}:
                entry["suspicious_archive"] = True
                entry["flags"].append(f"{actual_label} attachments are a common delivery wrapper")
        if actual_mime == "text/html" or extension in {"html", "htm", "shtml"}:
            entry["flags"].append("HTML attachment: often a credential-harvesting page")
            entry["html"] = True
        out.append(entry)
    return out


def _is_executable_name(name: str) -> bool:
    ext = name.rsplit(".", 1)[-1].casefold() if "." in name else ""
    return ext in _EXECUTABLE_EXTENSIONS


def inventory_zip(data: bytes) -> dict[str, Any]:
    """The central directory only. Nothing is extracted, nothing is decompressed."""

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = []
            total_uncompressed = 0
            encrypted = False
            for info in archive.infolist()[:MAX_ARCHIVE_ENTRIES]:
                total_uncompressed += info.file_size
                if info.flag_bits & 0x1:
                    encrypted = True
                entries.append({"name": info.filename[:200], "size": info.file_size,
                                "compressed": info.compress_size, "encrypted": bool(info.flag_bits & 0x1)})
            ratio = (total_uncompressed / max(1, len(data)))
            return {"format": "zip", "entries": entries, "count": len(archive.infolist()),
                    "encrypted": encrypted, "uncompressed_total": total_uncompressed,
                    "bomb_ratio": round(ratio, 1)}
    except (zipfile.BadZipFile, RuntimeError, ValueError, struct.error) as error:
        return {"format": "zip", "entries": [], "note": f"could not read the directory: {error}"}


# ---------------------------------------------------------------------------
# 4 + 6. Enrichment — strings in, facts out. No message, no bytes in scope.
# ---------------------------------------------------------------------------


def enrich(iocs: dict[str, Any], *, sender_domain: str, hop_ips: list[str],
           dkim: list[dict[str, str]], transport: recon.Transport, evidence: recon.Evidence,
           keys: dict[str, str] | None = None) -> dict[str, Any]:
    """Passive lookups *about* what the mail names. Nothing it names is contacted.

    The signature is the boundary: this receives domain and address strings and
    hashes. It has no access to the parsed message or to any attachment bytes,
    and a test holds that.
    """

    keys = keys if keys is not None else recon.reputation_keys()
    out: dict[str, Any] = {"sender_dns": {}, "hops": [], "urls": {}, "hashes": {}, "domain_age": {}}

    if sender_domain:
        dns: dict[str, Any] = {"domain": sender_domain}
        dns["mx"] = transport.dns(sender_domain, "MX", evidence)
        txt = transport.dns(sender_domain, "TXT", evidence)
        dns["spf_record"] = next((t.strip('"') for t in txt if "v=spf1" in t), "")
        dmarc = transport.dns(f"_dmarc.{sender_domain}", "TXT", evidence)
        dns["dmarc_record"] = next((t.strip('"') for t in dmarc if "v=DMARC1" in t), "")
        policy = re.search(r"\bp=(\w+)", dns["dmarc_record"] or "")
        dns["dmarc_policy"] = policy.group(1) if policy else ""
        dns["dkim_selectors"] = {}
        for sig in dkim[:3]:
            if sig.get("d") and sig.get("s"):
                found = transport.dns(f"{sig['s']}._domainkey.{sig['d']}", "TXT", evidence)
                dns["dkim_selectors"][f"{sig['s']}._domainkey.{sig['d']}"] = "published" if found else "not found"
        out["sender_dns"] = dns
        out["domain_age"] = domain_age(sender_domain, evidence)

    seen_ip: dict[str, dict[str, Any]] = {}
    for ip in hop_ips[:6]:
        if ip in seen_ip:
            continue
        row: dict[str, Any] = {"ip": ip}
        row["ptr"] = transport.dns(ipaddress.ip_address(ip).reverse_pointer, "PTR", evidence)
        try:
            row["asn"] = recon.lookup_asn(ip, transport, evidence)
        except recon.ReconError as error:
            row["asn"] = {"note": str(error)}
        row["reputation"] = recon.lookup_reputation(ip, transport, evidence, keys)
        seen_ip[ip] = row
    out["hops"] = list(seen_ip.values())

    if keys.get("virustotal"):
        for host in [u for u in iocs.get("domains", []) if not _IPV4_RE.fullmatch(u)][:8]:
            try:
                data = transport.get_json(
                    f"https://www.virustotal.com/api/v3/domains/{host}", evidence, service="VirusTotal",
                    headers={"x-apikey": keys["virustotal"], "Accept": "application/json"})
                stats = (((data or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
                out["urls"][defang(host)] = {"malicious": int(stats.get("malicious") or 0),
                                             "suspicious": int(stats.get("suspicious") or 0),
                                             "harmless": int(stats.get("harmless") or 0)}
            except recon.ReconError as error:
                out["urls"][defang(host)] = {"note": str(error)}
        for digest in iocs.get("attachment_hashes", [])[:8]:
            try:
                data = transport.get_json(
                    f"https://www.virustotal.com/api/v3/files/{digest}", evidence, service="VirusTotal",
                    headers={"x-apikey": keys["virustotal"], "Accept": "application/json"})
                stats = (((data or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
                out["hashes"][digest] = {"malicious": int(stats.get("malicious") or 0),
                                         "suspicious": int(stats.get("suspicious") or 0),
                                         "known": True}
            except recon.ReconError as error:
                out["hashes"][digest] = {"known": False, "note": str(error)}
    else:
        out["not_checked"] = ["VirusTotal (domains, attachment hashes): no key (ti config keys)"]
    return out


_CREATED_RE = re.compile(r"(?im)^\s*(?:creation date|created|registered on|registration date|domain registration date)\s*:\s*(\S+)")


def domain_age(domain: str, evidence: recon.Evidence) -> dict[str, Any]:
    """Registration date from whois, when the binary and the registry answer."""

    binary = which("whois")
    registrable = _registrable(domain)
    if not binary:
        return {"domain": registrable, "note": "whois is not installed"}
    argv = [binary, registrable]
    raw = run_argv(argv, timeout=15)
    evidence.ran(argv)
    evidence.contact("whois")
    text = raw.get("stdout") or ""
    if re.search(r"(?i)\b(?:not found|no match|does not exist|no data found|no entries found|not registered)\b", text):
        return {"domain": registrable, "registered": False,
                "note": "the registry reports no such domain"}
    # A date is only the domain's own if the answer names the domain. The TLD's
    # IANA stub carries "created: 1991-12-24" and is returned for any lookup,
    # which made a domain that does not exist look thirty years old.
    own = re.search(rf"(?im)^\s*domain(?: name)?:\s*{re.escape(registrable)}\s*$", text)
    if not own:
        return {"domain": registrable, "note": "whois answered, but not with this domain's record"}
    # And only a date that comes *after* that line: the TLD stub precedes the
    # referral, and its "created:" is the first match in the whole answer.
    m = _CREATED_RE.search(text, own.start())
    if not m:
        return {"domain": registrable, "registered": True, "note": "no creation date in the whois answer"}
    created = m.group(1).strip()
    days = recon._days_since(created[:10]) if created[:4].isdigit() else None
    return {"domain": registrable, "registered": True, "created": created, "age_days": days}


# ---------------------------------------------------------------------------
# 8. Correlation and score
# ---------------------------------------------------------------------------


def score(parsed: dict[str, Any], enrichment: dict[str, Any] | None) -> dict[str, Any]:
    headers, auth, iocs = parsed["headers"], parsed["auth"], parsed["iocs"]
    attachments = parsed["attachments"]
    enrichment = enrichment or {}
    reasons: list[dict[str, Any]] = []

    def add(key: str, why: str) -> None:
        reasons.append({"factor": key, "weight": WEIGHTS[key], "why": why})

    if auth["dmarc"] == "fail":
        add("dmarc_fail", f"DMARC failed for {auth.get('dmarc_domain') or headers['from']['domain']}")
    if auth["dkim"] in {"fail", "permerror", "temperror", "neutral", "policy"}:
        add("dkim_invalid", f"DKIM result was {auth['dkim']}")
    if auth["spf"] in {"fail", "softfail", "permerror"}:
        add("spf_fail", f"SPF result was {auth['spf']}" + (f" for {auth['spf_domain']}" if auth.get("spf_domain") else ""))
    if auth.get("notes") and any("not for the displayed" in n for n in auth["notes"]):
        add("auth_for_other_identity", next(n for n in auth["notes"] if "not for the displayed" in n))
    for anomaly in headers.get("anomalies", []):
        if anomaly.startswith("Reply-To domain"):
            add("reply_to_mismatch", anomaly)
        elif anomaly.startswith("display name"):
            add("display_name_impersonation", anomaly)
    sender_domain = headers["from"]["domain"]
    age = enrichment.get("domain_age") or {}
    if age.get("registered") is False:
        add("lookalike_or_new_domain", f"the From domain {age['domain']} is not registered at all")
    elif age.get("age_days") is not None and age["age_days"] < 90:
        add("lookalike_or_new_domain", f"{age['domain']} was registered {age['age_days']} days ago")
    else:
        for brand in _BRANDS:
            look = lookalike(sender_domain, brand)
            if look and _registrable(sender_domain) != brand:
                add("lookalike_or_new_domain", f"sender domain {sender_domain}: {look}")
                break
    url_reps = enrichment.get("urls") or {}
    bad_urls = [h for h, r in url_reps.items() if isinstance(r, dict) and r.get("malicious", 0) > 0]
    if bad_urls:
        add("malicious_url_reputation", f"VirusTotal flags {', '.join(bad_urls[:3])}")
    for hop in enrichment.get("hops") or []:
        rep = hop.get("reputation") or {}
        ab = rep.get("abuseipdb") or {}
        vt = rep.get("virustotal") or {}
        if ab.get("confidence", 0) > 50 or vt.get("malicious", 0) > 0:
            add("bad_sender_ip_reputation",
                f"{hop['ip']}: " + (f"AbuseIPDB {ab['confidence']}%" if ab else "") + (f" VirusTotal {vt['malicious']} malicious" if vt.get("malicious") else ""))
            break
    if any(a.get("executable") for a in attachments):
        names = [a["filename"] for a in attachments if a.get("executable")]
        add("executable_attachment", f"executable attachment: {', '.join(names[:3])}")
    if any(a.get("mismatch") for a in attachments):
        names = [f"{a['filename']} is {a['actual_label']}" for a in attachments if a.get("mismatch")]
        add("extension_mime_mismatch", "; ".join(names[:3]))
    if any(a.get("suspicious_archive") for a in attachments):
        names = [a["filename"] for a in attachments if a.get("suspicious_archive")]
        add("suspicious_archive", f"suspicious archive: {', '.join(names[:3])}")
    hash_reps = enrichment.get("hashes") or {}
    if any(isinstance(r, dict) and r.get("malicious", 0) > 0 for r in hash_reps.values()) and not any(r["factor"] == "executable_attachment" for r in reasons):
        add("executable_attachment", "VirusTotal flags an attachment hash as malicious")
    if iocs.get("anchors"):
        add("link_text_lies", iocs["anchors"][0]["finding"])
    if any("host is a bare IP address" in u.get("flags", []) for u in iocs.get("urls", [])):
        add("url_to_bare_ip", "a link points at a bare IP address")
    sender_dns = enrichment.get("sender_dns") or {}
    if sender_dns and sender_domain and not sender_dns.get("dmarc_record"):
        add("no_dmarc_record", f"{sender_domain} publishes no DMARC record")

    total = min(100, sum(r["weight"] for r in reasons))
    level = "HIGH" if total >= 60 else "MEDIUM" if total >= 30 else "LOW" if total > 0 else "NONE OBSERVED"
    not_checked = list(enrichment.get("not_checked") or [])
    for hop in enrichment.get("hops") or []:
        for note in (hop.get("reputation") or {}).get("not_checked") or []:
            if note not in not_checked:
                not_checked.append(note)
    return {"score": total, "level": level, "reasons": reasons, "not_checked": not_checked,
            "enriched": bool(enrichment)}


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------


def execute(context: ToolContext, *, operation: str, path: str | None = None,
            content: str | None = None, enrich: bool | None = None,
            timeout: int = 15) -> dict[str, Any]:
    if enrich is None:
        enrich = operation in {"analyze", "hops"}
    if content:
        raw = content.encode("utf-8", errors="replace")
        source = "content"
    elif path:
        target = context.guarded_path(path)
        if not target.is_file():
            raise MailError(f"Not a readable file: {path}", code="not_found")
        raw = target.read_bytes()
        source = str(target)
    else:
        raise MailError("email needs a path to an .eml file, or content.", code="invalid_arguments")

    parsed = parse_message(raw)
    evidence = recon.Evidence()
    enrichment: dict[str, Any] | None = None
    if enrich and operation in {"analyze", "hops"}:
        transport = recon.Transport(timeout=timeout)
        hop_ips = [h["ip"] for h in parsed["headers"]["hops"] if h.get("ip") and h.get("ip_public")]
        if parsed["headers"].get("originating_ip") and recon.is_public_address(parsed["headers"]["originating_ip"]):
            hop_ips.insert(0, parsed["headers"]["originating_ip"])
        enrichment = _enrich_boundary(parsed, hop_ips, transport, evidence)
    result: dict[str, Any] = {"status": "success", "operation": operation, "source": source,
                              "message_sha256": parsed["sha256"], "size": parsed["size"]}
    if operation == "analyze":
        result.update({"headers": parsed["headers"], "auth": parsed["auth"], "iocs": parsed["iocs"],
                       "attachments": parsed["attachments"], "structure": parsed["structure"],
                       "enrichment": enrichment, "risk": score(parsed, enrichment)})
    elif operation == "headers":
        result.update({"headers": parsed["headers"], "auth": parsed["auth"]})
    elif operation == "auth":
        result.update({"auth": parsed["auth"], "from": parsed["headers"]["from"]})
    elif operation == "hops":
        result.update({"hops": parsed["headers"]["hops"], "enrichment": enrichment})
    elif operation == "iocs":
        result.update({"iocs": parsed["iocs"]})
    elif operation == "attachments":
        result.update({"attachments": parsed["attachments"]})
    else:
        raise MailError(f"Unknown operation {operation!r}.", code="invalid_arguments")
    result.update({"contacted": evidence.contacted, "recipe": evidence.recipe[:6],
                   "notes": evidence.notes, "exit_code": 0})
    return result


def _enrich_boundary(parsed: dict[str, Any], hop_ips: list[str], transport: recon.Transport,
                     evidence: recon.Evidence) -> dict[str, Any]:
    """The only path from the parser to the network, and it carries strings alone."""

    iocs = {"domains": list(parsed["iocs"]["domains"]), "ips": list(parsed["iocs"]["ips"]),
            "attachment_hashes": list(parsed["iocs"]["attachment_hashes"])}
    return enrich(iocs, sender_domain=parsed["headers"]["from"]["domain"], hop_ips=hop_ips,
                  dkim=[{"d": s["d"], "s": s["s"]} for s in parsed["auth"]["signatures"]],
                  transport=transport, evidence=evidence)
