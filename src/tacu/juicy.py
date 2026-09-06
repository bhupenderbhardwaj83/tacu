"""Juicy-information detector and validator.

Pipeline: candidate → validator → context → confidence → overlap → finding.

Analyst-facing output keeps values in the clear. Redaction is a separate
policy for non-local model providers, not part of detection.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import ipaddress
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, replace
from typing import Callable, Sequence
from urllib.parse import urlparse

from . import juicyfields
from .theme import PALETTE, color_enabled, paint


CONFIDENCE_LEVELS = ("critical", "high", "medium", "low")
_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Location-like kinds compete for the same span (URL over domain, email over domain).
_LOCATION = frozenset({"url", "domain", "ipv4", "ipv6", "internal-host"})


@dataclass(frozen=True)
class JuicyFinding:
    kind: str
    value: str
    start: int
    end: int
    line: int
    confidence: str = "high"
    category: str = ""
    source: str = ""
    context: str = ""
    packet: int = 0
    item: int = 0


def secret_fingerprint(kind: str, value: str) -> str:
    """SHA-256 of kind + normalized secret. Same credential, same id — for rotation."""

    blob = f"{kind.strip().lower()}\n{(value or '').strip()}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def redacted_preview(value: str) -> str:
    """Shareable stub: first 4 + *** + last 4. Terminal still shows the full value."""

    text = (value or "").replace("\n", " ").strip()
    if not text:
        return ""
    if len(text) <= 8:
        return text[:2] + "***"
    return f"{text[:4]}***{text[-4:]}"


def line_snippet(text: str, start: int, end: int, limit: int = 160) -> str:
    """The source line around a match, trimmed for reports."""

    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    snippet = text[line_start:line_end].replace("\r", "").strip()
    if len(snippet) > limit:
        snippet = snippet[:limit] + "…"
    return snippet


def redact_value_in_text(text: str, value: str) -> str:
    """Replace the live secret inside a context line with the shareable stub."""

    if not text or not value or value not in text:
        return text
    return text.replace(value, redacted_preview(value))


def wants_juicy(text: str) -> bool:
    """True for juicy / common typos (jucy, juici) plus info/details/data/secrets."""

    return bool(_JUICY_REQUEST.search(text or ""))


@dataclass(frozen=True)
class JuicyQuestion:
    """How a plain-language question maps onto the juicy inventory.

    `kinds` empty means the full analyst catalog (HIGH_JUICY_KINDS).
    `needles` are literal values pulled from the question (a phone, email, token).
    `want_model` is True for questions: the inventory is filtered first, and only
    that slice is sent to the model. Extract-without-ask never sets this.
    """

    kinds: frozenset[str]
    want_model: bool
    needles: tuple[str, ...] = ()


_KIND_QUERY: tuple[tuple[re.Pattern[str], frozenset[str]], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), frozenset(kinds))
    for pattern, kinds in (
        (r"\bpasswords?|\bpasswd\b|\bpwd\b|\bpassphrases?|\bcredentials?\b",
         {"password"}),
        (r"\buser\s*names?|\busernames?|\blogins?\b",
         {"username"}),
        (r"\be-?mails?\b",
         {"email"}),
        (r"\bphones?|\bmobiles?|\bcellphones?|\bcell\s*phones?|"
         r"\bmobile\s+numbers?|\bphone\s+numbers?|\bcontact\s+numbers?\b",
         {"indian-phone", "intl-phone"}),
        (r"\bpan\b|\bpermanent account\b",
         {"pan"}),
        (r"\baadhaars?|\badhaar\b",
         {"aadhaar"}),
        (r"\bcredit\s*cards?|\bcard numbers?\b",
         {"credit-card"}),
        (r"\burls?\b|\bweb\s*addresses?|\blinks?\b",
         {"url", "secret-in-url", "domain"}),
        (r"\bapis?\b|\bapi[_-]?keys?|\baccess[_-]?keys?|\btokens?|\bsecrets?\b|\bbearers?\b",
         {"secret", "bearer", "github-token", "gitlab-token", "slack-token", "stripe-key",
          "sendgrid-key", "google-api-key", "npm-token", "pypi-token", "azure-key",
          "aws-access-key", "twilio-sid"}),
        (r"\baws\b",
         {"aws-access-key"}),
        (r"\bjwts?\b|\bjson web tokens?\b",
         {"jwt"}),
        (r"\bprivate\s+keys?|\bpem keys?|\bssh keys?|\bcertificates?|\bpem\b",
         {"private-key", "ssh-key", "pem-certificate"}),
        (r"\bips?\b|\bip\s+address(?:es)?|\bipv4\b|\bipv6\b",
         {"ipv4", "ipv6"}),
        (r"\bibans?\b|\bupi\b|\bswift\b|\bbank accounts?\b",
         {"iban", "upi", "swift", "bank-account"}),
        (r"\bcookies?\b|\bsessions?\b",
         {"session-cookie", "insecure-cookie"}),
        (r"\bpassports?\b|\buuids?\b",
         {"passport", "uuid"}),
        (r"\bgithub\b|\bgitlab\b|\bslack\b|\bstripe\b|\bazure\b|\bsendgrid\b|\btwilio\b|\bnpm\b|\bpypi\b",
         {"github-token", "gitlab-token", "slack-token", "stripe-key", "azure-key",
          "sendgrid-key", "twilio-sid", "npm-token", "pypi-token"}),
        (r"\bdatabase\b|\bdb[-_ ]?uri\b|\bconnection strings?\b",
         {"db-uri"}),
        (r"\bcors\b|\binjection\b|\bsql\b|\bxxe\b|\bldap\b",
         {"cors-wildcard", "sql-error", "sql-fragment", "xxe", "ldap-filter"}),
    )
)
_JUICY_ADVICE = re.compile(
    r"\b(?:rotate|revoke|riskiest|"
    r"most (?:urgent|critical|exposed)|which .{0,24}(?:first|worst))\b",
    re.IGNORECASE,
)
_JUICY_FOLLOWUP = re.compile(
    r"\b(?:what should i\b|how (?:do|to|should) (?:i |we )?(?:lock|protect|fix)|recommend)\b",
    re.IGNORECASE,
)
_LISTING_QUESTION = re.compile(
    r"\b(?:are there|is there|show(?:\s+me)?|list|find(?:\s+me)?|"
    r"what .{0,40}(?:were |was )?found|print|dump)\b",
    re.IGNORECASE,
)
_KIND_INSIGHT = re.compile(
    r"\b(?:how|why|tell me|summar|explain|analy[sz]e|dangerous|sensitive|"
    r"expos(?:ed|ure)|protect|insight|meaning)\b",
    re.IGNORECASE,
)
_NEEDLE_STOP = frozenset({
    "is", "there", "are", "the", "data", "file", "table", "in", "a", "an", "of",
    "any", "show", "me", "list", "find", "print", "dump", "what", "were", "was",
    "found", "juicy", "jucy", "juici", "jcy", "information", "info", "details",
    "detail", "this", "that", "those", "these", "with", "from", "for", "and",
    "or", "to", "do", "does", "have", "has", "been", "some", "all", "values",
    "value", "kind", "kinds", "please", "just", "about",
})
_QUOTED_NEEDLE = re.compile(r"""['"]([^'"\n]{2,})['"]""")
_EMAIL_NEEDLE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_DIGIT_NEEDLE = re.compile(r"\d[\d\s().-]{4,}\d")
_SECRETISH_NEEDLE = re.compile(
    r"\b(?=[A-Za-z0-9_+/=.-]*\d)[A-Za-z][A-Za-z0-9_+/=.-]{5,}\b"
)


def needles_in_question(text: str) -> tuple[str, ...]:
    """Literal values a person asked about: digits, emails, quoted strings, tokens."""

    blob = text or ""
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        item = (raw or "").strip()
        if len(item) < 3:
            return
        key = item.casefold()
        if key in seen or key in _NEEDLE_STOP:
            return
        dashed = key.replace("_", "-")
        if dashed in JUICY_KIND_NAMES or dashed in HIGH_JUICY_KINDS:
            return
        seen.add(key)
        found.append(item)

    for match in _QUOTED_NEEDLE.finditer(blob):
        add(match.group(1))
    for match in _EMAIL_NEEDLE.finditer(blob):
        add(match.group(0))
    for match in _DIGIT_NEEDLE.finditer(blob):
        digits = re.sub(r"\D", "", match.group(0))
        add(digits if len(digits) >= 6 else match.group(0))
    remainder = _QUOTED_NEEDLE.sub(" ", blob)
    remainder = _EMAIL_NEEDLE.sub(" ", remainder)
    remainder = _DIGIT_NEEDLE.sub(" ", remainder)
    for token in _SECRETISH_NEEDLE.findall(remainder):
        if token.casefold() in _NEEDLE_STOP or token.isalpha():
            continue
        add(token)
    return tuple(found)


def value_matches_needles(value: str, needles: Sequence[str]) -> bool:
    """True when the finding contains any needle, including digit-normalised phones."""

    if not needles:
        return True
    folded = (value or "").casefold()
    digits = re.sub(r"\D", "", value or "")
    for needle in needles:
        text = (needle or "").strip()
        if not text:
            continue
        if text.casefold() in folded:
            return True
        ndigits = re.sub(r"\D", "", text)
        if len(ndigits) >= 6 and ndigits in digits:
            return True
        if len(digits) >= 6 and digits in ndigits:
            return True
    return False


def parse_kind_flag(text: str) -> frozenset[str]:
    """Comma/space-separated kinds or aliases (`phone`, `jwt`, `indian-phone`)."""

    found: set[str] = set()
    for part in re.split(r"[,\s]+", text or ""):
        if not part:
            continue
        named = _kinds_named_in(part.replace("_", "-"))
        found.update(named)
        for pattern, group in _KIND_QUERY:
            if pattern.search(part):
                found.update(group)
        folded = part.casefold().replace("_", "-")
        if folded in JUICY_KIND_NAMES or folded in HIGH_JUICY_KINDS:
            found.add(folded)
        elif not named:
            found.add(folded)
    return frozenset(found)


def finding_where(item: JuicyFinding) -> str:
    """Place label: path:line, plus packet N (Wireshark) and item N (Burp) when known."""

    if item.source:
        place = f"{item.source}:{item.line}"
    else:
        place = f"source line {item.line}"
    extras: list[str] = []
    if item.packet:
        extras.append(f"packet {item.packet}")
    if item.item:
        extras.append(f"item {item.item}")
    if extras:
        return place + " · " + " · ".join(extras)
    return place


def kind_matches_query(kind: str, wanted: frozenset[str]) -> bool:
    """True when a finding kind (or a CSV column name used as kind) is in the query set."""

    if not wanted:
        return True
    folded = (kind or "").casefold().replace("_", "-")
    if folded in wanted:
        return True
    return any(item == folded or item in folded or folded in item for item in wanted)


def _kinds_named_in(blob: str) -> set[str]:
    """Match any detector kind by hyphenated or spaced name (jwt, private key, aws-access-key)."""

    found: set[str] = set()
    for kind in JUICY_KIND_NAMES:
        dashed = kind.replace("_", "-")
        spaced = dashed.replace("-", r"[\s_-]+")
        if re.search(rf"\b{spaced}s?\b", blob, re.IGNORECASE):
            found.add(kind)
    return found


def parse_juicy_question(text: str) -> JuicyQuestion | None:
    """Map a data-ask / --ask question onto the juicy inventory, or None for SQL/model-as-usual."""

    blob = (text or "").strip()
    if not blob:
        return None
    kinds: set[str] = set()
    for pattern, group in _KIND_QUERY:
        if pattern.search(blob):
            kinds.update(group)
    kinds.update(_kinds_named_in(blob))
    needles = needles_in_question(blob)
    advice = bool(_JUICY_ADVICE.search(blob))
    inventory = wants_juicy(blob)
    listing = bool(_LISTING_QUESTION.search(blob))
    if kinds or inventory:
        advice = advice or bool(_JUICY_FOLLOWUP.search(blob)) or bool(_KIND_INSIGHT.search(blob))
    if not kinds and not inventory and not advice:
        if not (needles and listing):
            return None
    return JuicyQuestion(
        kinds=frozenset(kinds),
        want_model=True,
        needles=needles,
    )


def meets_confidence(finding: JuicyFinding, minimum: str) -> bool:
    return _RANK.get(finding.confidence, 0) >= _RANK.get(minimum, 0)


def juicy_ansi(kind: str = "", category: str = "", confidence: str = "high") -> str:
    """Soothing 256-color by family; critical findings are also bold."""

    family = category or _KIND_CATEGORY.get(kind, "secret")
    color = _FAMILY_COLOR.get(family, PALETTE.juicy_secret)
    if confidence == "critical":
        return color + PALETTE.bold
    return color


def colorize_finding(finding: JuicyFinding) -> bool:
    """Whether general terminal output should highlight this finding."""

    if finding.category in {"injection", "http", "config"}:
        return False
    if finding.confidence == "low" and finding.kind not in {"ipv4", "ipv6", "url", "domain", "email"}:
        return False
    return True


# ---------------------------------------------------------------------------
# Checksums and structure
# ---------------------------------------------------------------------------

def _luhn(value: str) -> bool:
    digits = [int(char) for char in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6), (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4), (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2), (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def _verhoeff(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    checksum = 0
    for index, char in enumerate(reversed(digits)):
        checksum = _VERHOEFF_D[checksum][_VERHOEFF_P[index % 8][int(char)]]
    return checksum == 0


def _iban_checksum(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not 15 <= len(compact) <= 34 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in Counter(value).values())


def _context(text: str, start: int, end: int, radius: int = 96) -> str:
    return text[max(0, start - radius): min(len(text), end + radius)]


_PLACEHOLDERS = frozenset({
    "example", "sample", "dummy", "placeholder", "redacted", "none", "null",
    "undefined", "todo", "xxxx", "xxxxxxxx", "your_password", "your_password_here",
    "<password>", "${password}", "secret", "token", "apikey", "api_key",
})
_WEAK_SECRETS = frozenset({
    "password", "passwd", "admin", "root", "changeme", "changeit", "123456",
    "12345678", "default", "toor", "qwerty", "letmein",
})
_SECRET_HINT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|"
    r"credential|client[_-]?secret|private[_-]?key|access[_-]?token)\b"
)
_PASSPORT_HINT = re.compile(r"(?i)\bpassports?\b")
_UUID_HINT = re.compile(r"(?i)\b(uuid|guid|account|customer|user[_-]?id|request[_-]?id)\b")
_BANK_HINT = re.compile(r"(?i)\b(account[_-]?no(?:umber)?|acct|iban|ifsc|swift|routing)\b")
_KNOWN_IIN = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5))")


def _is_placeholder(value: str) -> bool:
    folded = value.strip("\"'").casefold()
    if folded in _PLACEHOLDERS:
        return True
    if re.fullmatch(r"[x*.#]{4,}", folded):
        return True
    if re.fullmatch(r"\$\{[^}]+\}", value) or re.fullmatch(r"<[^>]+>", value):
        return True
    return False


# ---------------------------------------------------------------------------
# Validators — return confidence or None to reject
# ---------------------------------------------------------------------------

def _accept(confidence: str) -> Callable[[str, str], str | None]:
    return lambda _value, _context: confidence


def _validate_aadhaar(value: str, _ctx: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 12 or digits[0] not in "23456789":
        return None
    return "high" if _verhoeff(digits) else None


def _validate_pan(value: str, _ctx: str) -> str | None:
    if not re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", value):
        return None
    # 4th character is the holder type (P individual, C company, …). Unknown letters
    # still match the published shape, so they stay medium rather than being dropped.
    return "high" if value[3] in "PCHABGJLFT" else "medium"


def _validate_card(value: str, _ctx: str) -> str | None:
    if not _luhn(value):
        return None
    digits = re.sub(r"\D", "", value)
    return "high" if _KNOWN_IIN.match(digits) else "medium"


def _validate_iban(value: str, _ctx: str) -> str | None:
    return "high" if _iban_checksum(value) else None


def _validate_swift(value: str, ctx: str) -> str | None:
    compact = value.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?", compact):
        return None
    hinted = bool(_BANK_HINT.search(ctx))
    # A BIC's 5th and 6th characters are an ISO country code, and its location
    # or branch code almost always carries a digit. ESTABLISHED satisfies the
    # letter pattern and even the country code (BL), so without the digit test
    # every netstat capture reports a bank code.
    if not hinted and (compact[4:6] not in _ISO_COUNTRIES
                       or not any(char.isdigit() for char in compact)):
        return None
    if len(compact) == 11:
        return "high" if hinted else "medium"
    return "high" if hinted else None


def _validate_stripe(value: str, _ctx: str) -> str | None:
    if value.startswith("pk_"):
        return "medium"
    if "_test_" in value:
        return "high"
    return "critical"


def _validate_jwt(value: str, _ctx: str) -> str | None:
    parts = value.split(".")
    if len(parts) != 3:
        return None
    header = parts[0] + "=" * (-len(parts[0]) % 4)
    try:
        decoded = json.loads(base64.urlsafe_b64decode(header))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    algorithm = str(decoded.get("alg") or "")
    if algorithm.lower() == "none":
        return "critical"
    if algorithm:
        return "high"
    return "medium"


# ISO 3166-1 alpha-2, the 5th-6th characters of every BIC. Kept as a set rather
# than a dependency so the check works on a machine with nothing installed.
_ISO_COUNTRIES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL
BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV
CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD
GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM
IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK
LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW
MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR
PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS
ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY
UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())

# The suffixes that actually turn up in source and captures. Every two-letter
# label is treated as a country code, which covers the rest without a list.
_COMMON_TLDS = frozenset("""
com org net edu gov mil int info biz name pro app dev io co ai cloud tech online
site web xyz store shop live life world today news blog wiki page link click
email systems services solutions network host hosting digital agency studio
media group team works company enterprises industries global international
local internal corp lan intranet test example invalid localhost onion
""".split())


def _validate_domain(value: str, ctx: str) -> str | None:
    """Tell a hostname from a dotted identifier in code.

    `System.Environment.GetEnvironmentVariable` has the shape of a domain and is
    a method call. Hostnames are case-insensitive and written in one case; code
    is camelCase, and that is the difference worth using — no TLD list needed,
    so a new suffix is never reported as unknown.
    """

    label = value.rsplit(".", 1)[-1]
    if not label.isalpha() or len(label) > 24:
        return None
    # A hostname ends in a public suffix. Without that test every `item.value`
    # and `config.settings` in the codebase is reported as a host.
    if label.casefold() not in _COMMON_TLDS and len(label) != 2:
        return None
    if not (label.islower() or label.isupper()):
        return None
    if any(part[:1].isupper() and not part.isupper() for part in value.split(".")[:-1]):
        return None
    # A name that is immediately called is a function, not a host.
    if f"{value}(" in ctx:
        return None
    return "low"


def _validate_ipv4(value: str, _ctx: str) -> str | None:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return "low"
    if address.is_private:
        return "medium"
    if address.is_global:
        return "medium"
    return "low"


def _validate_ipv6(value: str, _ctx: str) -> str | None:
    try:
        address = ipaddress.IPv6Address(value)
    except ipaddress.AddressValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return "low"
    return "medium"


def _validate_url(value: str, _ctx: str) -> str | None:
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return "critical"
    host = parsed.hostname.casefold()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost"):
        return "low"
    if parsed.scheme == "http":
        return "medium"
    return "medium"


def _validate_db_uri(value: str, _ctx: str) -> str | None:
    try:
        parsed = urlparse(value)
    except ValueError:
        return "medium"
    if parsed.username or parsed.password or "@" in value.split("://", 1)[-1]:
        return "critical"
    return "medium"


def _line_around(context: str, value: str) -> str:
    """The line the candidate sits on, found by locating the candidate itself.

    The window is clipped at the start of a file, so the candidate is not always
    in the middle of it — taking the middle line read the *next* line near the
    top of a file and judged the candidate on someone else's words.
    """

    if not context:
        return ""
    index = context.find(value) if value else -1
    if index < 0:
        index = len(context) // 2
    start = context.rfind("\n", 0, index) + 1
    end = context.find("\n", index)
    return context[start:] if end < 0 else context[start:end]


def _field_secret(kind: str) -> Callable[[str, str], str | None]:
    """Score a name-and-assignment candidate instead of trusting the name.

    `password = os.getenv("DB_PASSWORD")` names a secret; `password = "Xv9!q"`
    is one. Only the second is a hard-coded credential, and the score says so.
    """

    def validate(value: str, ctx: str) -> str | None:
        score, _origin, _cleaned = juicyfields.score_field_secret(
            value=value, context=ctx, line=_line_around(ctx, value), kind=kind)
        return juicyfields.level_for(score)

    return validate


_validate_password = _field_secret("password")
_validate_username = _field_secret("username")


_validate_secret = _field_secret("secret")


def _validate_indian_phone(value: str, _ctx: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    if len(digits) != 10 or digits[0] not in "6789":
        return None
    return "medium"


def _validate_intl_phone(value: str, ctx: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if not 8 <= len(digits) <= 15:
        return None
    if re.search(r"(?i)\b(tel|phone|mobile|whatsapp|sms)\b", ctx):
        return "medium"
    return "low"


def _validate_passport(value: str, ctx: str) -> str | None:
    if not _PASSPORT_HINT.search(ctx):
        return None
    return "medium"


def _validate_uuid(value: str, ctx: str) -> str | None:
    return "medium" if _UUID_HINT.search(ctx) else "low"


def _validate_upi(value: str, _ctx: str) -> str | None:
    handle, _, psp = value.partition("@")
    if len(handle) < 2 or not psp:
        return None
    return "high"


def _validate_bank_account(value: str, ctx: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if not 8 <= len(digits) <= 18:
        return None
    return "medium" if _BANK_HINT.search(ctx) else None


def _validate_session_cookie(value: str, _ctx: str) -> str | None:
    if "=" not in value:
        return None
    name, _, token = value.partition("=")
    if len(token) < 8:
        return None
    return "high" if len(token) >= 16 else "medium"


def _validate_insecure_cookie(value: str, _ctx: str) -> str | None:
    folded = value.casefold()
    if "set-cookie" not in folded:
        return None
    missing = "secure" not in folded or "httponly" not in folded
    return "medium" if missing else None


def _validate_guessable_id(value: str, _ctx: str) -> str | None:
    number = re.search(r"\d+$", value)
    if not number:
        return None
    return "low"


# ---------------------------------------------------------------------------
# Candidate patterns — order is overlap priority (earlier wins)
# ---------------------------------------------------------------------------

_Spec = tuple[str, str, re.Pattern[str], int, Callable[[str, str], str | None] | None]

_SPECS: tuple[_Spec, ...] = (
    ("private-key", "secret",
     re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"), 0, _accept("critical")),
    ("pem-certificate", "secret",
     re.compile(r"-----BEGIN CERTIFICATE-----"), 0, _accept("medium")),
    ("bearer", "authentication",
     re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/=-]{8,})"),
     1, _accept("critical")),
    ("basic-auth", "authentication",
     re.compile(r"(?i)\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{8,})"),
     1, _accept("critical")),
    ("jwt", "authentication",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
     0, _validate_jwt),
    ("aws-access-key", "secret",
     re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 0, _accept("critical")),
    ("github-token", "secret",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,255}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
     0, _accept("critical")),
    ("gitlab-token", "secret",
     re.compile(r"\b(?:glpat|glptt|gldt|glrt|glsoat)-[A-Za-z0-9_-]{20,}\b"),
     0, _accept("critical")),
    ("slack-token", "secret",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bhttps://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+\b",
                re.I),
     0, _accept("critical")),
    ("stripe-key", "secret",
     re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bwhsec_[A-Za-z0-9]{16,}\b"),
     0, _validate_stripe),
    ("azure-key", "secret",
     re.compile(r"(?i)\b(?:AccountKey|SharedAccessKey|SharedAccessSignature)\s*=\s*([A-Za-z0-9+/=]{16,})"),
     1, _accept("critical")),
    ("sendgrid-key", "secret",
     re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), 0, _accept("critical")),
    ("twilio-sid", "secret",
     re.compile(r"\b(?:SK|AC)[0-9a-fA-F]{32}\b"), 0, _accept("high")),
    ("npm-token", "secret",
     re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), 0, _accept("critical")),
    ("pypi-token", "secret",
     re.compile(r"\bpypi-AgE[A-Za-z0-9_-]{20,}\b"), 0, _accept("critical")),
    ("google-api-key", "secret",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0, _accept("high")),
    ("db-uri", "secret",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql)"
                r"://[^\s\"'<>]+", re.I),
     0, _validate_db_uri),
    ("ssh-key", "secret",
     re.compile(r"\bssh-(?:rsa|ed25519|ecdsa-[A-Za-z0-9-]+)\s+[A-Za-z0-9+/]{40,}={0,3}(?:\s+[^\r\n]+)?"),
     0, _accept("medium")),
    ("email", "identity",
     re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.I),
     0, _accept("high")),
    ("upi", "financial",
     re.compile(r"\b[A-Za-z0-9._-]{2,256}@(?:upi|okaxis|oksbi|okhdfcbank|okicici|"
                r"okyesbank|ybl|paytm|ibl|axl|apl|waaxis)\b", re.I),
     0, _validate_upi),
    ("url", "network",
     re.compile(r"\b(?:https?|ftp)://[^\s<>\"']+", re.I), 0, _validate_url),
    ("secret-in-url", "authentication",
     re.compile(r"""(?ix)[?&](password|passwd|pwd|secret|token|access_token|
                               api_key|apikey|jwt|session)=([^&#\s]{3,})"""),
     0, _accept("critical")),
    ("iban", "financial",
     re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b"), 0, _validate_iban),
    ("swift", "financial",
     re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"), 0, _validate_swift),
    ("pan", "identity",
     re.compile(r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])"), 0, _validate_pan),
    ("aadhaar", "identity",
     re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), 0, _validate_aadhaar),
    ("credit-card", "financial",
     re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), 0, _validate_card),
    ("indian-phone", "identity",
     re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"), 0, _validate_indian_phone),
    ("intl-phone", "identity",
     re.compile(r"(?<!\d)\+[1-9]\d{7,14}(?!\d)"), 0, _validate_intl_phone),
    ("passport", "identity",
     re.compile(r"\b[A-Z][0-9]{7}\b"), 0, _validate_passport),
    ("uuid", "identity",
     re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
                r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"),
     0, _validate_uuid),
    ("bank-account", "financial",
     re.compile(r"""(?ix)\b(?:account[_-]?no(?:umber)?|acct(?:ount)?[_-]?(?:no|number)?)\b
                    [\"']?\s*[:=]\s*[\"']?(\d[\d -]{7,22}\d)"""),
     1, _validate_bank_account),
    ("ipv4", "network",
     re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), 0, _validate_ipv4),
    ("ipv6", "network",
     re.compile(r"(?<![\w:])(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{0,4}(?![\w:])", re.I),
     0, _validate_ipv6),
    ("internal-host", "network",
     re.compile(r"(?<![@\w-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
                r"(?:internal|corp|lan|local|intranet)\b", re.I),
     0, _accept("low")),
    ("domain", "network",
     re.compile(r"(?<![@\w-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b", re.I),
     0, _validate_domain),
    # Field-named credentials. An alias at a word boundary plus an assignment is
    # the candidate; the value's origin decides whether it is a finding at all.
    ("password", "authentication",
     juicyfields.assignment_pattern(juicyfields.PASSWORD_GROUP), "value", _validate_password),
    ("password", "authentication",
     juicyfields.xml_element_pattern(juicyfields.PASSWORD_GROUP), "value", _validate_password),
    ("password", "authentication",
     juicyfields.xml_attribute_pattern(juicyfields.PASSWORD_GROUP), "value", _validate_password),
    ("username", "identity",
     juicyfields.assignment_pattern(juicyfields.USERNAME_GROUP), "value", _validate_username),
    ("username", "identity",
     juicyfields.xml_element_pattern(juicyfields.USERNAME_GROUP), "value", _validate_username),
    ("secret", "secret",
     juicyfields.assignment_pattern(juicyfields.SECRET_GROUP), "value", _validate_secret),
    ("secret", "secret",
     juicyfields.xml_element_pattern(juicyfields.SECRET_GROUP), "value", _validate_secret),
    ("secret", "secret",
     juicyfields.xml_attribute_pattern(juicyfields.SECRET_GROUP), "value", _validate_secret),
    ("session-cookie", "authentication",
     re.compile(r"""(?i)\b(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|sessionid|
                            connect\.sid)=([A-Za-z0-9._-]{8,})"""),
     0, _validate_session_cookie),
    ("insecure-cookie", "http",
     re.compile(r"(?i)Set-Cookie:\s*[^\r\n]+"), 0, _validate_insecure_cookie),
    ("cors-wildcard", "http",
     re.compile(r"(?i)Access-Control-Allow-Origin\s*:\s*\*"), 0, _accept("medium")),
    ("debug-enabled", "config",
     re.compile(r"(?i)\b(?:debug|development)\s*[:=]\s*(?:true|1|yes)\b"), 0, _accept("medium")),
    ("tls-verify-disabled", "config",
     re.compile(r"(?i)\b(?:verify_ssl|ssl_verify|verify|CURLOPT_SSL_VERIFYPEER|"
                r"NODE_TLS_REJECT_UNAUTHORIZED)\s*[:=]\s*(?:false|0|no)\b"),
     0, _accept("high")),
    ("unrestricted-bind", "config",
     re.compile(r"(?i)\b(?:bind|host|listen)\s*[:=]\s*[\"']?0\.0\.0\.0\b"), 0, _accept("medium")),
    ("guessable-id", "http",
     re.compile(r"""(?ix)[?&](id|user_id|userid|account_id|account|customer_id|
                               order_id|invoice_id|profile_id)=(\d{1,12})"""),
     0, _validate_guessable_id),
    ("sql-error", "injection",
     re.compile(r"(?i)(SQL syntax.*MySQL|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\.?Exception|"
                r"Unclosed quotation mark|ODBC SQL Server Driver)"),
     0, _accept("high")),
    ("sql-fragment", "injection",
     re.compile(r"""(?i)(?:'\s*(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|
                      \bunion\s+select\b|\bdrop\s+table\b)"""),
     0, _accept("medium")),
    ("stack-trace", "injection",
     re.compile(r"(?i)(Traceback \(most recent call last\)|java\.lang\.\w+Exception|"
                r"System\.\w+Exception|at [\w.$]+\(.*\.java:\d+\))"),
     0, _accept("medium")),
    ("xxe", "injection",
     re.compile(r"(?i)<!DOCTYPE[^>]+(?:SYSTEM|PUBLIC)"), 0, _accept("medium")),
    ("ldap-filter", "injection",
     re.compile(r"\(\s*(?:objectClass|cn|uid)\s*="), 0, _accept("low")),
    ("xpath-fragment", "injection",
     re.compile(r"(?i)//\w+\s*\[\s*@\w+\s*="), 0, _accept("low")),
    ("java-serialized", "injection",
     re.compile(r"\brO0AB[A-Za-z0-9+/]{8,}"), 0, _accept("medium")),
    ("directory-listing", "http",
     re.compile(r"(?i)(?:<title>\s*)?Index of /"), 0, _accept("medium")),
    ("shell-metachar", "injection",
     re.compile(r"""(?ix)[?&](?:cmd|exec|command|ping|query)=[^&\s]*[;&|`$]"""),
     0, _accept("medium")),
)

_JUICY_REQUEST = re.compile(
    r"\b(?:juicy|jucy|jcy|juici|juciy|juiccy|jucey)\b"
    r"(?:\s+(?:info(?:rmation)?|details?|data|values?|findings?|secrets?))?",
    re.IGNORECASE,
)

# One kind can have several syntaxes (a password in Python, in XML, in an
# attribute), so the kind list is deduplicated and priority is the first spec.
JUICY_KIND_NAMES = tuple(dict.fromkeys(
    kind for kind, _category, _pattern, _group, _validate in _SPECS))
_KIND_CATEGORY = {kind: category for kind, category, _pattern, _group, _validate in _SPECS}
_PRIORITY: dict[str, int] = {}
for _index, (_kind, *_rest) in enumerate(_SPECS):
    _PRIORITY.setdefault(_kind, _index)
_FAMILY_COLOR = {
    "identity": PALETTE.juicy_id,
    "financial": PALETTE.juicy_money,
    "authentication": PALETTE.juicy_auth,
    "secret": PALETTE.juicy_secret,
    "network": PALETTE.juicy_net,
    "http": PALETTE.juicy_signal,
    "injection": PALETTE.juicy_signal,
    "config": PALETTE.juicy_signal,
}

HIGH_JUICY_KINDS = frozenset({
    "private-key", "jwt", "aws-access-key", "ssh-key", "email", "pan", "aadhaar",
    "credit-card", "password", "username", "secret",
    "indian-phone", "upi", "iban", "github-token", "gitlab-token", "slack-token",
    "stripe-key", "sendgrid-key", "twilio-sid", "npm-token", "pypi-token",
    "google-api-key", "bearer", "basic-auth", "db-uri", "secret-in-url",
    "azure-key", "session-cookie", "passport",
})
REMOTE_REDACT_KINDS = frozenset({
    "private-key", "jwt", "aws-access-key", "ssh-key", "email", "pan", "aadhaar",
    "credit-card", "password", "secret",
    "github-token", "gitlab-token", "slack-token", "stripe-key", "sendgrid-key",
    "twilio-sid", "npm-token", "pypi-token", "google-api-key", "bearer",
    "basic-auth", "db-uri", "secret-in-url", "session-cookie", "iban", "upi",
    "azure-key",
})


# Kinds that name who you are, and kinds that let you prove it. One of each in
# the same block is a working credential, which is worth more than the sum.
# Only a *field-assigned* identity counts: an address that merely appears on the
# same line as a password is prose, not the other half of a login.
_IDENTITY_KINDS = frozenset({"username"})
_PROOF_KINDS = frozenset({"password", "secret", "bearer", "basic-auth", "jwt"})
_PAIR_LINE_WINDOW = 5


def _correlate_credentials(findings: list[JuicyFinding]) -> list[JuicyFinding]:
    """Raise a username and a password found together to what they really are.

    Separately they are a name and a string. Within a few lines of each other
    they are an account someone can log in with, so both are upgraded once.
    """

    proofs = [item for item in findings if item.kind in _PROOF_KINDS]
    names = [item for item in findings if item.kind in _IDENTITY_KINDS]
    if not proofs or not names:
        return findings
    paired: set[int] = set()
    for name in names:
        for proof in proofs:
            if abs(proof.line - name.line) <= _PAIR_LINE_WINDOW:
                paired.add(id(name))
                paired.add(id(proof))
    if not paired:
        return findings
    return [replace(item, confidence=_raise_confidence(item.confidence))
            if id(item) in paired else item for item in findings]


def _raise_confidence(level: str) -> str:
    order = ("low", "medium", "high", "critical")
    try:
        return order[min(order.index(level) + 1, len(order) - 1)]
    except ValueError:
        return level


def detect_juicy(text: str) -> list[JuicyFinding]:
    """Detect high-value identifiers, credentials, keys, endpoints, and signals."""

    candidates: list[JuicyFinding] = []
    for kind, category, pattern, group, validate in _SPECS:
        for match in pattern.finditer(text):
            value = match.group(group) if group else match.group(0)
            start, end = (match.span(group) if group else match.span())
            if kind == "credit-card":
                trimmed = value.rstrip(" -")
                end -= len(value) - len(trimmed)
                value = trimmed
            nearby = _context(text, start, end)
            confidence = "high"
            if validate is not None:
                # The raw value is what carries the origin: quotes, an `f` prefix
                # and `${...}` all decide whether this is a secret at all, so it
                # is judged before anything is trimmed off it.
                scored = validate(value, nearby)
                if not scored:
                    continue
                confidence = scored
            if group == "value":
                # Report the credential, not the quotes around it, so the same
                # secret fingerprints identically however it was written.
                stripped = juicyfields.unquote(value)
                if stripped != value:
                    offset = value.find(stripped)
                    start, end = start + offset, start + offset + len(stripped)
                value = stripped
            candidates.append(JuicyFinding(
                kind, value, start, end, text.count("\n", 0, start) + 1,
                confidence, category, context=line_snippet(text, start, end),
            ))
    accepted = _correlate_credentials(_resolve_overlaps(candidates))
    seen = {(item.kind, item.value) for item in accepted}
    extra: list[JuicyFinding] = []
    for item in _csv_column_findings(text):
        mark = (item.kind, item.value)
        if mark in seen:
            continue
        seen.add(mark)
        extra.append(item)
    if not extra:
        return accepted
    return sorted(accepted + extra, key=lambda item: item.start)


_COLUMN_HINTS = (
    "pass", "user", "email", "token", "secret", "key", "auth", "cookie",
    "phone", "pan", "aadhaar", "otp", "session", "api",
)


def _column_kind(name: str) -> tuple[str, str]:
    folded = name.casefold()
    if "email" in folded:
        return "email", "identity"
    if "pass" in folded or folded in {"pwd", "passwd"}:
        return "password", "authentication"
    if "user" in folded or folded in {"login"}:
        return "username", "identity"
    if "phone" in folded or "mobile" in folded:
        return "indian-phone", "identity"
    return "secret", "secret"


# A column name is a label: short, no punctuation soup, not a sentence.
_COLUMN_NAME = re.compile(r"^[\w .#/()-]{1,40}$")
_HEADER_ROWS_CHECKED = 200


def _looks_like_a_header(header: list[str]) -> bool:
    """Is this really a header row, or is it prose that happens to have commas?

    A docstring opening "What the user asked for, turned into things that can be
    checked" was read as a CSV header, which turned every following line of that
    file into a credential. A header is several short labels, and the rows below
    it agree on how many there are.
    """

    fields = [name.strip() for name in header]
    if len(fields) < 2 or any(not name for name in fields):
        return False
    if not all(_COLUMN_NAME.match(name) for name in fields):
        return False
    return all(len(name.split()) <= 4 for name in fields)


def _hint_columns(header: list[str]) -> list[int]:
    """Columns whose *name* carries a credential word, token by token."""

    found: list[int] = []
    for index, name in enumerate(header):
        tokens = [part for part in re.split(r"[^A-Za-z0-9]+", name.casefold()) if part]
        if any(hint in token for token in tokens for hint in _COLUMN_HINTS):
            found.append(index)
    return found


def _csv_column_findings(text: str) -> list[JuicyFinding]:
    """Credential-named CSV columns (password, api_key, …) even without key=value."""

    sample = text.lstrip()[:4_000]
    if "," not in sample.split("\n", 1)[0]:
        return []
    try:
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        rows = [row for _index, row in zip(range(_HEADER_ROWS_CHECKED), reader)]
    except (csv.Error, StopIteration):
        return []
    if not _looks_like_a_header(header) or not rows:
        return []
    # Rows in a table agree with their header on how many columns there are;
    # lines of source code split on commas do not.
    width = len(header)
    if sum(1 for row in rows if len(row) == width) < max(1, int(len(rows) * 0.8)):
        return []
    indexes = _hint_columns(header)
    if not indexes:
        return []
    offset = 0
    # Approximate line starts so "where" can still say a row number.
    findings: list[JuicyFinding] = []
    line = 2
    for row in rows:
        for index in indexes:
            if index >= len(row):
                continue
            value = (row[index] or "").strip()
            if not value or _is_placeholder(value):
                continue
            kind, category = _column_kind(header[index])
            packet = native_id(row, header, _PACKET_HEADERS)
            native_item = native_id(row, header, _ITEM_HEADERS)
            findings.append(JuicyFinding(
                kind, value, offset, offset + len(value), line, "high", category,
                packet=packet, item=native_item,
            ))
        line += 1
    return findings


_PACKET_HEADERS = (
    "packet", "no.", "frame.number", "frame_number", "frame number", "frame.no",
)
_ITEM_HEADERS = (
    "item", "itemid", "item_id", "burp_id", "messageid", "message_id", "message id",
)
_BURP_ITEM_TAG = re.compile(r"<(item|issue)\b", re.IGNORECASE)


def parse_native_int(value: object) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    if text.isdigit():
        return int(text)
    try:
        return int(float(text))
    except ValueError:
        return 0


def native_id(row: list[str], header: list[str], names: tuple[str, ...]) -> int:
    wanted = {name.casefold() for name in names}
    for index, column in enumerate(header):
        if column.casefold().strip() not in wanted or index >= len(row):
            continue
        number = parse_native_int(row[index])
        if number:
            return number
    return 0


def _csv_native_header(sample: str) -> list[str]:
    first = (sample or "").lstrip().split("\n", 1)[0]
    if "," not in first and "\t" not in first:
        return []
    try:
        row = next(csv.reader([first]))
    except (csv.Error, StopIteration):
        return []
    names = {name.casefold().strip() for name in row}
    known = set(_PACKET_HEADERS) | set(_ITEM_HEADERS)
    if names & known:
        return row
    if "no" in names and {"time", "source", "destination", "protocol"} <= names:
        return row
    return []


def looks_like_burp_export(source: str, sample: str) -> bool:
    head = (sample or "")[:16_000].casefold()
    if "burpversion" in head or "<!doctype items" in head:
        return True
    folded = (source or "").casefold()
    if "burp" in folded and ("<item" in head or "<issue" in head):
        return True
    if folded.endswith((".xml", ".xml.gz")) and "<items" in head and "<item" in head:
        return True
    return False


def _line_as_csv_row(text: str, start: int) -> list[str]:
    line_start = text.rfind("\n", 0, max(start, 0)) + 1
    line_end = text.find("\n", max(start, 0))
    if line_end < 0:
        line_end = len(text)
    try:
        return next(csv.reader([text[line_start:line_end]]))
    except (csv.Error, StopIteration):
        return []


class NativeIdTracker:
    """Stamp Wireshark packet / Burp item numbers onto findings as text is streamed."""

    def __init__(self, source: str = "") -> None:
        self.source = source
        self.mode = ""
        self.header: list[str] = []
        self.tags_before = 0

    def prime(self, sample: str) -> None:
        if self.mode:
            return
        if looks_like_burp_export(self.source, sample):
            self.mode = "burp"
            return
        header = _csv_native_header(sample)
        if header:
            self.mode = "csv"
            self.header = header
            return
        self.mode = "none"

    def locate(self, finding: JuicyFinding, scanned: str) -> JuicyFinding:
        packet, item = finding.packet, finding.item
        if self.mode == "csv" and self.header:
            row = _line_as_csv_row(scanned, finding.start)
            if row:
                packet = packet or native_id(row, self.header, _PACKET_HEADERS + ("no",))
                item = item or native_id(row, self.header, _ITEM_HEADERS)
        elif self.mode == "burp" and not item:
            item = self.tags_before + len(_BURP_ITEM_TAG.findall(scanned[:max(finding.start, 0)]))
        if packet == finding.packet and item == finding.item:
            return finding
        return replace(finding, packet=packet, item=item)

    def advance(self, scanned: str, next_overlap: str) -> None:
        if self.mode != "burp":
            return
        total = self.tags_before + len(_BURP_ITEM_TAG.findall(scanned))
        self.tags_before = max(0, total - len(_BURP_ITEM_TAG.findall(next_overlap)))


def _resolve_overlaps(candidates: list[JuicyFinding]) -> list[JuicyFinding]:
    """Drop competing location spans; keep nested credentials inside URLs."""

    candidates.sort(key=lambda item: (
        item.start, _PRIORITY.get(item.kind, 99), -(item.end - item.start),
    ))
    accepted: list[JuicyFinding] = []
    for finding in candidates:
        overlaps = [old for old in accepted if finding.start < old.end and old.start < finding.end]
        if not overlaps:
            accepted.append(finding)
            continue
        locationish = finding.kind in _LOCATION or finding.kind == "email"
        if locationish:
            # A hostname or email-shaped userinfo inside a URL must not evict the URL.
            if any(old.kind == "url" and old.start <= finding.start and finding.end <= old.end
                   for old in overlaps):
                continue
            if any(_PRIORITY.get(old.kind, 99) <= _PRIORITY.get(finding.kind, 99) for old in overlaps):
                continue
            accepted = [old for old in accepted if old not in overlaps]
            accepted.append(finding)
            continue
        if all(old.kind in _LOCATION or old.kind == "email" for old in overlaps):
            accepted.append(finding)
            continue
        if any(old.kind == finding.kind for old in overlaps):
            continue
        if any(_PRIORITY.get(old.kind, 99) <= _PRIORITY.get(finding.kind, 99) for old in overlaps):
            continue
        accepted = [old for old in accepted if old not in overlaps]
        accepted.append(finding)
    return sorted(accepted, key=lambda item: item.start)


# ---------------------------------------------------------------------------
# Analyst report — compact inventory, exposure once per kind
# ---------------------------------------------------------------------------

_EXPOSURE = {
    "password": "A leaked password is a live login. Rotate it; never store it in pages, URLs, or logs.",
    "username": "Pairs with a password for account takeover. Do not publish staff or customer logins.",
    "secret": "An API key or token acts as the application. Revoke it and keep it off the client.",
    "jwt": "A JWT is a portable session. Anyone holding it is that user until it expires.",
    "bearer": "A Bearer token is a password in transit. Rotate it; never put it in a query string or HTML.",
    "basic-auth": "Basic auth decodes to username:password. Rotate and move to a stronger scheme.",
    "session-cookie": "A session cookie is a stolen-login token. Set Secure + HttpOnly; do not log it.",
    "secret-in-url": "Secrets in URLs land in history, proxies, and Referer. Move them to a header or POST body.",
    "email": "Identifies a person and is enough to phish or trigger a reset. Minimise copies.",
    "indian-phone": "A phone number is a recovery channel. Limit who can export it.",
    "intl-phone": "A phone number is a recovery channel. Limit who can export it.",
    "pan": "PAN is tax identity in India. Restrict access; it is not a public identifier.",
    "aadhaar": "Aadhaar is national identity. Do not store or share the number unless you must.",
    "passport": "A passport number is travel identity. Keep it out of logs and test dumps.",
    "credit-card": "A card number enables fraud. This is PCI data — delete copies you do not need.",
    "iban": "An IBAN can be used for unauthorised transfers. Treat it as financial PII.",
    "upi": "A UPI ID receives payments. Confirm it was meant to be public before leaving it in logs.",
    "bank-account": "An account number is enough to attempt a transfer. Restrict export.",
    "uuid": "May be a guessable account or object id. Confirm it is not an access-control key.",
    "aws-access-key": "Controls cloud resources. Disable this key in IAM now and audit its use.",
    "github-token": "Can push code and read private repos. Revoke it in GitHub settings.",
    "gitlab-token": "Can read or change GitLab projects. Revoke it in GitLab settings.",
    "slack-token": "Can read or post in Slack. Revoke the token or webhook in Slack.",
    "stripe-key": "Can move money or read payments. Roll the key in the Stripe dashboard.",
    "sendgrid-key": "Can send mail as you. Revoke it in SendGrid.",
    "twilio-sid": "Can send SMS or calls as you. Rotate the Twilio credential.",
    "npm-token": "Can publish packages. Revoke it on npmjs.com.",
    "pypi-token": "Can publish packages. Revoke it on PyPI.",
    "google-api-key": "Billed Google APIs and data. Restrict or rotate the key in Cloud Console.",
    "azure-key": "Access to an Azure resource. Rotate the key or SAS in the portal.",
    "private-key": "A private key is identity. Destroy extra copies and rotate the pair; never commit it.",
    "pem-certificate": "A certificate is usually public, but it maps your service. Check it was meant to be here.",
    "ssh-key": "An SSH public key identifies a login. Confirm it belongs on this host.",
    "db-uri": "A database URL with a password is a direct path into data. Rotate the account.",
    "url": "May leak hostnames, tokens, or internal paths. Prefer https and no secrets in the query.",
    "ipv4": "Maps infrastructure. Do not publish admin or internal addresses.",
    "ipv6": "Maps infrastructure. Do not publish admin or internal addresses.",
    "internal-host": "An internal name reveals network layout. Keep it off public pages.",
    "domain": "A hostname can be used for targeting. Confirm it is meant to be public.",
    "insecure-cookie": "A cookie without Secure/HttpOnly can be stolen in transit or by script. Fix the flags.",
    "cors-wildcard": "Any website can read this response. Restrict Access-Control-Allow-Origin.",
    "debug-enabled": "Debug mode leaks internals. Turn it off outside development.",
    "tls-verify-disabled": "Disabled TLS checks allow a proxy to read or alter traffic. Turn verification back on.",
    "unrestricted-bind": "Listening on 0.0.0.0 exposes the port to the network. Bind to localhost if it is local-only.",
    "guessable-id": "Sequential ids are easy to walk. Authorise by session, not by knowing the number.",
    "sql-error": "The database is talking to the client. Hide errors; this is a map for injection.",
    "sql-fragment": "Looks like an injection payload. Confirm whether it was a test or a live attempt.",
    "stack-trace": "A stack trace maps your code and paths. Show a generic error to clients.",
    "xxe": "An XML external entity can read files. Disable external entity resolution.",
    "directory-listing": "A directory index lists files you may not mean to publish. Disable listing.",
    "shell-metachar": "Command characters in a parameter can become RCE if the value is executed. Do not exec it.",
}

_CATEGORY_EXPOSURE = {
    "identity": "Identifies a person. Limit who can see this copy.",
    "financial": "Can be used for fraud. Restrict copies and retention.",
    "authentication": "Lets someone act as a user. Rotate and keep it off the client.",
    "secret": "Lets someone act as the service. Revoke and rotate.",
    "network": "Maps where systems live. Confirm it should be public.",
    "http": "A weakness in how the HTTP service is configured. Fix the flag or header.",
    "injection": "A signal that input may be executed. Do not run it; log and review.",
    "config": "An unsafe setting. Turn the dangerous option off.",
}

_TALLY_COLOR = {
    "critical": PALETTE.juicy_secret,
    "high": PALETTE.juicy_auth,
    "medium": PALETTE.juicy_id,
    "low": PALETTE.muted,
}


def kind_category(kind: str) -> str:
    return _KIND_CATEGORY.get(kind, "")


def exposure_note(kind: str, category: str = "") -> str:
    """One-line, defensive: how this finding can be misused, and what to do."""

    return _EXPOSURE.get(kind) or _CATEGORY_EXPOSURE.get(category or kind_category(kind), (
        "Sensitive if exposed. Confirm who can read this copy and whether it should exist."
    ))


def format_juicy_report(
    rows: list[tuple[str, str, str, str]],
    *,
    title: str = "JUICY",
    how: str = "",
    enabled: bool | None = None,
) -> str:
    """Compact inventory: one line per finding, exposure once per kind.

    Each row is (where, kind, value, confidence). Values are never masked.
    """

    if enabled is None:
        enabled = color_enabled()
    counts = {level: 0 for level in CONFIDENCE_LEVELS}
    by_kind: dict[str, list[tuple[str, str, str]]] = {}
    for where, kind, value, confidence in rows:
        counts[confidence] = counts.get(confidence, 0) + 1
        by_kind.setdefault(kind, []).append((where, value, confidence))

    lines: list[str] = []
    subtitle = f" · {how}" if how else ""
    lines.append(paint(
        f"{title}{subtitle} · {len(rows):,} finding(s) · not redacted",
        PALETTE.violet + PALETTE.bold, enabled=enabled,
    ))
    tally = "   ".join(
        paint(f"{level} {counts.get(level, 0)}",
              _TALLY_COLOR.get(level, PALETTE.muted)
              + (PALETTE.bold if counts.get(level, 0) else ""),
              enabled=enabled)
        for level in CONFIDENCE_LEVELS
    )
    lines.append("  " + tally)
    if not rows:
        lines.append(paint("  No juicy values.", PALETTE.muted, enabled=enabled))
        return "\n".join(lines)

    kind_order: list[str] = []
    seen_kind: set[str] = set()
    for family in ("secret", "authentication", "identity", "financial", "network",
                   "http", "injection", "config"):
        for kind, bucket in by_kind.items():
            if kind in seen_kind:
                continue
            if kind_category(kind) != family:
                continue
            kind_order.append(kind)
            seen_kind.add(kind)
    for kind in by_kind:
        if kind not in seen_kind:
            kind_order.append(kind)

    for kind in kind_order:
        bucket = by_kind[kind]
        bucket.sort(key=lambda item: (-_RANK.get(item[2], 0), item[0], item[1]))
        family = kind_category(kind)
        top = max(bucket, key=lambda item: _RANK.get(item[2], 0))[2]
        lines.append("")
        heading = f"{kind.upper()}  ·  {len(bucket)}  ·  {top}"
        lines.append(paint(heading, juicy_ansi(kind, family, top) + PALETTE.bold, enabled=enabled))
        lines.append(paint(f"  {exposure_note(kind, family)}", PALETTE.muted, enabled=enabled))
        value_width = min(56, max(8, max(len(item[1]) for item in bucket)))
        for where, value, confidence in bucket:
            shown = paint(value, juicy_ansi(kind, family, confidence), enabled=enabled)
            pad = value_width - len(value)
            place = where.strip() or "—"
            conf = paint(f"{confidence:<8}", juicy_ansi(kind, family, confidence), enabled=enabled)
            lines.append(f"  {conf} {shown}{' ' * max(1, pad)}  {paint(place, PALETTE.dim + PALETTE.muted, enabled=enabled)}")
    return "\n".join(lines)
