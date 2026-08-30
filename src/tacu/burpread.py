"""Burp Suite HTTP history and scanner exports, as one row per item.

Two portable dumps are supported — the same two people actually get out of
Burp without reverse-engineering a project file:

* Native GUI export: Proxy / HTTP history → select items → Save items
  produces XML with base64-encoded request and response.
* Extension / CLI parsers (Montoya project-file parsers, Looking Glass, and
  similar) dump proxy history, site map, and audit items as JSON or NDJSON.

A `.burp` project file is PortSwigger's proprietary store. Opening it needs
Burp itself. TACU will not pretend to parse it; export XML or JSON first.

Live REST / JSON-RPC bridges into a running Burp instance are out of scope:
dump the traffic to a file, then `ti data load` that file.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import re
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlparse, unquote_plus
from xml.etree import ElementTree

from .core import TacuError, detect_juicy, HIGH_JUICY_KINDS

BODY_LIMIT = 256 * 1024
FORM_VALUE_LIMIT = 400
_WRAP_KEYS = (
    "proxyHistory", "proxy_history", "siteMap", "site_map",
    "auditItems", "audit_items", "issues", "items", "history",
)
# Generic JSON often has "items" or "history"; these names are Burp-specific.
_BURP_WRAP_HINTS = (
    "proxyHistory", "proxy_history", "siteMap", "site_map",
    "auditItems", "audit_items",
)
_ITEM_KEYS = {"request", "response", "raw_request", "raw_response"}
_COLUMNS = (
    "item", "burp_id", "source", "time", "url", "method", "host", "host_ip", "port", "protocol", "path",
    "status", "location", "mime", "content_type", "comment", "name", "severity", "confidence",
    "cookie", "set_cookie", "authorization", "query", "form", "juicy",
    "req_headers", "req_body", "res_headers", "res_body",
    "req_bytes", "res_bytes",
)
_INTEREST_FIELDS = ("pass", "user", "email", "token", "auth", "secret", "session", "otp")
_NOISE_FIELDS = frozenset({
    "__viewstate", "__viewstategenerator", "__eventvalidation",
    "__eventtarget", "__eventargument", "__viewstateencrypted",
    "__lastfocus", "__requestverificationtoken",
})
_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_ATTR = re.compile(r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(['"])(.*?)\2""", re.DOTALL)


def looks_like_burp_xml(sample: str) -> bool:
    """True for Burp Save-items / issue XML, regardless of filename or extension."""

    head = sample[:12_000].casefold()
    if "burpversion" in head:
        return True
    if "<!doctype items" in head and "base64" in head and (
            "<!element request" in head or "<!attlist request" in head):
        return True
    if "<items" in head and "<item" in head and ("<request" in head or "<url>" in head):
        return True
    if "<issues" in head and "<issue" in head and (
            "<severity>" in head or "<requestresponse" in head):
        return True
    return False


def looks_like_html(sample: str) -> bool:
    """Saved pages and inspector dumps — not Burp XML, not a generic XML table."""

    head = sample.lstrip()[:4_000].casefold()
    if head.startswith("<!doctype html") or head.startswith("<html"):
        return True
    if "<?xml" in head[:80] and "<html" in head:
        return True
    if "<html" in head[:1_500] and ("<head" in head or "<body" in head):
        return True
    return False


def looks_like_xml(sample: str) -> bool:
    """Generic XML/DOCTYPE, used to keep non-Burp XML off the CSV path."""

    text = sample.lstrip()[:20].casefold()
    return text.startswith("<?xml") or text.startswith("<!doctype")


def looks_like_burp_json(sample: str) -> bool:
    text = sample.lstrip()
    if not text or text[0] not in "{[":
        return False
    low = text[:4_000]
    if any(f'"{key}"' in low for key in _BURP_WRAP_HINTS):
        return True
    value = _first_json_value(text)
    return _value_is_burp(value)


def _first_json_value(text: str) -> Any:
    decoder = json.JSONDecoder()
    try:
        value, _ = decoder.raw_decode(text)
        return value
    except json.JSONDecodeError:
        line = text.split("\n", 1)[0].strip().rstrip(",")
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None


def _value_is_burp(value: Any) -> bool:
    if isinstance(value, dict):
        for key in _WRAP_KEYS:
            nested = value.get(key)
            if isinstance(nested, list) and nested and isinstance(nested[0], dict) and _item_is_burp(nested[0]):
                return True
        return _item_is_burp(value)
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return _item_is_burp(value[0])
    return False


def _item_is_burp(item: dict[str, Any]) -> bool:
    keys = {str(key).casefold() for key in item}
    if "url" not in keys:
        return False
    return bool(keys & {key.casefold() for key in _ITEM_KEYS})


def burp_project_error(path: Path) -> TacuError:
    return TacuError(
        f"{path.name} is a Burp Suite project file, not a table dump. "
        "The .burp format is proprietary and needs Burp itself to open. "
        "Export, then load the export:\n"
        "  In Burp: HTTP history → select items → Save items (XML)\n"
        "  Or dump JSON with a project-file parser / extension, then:\n"
        "  ti data load history.xml\n"
        "  ti data load dump.json"
    )


def iter_burp_xml(path: Path) -> Iterator[dict[str, Any]]:
    handle = gzip.open(path, "rb") if _gzipped(path) else path.open("rb")
    try:
        found = False
        index = 0
        for _event, element in ElementTree.iterparse(handle, events=("end",)):
            tag = element.tag.rsplit("}", 1)[-1]
            if tag == "item":
                found = True
                index += 1
                row = _xml_item(element, source="history")
                row["item"] = index
                row["burp_id"] = (element.get("id") or _child(element, "id")
                                  or _child(element, "number") or "")
                yield row
                element.clear()
            elif tag == "issue":
                found = True
                index += 1
                row = _xml_issue(element)
                row["item"] = index
                row["burp_id"] = (element.get("id") or _child(element, "serialNumber")
                                  or _child(element, "type") or "")
                yield row
                element.clear()
        if not found:
            raise TacuError(
                f"{path.name} is XML but has no Burp <item> or <issue> records. "
                "In Burp, select HTTP history items and Save items."
            )
    except ElementTree.ParseError as error:
        raise TacuError(f"{path.name} is not well-formed Burp XML: {error}") from error
    finally:
        handle.close()


def iter_burp_json_value(value: Any, *, source: str = "",
                         _counter: list[int] | None = None) -> Iterator[dict[str, Any]]:
    if _counter is None:
        _counter = [0]
    if isinstance(value, list):
        for item in value:
            yield from iter_burp_json_value(item, source=source, _counter=_counter)
        return
    if not isinstance(value, dict):
        return
    wrapped = False
    for key in _WRAP_KEYS:
        if key in value and isinstance(value[key], list):
            wrapped = True
            label = {
                "proxyHistory": "history", "proxy_history": "history",
                "siteMap": "sitemap", "site_map": "sitemap",
                "auditItems": "issue", "audit_items": "issue",
                "issues": "issue", "items": "history", "history": "history",
            }.get(key, source or "history")
            for item in value[key]:
                yield from iter_burp_json_value(item, source=label, _counter=_counter)
    if wrapped:
        return
    _counter[0] += 1
    row = _json_item(value, source=source or "history")
    item_no, burp_id = _json_native_ids(value, _counter[0])
    row["item"] = item_no
    if not row.get("burp_id"):
        row["burp_id"] = burp_id
    yield row


def _json_native_ids(item: dict[str, Any], fallback: int) -> tuple[int, str]:
    """Burp JSON may carry a numeric history id; otherwise use 1-based export order."""

    folded = {str(key).casefold(): value for key, value in item.items()}
    burp_id = ""
    for key in ("id", "itemid", "item_id", "number", "messageid", "message_id", "index"):
        raw = folded.get(key)
        if raw is None or isinstance(raw, (dict, list)):
            continue
        text = str(raw).strip()
        if text and not burp_id:
            burp_id = text
        if isinstance(raw, bool):
            continue
        if isinstance(raw, int) and raw > 0:
            return raw, burp_id or str(raw)
        if text.isdigit():
            return int(text), burp_id
    return fallback, burp_id


def _gzipped(path: Path) -> bool:
    with path.open("rb") as handle:
        return handle.read(2) == b"\x1f\x8b"


def _xml_item(element: ElementTree.Element, *, source: str) -> dict[str, Any]:
    request = _xml_message(element.find("request"))
    response = _xml_message(element.find("response"))
    req_headers, req_body = _split_http(request)
    res_headers, res_body = _split_http(response)
    method = _child(element, "method") or _request_method(req_headers)
    status = _child(element, "status") or _response_status(res_headers)
    host_node = element.find("host")
    host = (host_node.text or "").strip() if host_node is not None else ""
    host_ip = (host_node.get("ip") or "").strip() if host_node is not None else ""
    url = _child(element, "url")
    extras = _http_extras(url, req_headers, req_body, res_headers, res_body)
    return _row(
        source=source,
        time=_child(element, "time"),
        url=url,
        method=method,
        host=host,
        host_ip=host_ip,
        port=_child(element, "port"),
        protocol=_child(element, "protocol"),
        path=_child(element, "path") or _url_path(url),
        status=status,
        mime=_child(element, "mimetype"),
        comment=_child(element, "comment"),
        req_headers=req_headers,
        req_body=req_body,
        res_headers=res_headers,
        res_body=res_body,
        req_bytes=len(request.encode("utf-8")),
        res_bytes=len(response.encode("utf-8")),
        **extras,
    )


def _xml_issue(element: ElementTree.Element) -> dict[str, Any]:
    pair = element.find("requestresponse")
    request = _xml_message(None if pair is None else pair.find("request"))
    response = _xml_message(None if pair is None else pair.find("response"))
    req_headers, req_body = _split_http(request)
    res_headers, res_body = _split_http(response)
    host = _child(element, "host")
    path = _child(element, "path") or _child(element, "location")
    url = _child(element, "url") or (host + path if host and path else host or path)
    extras = _http_extras(url, req_headers, req_body, res_headers, res_body)
    return _row(
        source="issue",
        time="",
        url=url,
        method=_request_method(req_headers),
        host=host,
        port="",
        protocol="",
        path=path,
        status=_response_status(res_headers),
        mime="",
        comment=_child(element, "issueDetail") or _child(element, "issueBackground"),
        name=_child(element, "name"),
        severity=_child(element, "severity"),
        confidence=_child(element, "confidence"),
        req_headers=req_headers,
        req_body=req_body,
        res_headers=res_headers,
        res_body=res_body,
        req_bytes=len(request.encode("utf-8")),
        res_bytes=len(response.encode("utf-8")),
        **extras,
    )


def _json_item(item: dict[str, Any], *, source: str) -> dict[str, Any]:
    folded = {str(key).casefold(): value for key, value in item.items()}
    request = _message_from_json(folded, ("request", "raw_request", "httprequest"))
    response = _message_from_json(folded, ("response", "raw_response", "httpresponse"))
    req_headers, req_body = _split_http(request)
    res_headers, res_body = _split_http(response)
    if not req_headers:
        req_headers = _as_text(folded.get("request.headers") or folded.get("req_headers"))
    if not req_body:
        req_body = _as_text(folded.get("request.body") or folded.get("req_body"))
    if not res_headers:
        res_headers = _as_text(folded.get("response.headers") or folded.get("res_headers")
                               or folded.get("header"))
    if not res_body:
        res_body = _as_text(folded.get("response.body") or folded.get("res_body"))
    url = _as_text(folded.get("url"))
    extras = _http_extras(url, req_headers, req_body, res_headers, res_body)
    return _row(
        source=_as_text(folded.get("source")) or source,
        time=_as_text(folded.get("time") or folded.get("timestamp")),
        url=url,
        method=_as_text(folded.get("method")) or _request_method(req_headers),
        host=_as_text(folded.get("host")),
        host_ip=_as_text(folded.get("host_ip") or folded.get("ip") or folded.get("host.ip")),
        port=_as_text(folded.get("port")),
        protocol=_as_text(folded.get("protocol")),
        path=_as_text(folded.get("path")) or _url_path(url),
        status=_as_text(folded.get("status") or folded.get("statuscode"))
        or _response_status(res_headers),
        mime=_as_text(folded.get("mimetype") or folded.get("mime") or folded.get("contenttype")),
        comment=_as_text(folded.get("comment") or folded.get("issuedetail")),
        name=_as_text(folded.get("name") or folded.get("issuename")),
        severity=_as_text(folded.get("severity")),
        confidence=_as_text(folded.get("confidence")),
        req_headers=req_headers,
        req_body=req_body,
        res_headers=res_headers,
        res_body=res_body,
        req_bytes=len(request.encode("utf-8")) if request else len(req_body.encode("utf-8")),
        res_bytes=len(response.encode("utf-8")) if response else len(res_body.encode("utf-8")),
        **extras,
    )


def _message_from_json(folded: dict[str, Any], names: tuple[str, ...]) -> str:
    for name in names:
        if name not in folded:
            continue
        value = folded[name]
        if isinstance(value, dict):
            headers = _as_text(value.get("headers") or value.get("header"))
            body = _as_text(value.get("body") or value.get("content"))
            if headers and body:
                return headers + "\r\n\r\n" + body
            return headers or body
        text = _maybe_b64(_as_text(value))
        if text:
            return text
    return ""


def _xml_message(node: ElementTree.Element | None) -> str:
    if node is None:
        return ""
    raw = "".join(node.itertext()).strip()
    if not raw:
        return ""
    flag = (node.get("base64") or "").strip().casefold()
    if flag in {"true", "1", "yes"}:
        return _b64(raw)
    return _maybe_b64(raw)


def _b64(raw: str) -> str:
    compact = re.sub(r"\s+", "", raw)
    if not compact:
        return ""
    padded = compact + ("=" * ((4 - len(compact) % 4) % 4))
    try:
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        return raw


def _maybe_b64(text: str) -> str:
    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 16 and re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        decoded = _b64(compact)
        if decoded and decoded != compact and ("HTTP/" in decoded[:80] or "\r\n" in decoded[:200]):
            return decoded
    return text


def _child(element: ElementTree.Element, tag: str) -> str:
    node = element.find(tag)
    if node is None:
        return ""
    return (node.text or "").strip()


def _split_http(message: str) -> tuple[str, str]:
    if not message:
        return "", ""
    if "\r\n\r\n" in message:
        headers, body = message.split("\r\n\r\n", 1)
    elif "\n\n" in message:
        headers, body = message.split("\n\n", 1)
    else:
        return message, ""
    return headers, body


def _http_extras(url: str, req_headers: str, req_body: str,
                 res_headers: str, res_body: str) -> dict[str, str]:
    """Pull cookies, form fields, and juicy values out of the decoded HTTP."""

    content_type = _header(req_headers, "content-type")
    cookie = _header(req_headers, "cookie")
    authorization = _header(req_headers, "authorization")
    set_cookie = _header(res_headers, "set-cookie")
    location = _header(res_headers, "location")
    query = urlparse(url).query
    form = _join_fields(_form_pairs(req_body, content_type) + _html_inputs(res_body))
    # Do not scan raw Cookie values: session blobs (Gmail NID/SID) drown real findings.
    scan = "\n".join(part for part in (url, location, authorization, query, form) if part)
    findings = [item for item in detect_juicy(scan) if item.kind in HIGH_JUICY_KINDS]
    juicy_parts = [f"{item.kind}={item.value}" for item in findings[:40]]
    for key, value in _interest_pairs(form):
        mark = f"{key}={value}"
        if mark not in juicy_parts:
            juicy_parts.append(mark)
    juicy = "; ".join(juicy_parts[:40])
    return {
        "content_type": content_type.split(";", 1)[0].strip(),
        "cookie": cookie,
        "set_cookie": set_cookie,
        "authorization": authorization,
        "location": location,
        "query": unquote_plus(query) if query else "",
        "form": form,
        "juicy": juicy,
    }


def _header(headers: str, name: str) -> str:
    want = name.casefold()
    values: list[str] = []
    for line in headers.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().casefold() == want:
            values.append(value.strip())
    return "; ".join(values)


def _form_pairs(body: str, content_type: str) -> list[tuple[str, str]]:
    if not body or not body.strip():
        return []
    kind = content_type.casefold()
    if "json" in kind:
        return _json_pairs(body)
    if "multipart" in kind:
        return []
    stripped = body.strip()
    if stripped[:1] in "{[":
        return _json_pairs(body)
    if "=" not in body:
        return []
    try:
        parsed = parse_qsl(body, keep_blank_values=True, max_num_fields=300)
    except ValueError:
        return []
    return [(key, value) for key, value in parsed if not _noise_field(key)]


def _json_pairs(body: str) -> list[tuple[str, str]]:
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, dict):
        return [("json", body[:FORM_VALUE_LIMIT])]
    pairs = []
    for key, item in list(value.items())[:80]:
        text = json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list)) else str(item)
        if not _noise_field(str(key)):
            pairs.append((str(key), text))
    return pairs


def _html_inputs(html: str) -> list[tuple[str, str]]:
    if "<input" not in html.casefold():
        return []
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for tag in _INPUT_TAG.findall(html):
        attrs = {key.casefold(): value for key, _quote, value in _ATTR.findall(tag)}
        name = attrs.get("name") or ""
        value = attrs.get("value") or ""
        if not name or not value or _noise_field(name) or name.casefold() in seen:
            continue
        seen.add(name.casefold())
        pairs.append((name, value))
    return pairs


def _noise_field(name: str) -> bool:
    return name.casefold().strip() in _NOISE_FIELDS


def _interest_pairs(form: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if not form:
        return pairs
    for item in form.split("; "):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if not value:
            continue
        folded = key.casefold()
        if any(word in folded for word in _INTEREST_FIELDS):
            pairs.append((key, value))
    return pairs


def _join_fields(pairs: list[tuple[str, str]]) -> str:
    parts: list[str] = []
    seen: set[str] = set()
    for key, value in pairs:
        mark = key.casefold()
        if mark in seen:
            continue
        seen.add(mark)
        clip = value if len(value) <= FORM_VALUE_LIMIT else value[:FORM_VALUE_LIMIT] + "…"
        parts.append(f"{key}={clip}")
        if len(parts) >= 40:
            break
    return "; ".join(parts)


def _request_method(headers: str) -> str:
    first = headers.split("\n", 1)[0].strip()
    if not first:
        return ""
    return first.split(" ", 1)[0].upper()


def _response_status(headers: str) -> str:
    first = headers.split("\n", 1)[0].strip()
    parts = first.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return parts[1]
    return ""


def _url_path(url: str) -> str:
    if "://" not in url:
        return url
    rest = url.split("://", 1)[1]
    slash = rest.find("/")
    return rest[slash:] if slash >= 0 else "/"


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def _clip(text: str) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= BODY_LIMIT:
        return text
    return encoded[:BODY_LIMIT].decode("utf-8", errors="ignore") + "…"


def _row(**fields: Any) -> dict[str, Any]:
    row = {column: "" for column in _COLUMNS}
    text_fields = {
        "req_headers", "req_body", "res_headers", "res_body",
        "form", "juicy", "cookie", "set_cookie", "authorization", "query", "location",
    }
    for key, value in fields.items():
        if key in text_fields:
            row[key] = _clip(str(value or ""))
        elif key == "item":
            try:
                row[key] = int(value) if value not in (None, "") else 0
            except (TypeError, ValueError):
                row[key] = 0
        elif key in row:
            row[key] = value if value is not None else ""
    return row
