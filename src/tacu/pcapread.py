"""Stream libpcap and pcapng captures into one row per packet.

Only the standard library is used. Frames are decoded far enough to name
addresses, ports, and a short info line — enough to filter a capture the way
Wireshark's packet list is used, without holding the file in memory.
"""

from __future__ import annotations

import gzip
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator

from .core import TacuError

# Classic pcap magics: (endian, timestamp scale).
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_MAX_PACKET = 256 * 1024

_ETH = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
    0x88CC: "LLDP",
}
_IP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
}
_TCP_FLAGS = (
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
    (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"),
)
_HTTP_START = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ",
               b"OPTIONS ", b"CONNECT ", b"HTTP/1.")


def is_pcap_magic(head: bytes) -> bool:
    return len(head) >= 4 and (head[:4] in _PCAP_MAGIC or head[:4] == _PCAPNG_SHB)


def open_capture(path: Path) -> BinaryIO:
    handle = path.open("rb")
    magic = handle.read(2)
    handle.seek(0)
    if magic == b"\x1f\x8b":
        handle.close()
        return gzip.open(path, "rb")
    return handle


def iter_packets(path: Path) -> Iterator[dict[str, object]]:
    """Yield one dict per packet, in capture order."""

    with open_capture(path) as handle:
        head = handle.read(4)
        if len(head) < 4:
            raise TacuError(f"{path.name} is too small to be a capture.")
        handle.seek(0)
        if head == _PCAPNG_SHB:
            yield from _read_pcapng(handle)
            return
        if head in _PCAP_MAGIC:
            yield from _read_pcap(handle)
            return
        raise TacuError(
            f"{path.name} is not a libpcap or pcapng capture. "
            "Export from Wireshark as .pcap or .pcapng."
        )


def _read_pcap(handle: BinaryIO) -> Iterator[dict[str, object]]:
    magic = handle.read(4)
    endian, scale = _PCAP_MAGIC[magic]
    header = handle.read(20)
    if len(header) < 20:
        raise TacuError("Capture global header is truncated.")
    _major, _minor, _zone, _sig, _snap, network = struct.unpack(f"{endian}HHiIII", header)
    index = 0
    while True:
        pkt_header = handle.read(16)
        if not pkt_header:
            return
        if len(pkt_header) < 16:
            return
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_header)
        if incl_len > _MAX_PACKET:
            handle.seek(incl_len, 1)
            continue
        frame = handle.read(incl_len)
        if len(frame) < incl_len:
            return
        index += 1
        seconds = ts_sec + (ts_frac / scale if scale else 0)
        yield _decode_frame(index, seconds, orig_len, len(frame), frame, linktype=network)


def iter_enriched_packets(path: Path) -> Iterator[dict[str, object]]:
    """Two-pass: learn names from this capture, then tag every packet's IPs.

    Names come only from DNS answers, TLS SNI, and HTTP Host inside the file.
    Nothing is looked up on the network.
    """

    binds: dict[str, list[str]] = {}
    cnames: dict[str, str] = {}
    for row in iter_packets(path):
        _collect_names(row, binds, cnames)
    _apply_cnames(binds, cnames)
    lookup = {ip: _join_names(names) for ip, names in binds.items() if names}
    for row in iter_packets(path):
        row.pop("_names", None)
        row.pop("_cnames", None)
        src = str(row.get("src") or "")
        dst = str(row.get("dst") or "")
        row["src_name"] = lookup.get(src, "")
        row["dst_name"] = lookup.get(dst, "")
        row["sni"] = row.get("sni") or ""
        row["http_host"] = row.get("http_host") or ""
        yield row


def _collect_names(row: dict[str, object], binds: dict[str, list[str]],
                   cnames: dict[str, str]) -> None:
    for ip, name in row.get("_names") or ():
        _bind(binds, str(ip), str(name))
    for owner, target in row.get("_cnames") or ():
        _note_cname(cnames, str(owner), str(target))
    host = str(row.get("http_host") or row.get("sni") or "")
    dst = str(row.get("dst") or "")
    if host and dst:
        _bind(binds, dst, host)


def _bind(binds: dict[str, list[str]], ip: str, name: str) -> None:
    name = name.strip().rstrip(".").casefold()
    if not ip or not name or name == "localhost":
        return
    known = binds.setdefault(ip, [])
    if name not in known:
        known.append(name)


def _note_cname(cnames: dict[str, str], owner: str, target: str) -> None:
    owner = owner.strip().rstrip(".").casefold()
    target = target.strip().rstrip(".").casefold()
    if owner and target and owner != target:
        cnames[owner] = target


def _apply_cnames(binds: dict[str, list[str]], cnames: dict[str, str]) -> None:
    """If a CNAME target has an IP, also tag that IP with the names that alias it."""

    reverse: dict[str, list[str]] = {}
    for owner, target in cnames.items():
        reverse.setdefault(target, []).append(owner)
    if not reverse:
        return
    for names in binds.values():
        extra: list[str] = []
        seen = set(names)
        stack = list(names)
        while stack:
            name = stack.pop()
            for alias in reverse.get(name, ()):
                if alias not in seen:
                    seen.add(alias)
                    extra.append(alias)
                    stack.append(alias)
        names.extend(extra)


def _join_names(names: list[str]) -> str:
    return ", ".join(names)


def _read_pcapng(handle: BinaryIO) -> Iterator[dict[str, object]]:
    endian = "<"
    interfaces: dict[int, tuple[int, int]] = {}
    interface_seq = 0
    index = 0
    while True:
        prefix = handle.read(8)
        if not prefix:
            return
        if len(prefix) < 8:
            return
        block_type, length = struct.unpack(f"{endian}II", prefix)
        if prefix[:4] == _PCAPNG_SHB:
            bom = handle.read(4)
            if len(bom) < 4:
                return
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                endian = "<"
            length = struct.unpack(f"{endian}I", prefix[4:8])[0]
            remaining = max(0, length - 12)
            leftover = handle.read(remaining)
            if len(leftover) < remaining:
                return
            continue
        rest_len = max(0, length - 8)
        body = handle.read(rest_len)
        if len(body) < rest_len:
            return
        payload = body[:-4] if rest_len >= 4 else body
        if block_type == 1:
            if len(payload) < 8:
                continue
            linktype, _reserved, snaplen = struct.unpack(f"{endian}HHI", payload[:8])
            del snaplen
            resolution = 6
            options = payload[8:]
            pos = 0
            while pos + 4 <= len(options):
                opt_code, opt_len = struct.unpack(f"{endian}HH", options[pos:pos + 4])
                pos += 4
                if opt_code == 0:
                    break
                data = options[pos:pos + opt_len]
                pos += (opt_len + 3) & ~3
                if opt_code == 9 and data:
                    resolution = data[0]
            interfaces[interface_seq] = (linktype, resolution)
            interface_seq += 1
        elif block_type == 6 and len(payload) >= 20:
            iface, ts_hi, ts_lo, caplen, origlen = struct.unpack(f"{endian}IIIII", payload[:20])
            if caplen > _MAX_PACKET:
                continue
            frame = payload[20:20 + caplen]
            linktype, resol = interfaces.get(iface, (1, 6))
            ticks = (ts_hi << 32) | ts_lo
            if resol >= 128:
                scale = 2 ** (resol & 0x7F)
            else:
                scale = 10 ** (resol & 0x7F)
            seconds = ticks / scale if scale else float(ticks)
            index += 1
            yield _decode_frame(index, seconds, origlen, len(frame), frame, linktype=linktype)
        elif block_type == 3 and len(payload) >= 4:
            origlen = struct.unpack(f"{endian}I", payload[:4])[0]
            frame = payload[4:4 + min(origlen, max(0, len(payload) - 4))]
            linktype, _resol = interfaces.get(0, (1, 6))
            index += 1
            yield _decode_frame(index, 0.0, origlen, len(frame), frame, linktype=linktype)


def _decode_frame(index: int, seconds: float, orig_len: int, captured: int,
                  frame: bytes, *, linktype: int) -> dict[str, object]:
    parsed = _parse_link(frame, linktype)
    when = ""
    if seconds:
        when = datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    row: dict[str, object] = {
        "packet": index,
        "time": when,
        "seconds": round(seconds, 6) if seconds else None,
        "length": orig_len,
        "captured": captured,
        "src_mac": parsed.get("src_mac"),
        "dst_mac": parsed.get("dst_mac"),
        "ethertype": parsed.get("ethertype"),
        "src": parsed.get("src"),
        "dst": parsed.get("dst"),
        "src_name": "",
        "dst_name": "",
        "protocol": parsed.get("protocol"),
        "src_port": parsed.get("src_port"),
        "dst_port": parsed.get("dst_port"),
        "info": parsed.get("info"),
        "sni": parsed.get("sni") or "",
        "http_host": parsed.get("http_host") or "",
    }
    names = parsed.get("_names")
    if names:
        row["_names"] = names
    aliases = parsed.get("_cnames")
    if aliases:
        row["_cnames"] = aliases
    return row


def _parse_link(frame: bytes, linktype: int) -> dict[str, object]:
    if linktype == 1:
        return _ethernet(frame)
    if linktype == 113:
        return _linux_sll(frame)
    if linktype in {0, 108}:
        return _null_loopback(frame)
    if linktype in {12, 14, 101, 228, 229}:
        return _ip_payload(frame, {})
    return _ethernet(frame) if len(frame) >= 14 else _ip_payload(frame, {})


def _ethernet(frame: bytes) -> dict[str, object]:
    if len(frame) < 14:
        return {}
    dst = _mac(frame[0:6])
    src = _mac(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    payload = frame[14:]
    extra = {"src_mac": src, "dst_mac": dst}
    if ethertype == 0x8100 and len(payload) >= 4:
        ethertype = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]
    extra["ethertype"] = _ETH.get(ethertype, f"0x{ethertype:04x}")
    extra["dst_mac"] = dst
    extra["src_mac"] = src
    if ethertype == 0x0800:
        extra.update(_ipv4(payload, extra))
    elif ethertype == 0x86DD:
        extra.update(_ipv6(payload, extra))
    elif ethertype == 0x0806:
        extra.update(_arp(payload, extra))
    else:
        extra.setdefault("protocol", extra["ethertype"])
    return extra


def _linux_sll(frame: bytes) -> dict[str, object]:
    if len(frame) < 16:
        return {}
    protocol = struct.unpack("!H", frame[14:16])[0]
    extra = {"ethertype": _ETH.get(protocol, f"0x{protocol:04x}")}
    return _ethertype_payload(protocol, frame[16:], extra)


def _null_loopback(frame: bytes) -> dict[str, object]:
    if len(frame) < 4:
        return {}
    family = struct.unpack("<I", frame[:4])[0]
    if family in {24, 28, 30, 10}:
        return _ipv6(frame[4:], {})
    return _ipv4(frame[4:], {})


def _ethertype_payload(ethertype: int, payload: bytes, extra: dict[str, object]) -> dict[str, object]:
    if ethertype == 0x0800:
        extra.update(_ipv4(payload, extra))
    elif ethertype == 0x86DD:
        extra.update(_ipv6(payload, extra))
    elif ethertype == 0x0806:
        extra.update(_arp(payload, extra))
    else:
        extra.setdefault("protocol", extra.get("ethertype"))
    return extra


def _ip_payload(frame: bytes, extra: dict[str, object]) -> dict[str, object]:
    if not frame:
        return extra
    version = frame[0] >> 4
    if version == 4:
        extra.update(_ipv4(frame, extra))
    elif version == 6:
        extra.update(_ipv6(frame, extra))
    return extra


def _ipv4(payload: bytes, extra: dict[str, object]) -> dict[str, object]:
    if len(payload) < 20:
        return extra
    ihl = (payload[0] & 0x0F) * 4
    if ihl < 20 or len(payload) < ihl:
        return extra
    proto = payload[9]
    extra["src"] = socket.inet_ntoa(payload[12:16])
    extra["dst"] = socket.inet_ntoa(payload[16:20])
    extra["protocol"] = _IP.get(proto, f"IP/{proto}")
    rest = payload[ihl:]
    extra.update(_transport(proto, rest, extra))
    return extra


def _ipv6(payload: bytes, extra: dict[str, object]) -> dict[str, object]:
    if len(payload) < 40:
        return extra
    extra["src"] = socket.inet_ntop(socket.AF_INET6, payload[8:24])
    extra["dst"] = socket.inet_ntop(socket.AF_INET6, payload[24:40])
    nxt = payload[6]
    extra["protocol"] = _IP.get(nxt, f"IPv6/{nxt}")
    extra.update(_transport(nxt, payload[40:], extra))
    extra.setdefault("ethertype", "IPv6")
    return extra


def _arp(payload: bytes, extra: dict[str, object]) -> dict[str, object]:
    extra["protocol"] = "ARP"
    extra["ethertype"] = "ARP"
    if len(payload) < 28:
        return extra
    op = struct.unpack("!H", payload[6:8])[0]
    spa = socket.inet_ntoa(payload[14:18])
    tpa = socket.inet_ntoa(payload[24:28])
    extra["src"] = spa
    extra["dst"] = tpa
    extra["info"] = "who-has " + tpa if op == 1 else "is-at " + spa
    return extra


def _transport(proto: int, rest: bytes, extra: dict[str, object]) -> dict[str, object]:
    if proto == 6:
        return _tcp(rest, extra)
    if proto == 17:
        return _udp(rest, extra)
    if proto == 1:
        extra["info"] = "ICMP"
        extra["protocol"] = "ICMP"
        return extra
    if proto == 58:
        extra["info"] = "ICMPv6"
        extra["protocol"] = "ICMPv6"
        return extra
    return extra


def _tcp(rest: bytes, extra: dict[str, object]) -> dict[str, object]:
    extra["protocol"] = "TCP"
    if len(rest) < 14:
        return extra
    extra["src_port"], extra["dst_port"] = struct.unpack("!HH", rest[0:4])
    offset = ((rest[12] >> 4) & 0x0F) * 4
    flags = rest[13]
    names = [name for bit, name in _TCP_FLAGS if flags & bit]
    extra["info"] = " ".join(names) if names else f"flags=0x{flags:02x}"
    payload = rest[offset:] if offset >= 20 else rest[20:]
    extra.update(_app_payload(extra.get("src_port"), extra.get("dst_port"), payload, extra, tcp=True))
    return extra


def _udp(rest: bytes, extra: dict[str, object]) -> dict[str, object]:
    extra["protocol"] = "UDP"
    if len(rest) < 8:
        return extra
    extra["src_port"], extra["dst_port"] = struct.unpack("!HH", rest[0:4])
    payload = rest[8:]
    extra.update(_app_payload(extra.get("src_port"), extra.get("dst_port"), payload, extra, tcp=False))
    return extra


def _app_payload(src_port: object, dst_port: object, payload: bytes,
                 extra: dict[str, object], *, tcp: bool) -> dict[str, object]:
    ports = {src_port, dst_port}
    if 53 in ports and payload:
        dns = _dns_details(payload, tcp=tcp)
        if dns:
            extra["protocol"] = "DNS"
            extra["info"] = dns["info"]
            extra["_names"] = dns["binds"]
            extra["_cnames"] = dns["cnames"]
            return extra
    if tcp and any(payload.startswith(token) for token in _HTTP_START):
        line = payload.split(b"\r\n", 1)[0][:180].decode("latin-1", errors="replace")
        extra["protocol"] = "HTTP"
        extra["info"] = line
        extra["http_host"] = _http_host(payload)
        return extra
    if tcp:
        sni = _tls_sni(payload)
        if sni:
            extra["sni"] = sni
            extra["info"] = f"{extra.get('info') or ''} SNI {sni}".strip()
            return extra
    if tcp and 443 in ports:
        extra["protocol"] = extra.get("protocol") or "TCP"
        if extra.get("info") and "SYN" not in str(extra.get("info")):
            pass
        elif payload[:1] == b"\x16":
            extra["info"] = ((extra.get("info") or "") + " TLS").strip()
        return extra
    if 67 in ports or 68 in ports:
        extra["protocol"] = "DHCP"
        return extra
    return extra


def _dns_details(payload: bytes, *, tcp: bool) -> dict[str, object] | None:
    if tcp and len(payload) >= 2:
        length = struct.unpack("!H", payload[:2])[0]
        payload = payload[2:2 + length]
    if len(payload) < 12:
        return None
    _ident, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[:12])
    pos = 12
    qname = ""
    binds: list[tuple[str, str]] = []
    cnames: list[tuple[str, str]] = []
    answers: list[str] = []
    try:
        for _ in range(qdcount):
            qname, pos = _dns_read_name(payload, pos)
            pos += 4
        records = ancount + nscount + arcount
        for _ in range(records):
            if pos + 10 > len(payload):
                break
            owner, pos = _dns_read_name(payload, pos)
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", payload[pos:pos + 10])
            pos += 10
            rdata_at = pos
            rdata = payload[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1 and len(rdata) >= 4:
                ip = socket.inet_ntoa(rdata[:4])
                binds.append((ip, owner))
                if qname:
                    binds.append((ip, qname))
                answers.append(f"{owner} A {ip}")
            elif rtype == 28 and len(rdata) >= 16:
                ip = socket.inet_ntop(socket.AF_INET6, rdata[:16])
                binds.append((ip, owner))
                if qname:
                    binds.append((ip, qname))
                answers.append(f"{owner} AAAA {ip}")
            elif rtype == 5:
                cname, _ = _dns_read_name(payload, rdata_at)
                if cname:
                    answers.append(f"{owner} CNAME {cname}")
                    cnames.append((owner, cname))
                    if qname:
                        cnames.append((qname, cname))
    except (struct.error, OSError, ValueError, IndexError):
        if not qname:
            qname = _dns_qname(payload)
    qr = bool(flags & 0x8000)
    info = "; ".join(answers[:12]) if qr and answers else qname
    if not info:
        return None
    return {"info": info, "binds": binds, "cnames": cnames}


def _dns_read_name(payload: bytes, pos: int) -> tuple[str, int]:
    labels: list[str] = []
    end = pos
    jumped = False
    hops = 0
    while pos < len(payload) and hops < 20:
        hops += 1
        length = payload[pos]
        if length == 0:
            if not jumped:
                end = pos + 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(payload):
                break
            pointer = ((length & 0x3F) << 8) | payload[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = pointer
            continue
        if length & 0xC0:
            break
        pos += 1
        if pos + length > len(payload):
            break
        labels.append(payload[pos:pos + length].decode("ascii", errors="replace"))
        pos += length
        if not jumped:
            end = pos
    return ".".join(labels), end


def _dns_qname(payload: bytes) -> str:
    name, _ = _dns_read_name(payload, 12) if len(payload) >= 13 else ("", 0)
    return name


def _http_host(payload: bytes) -> str:
    header = payload.split(b"\r\n\r\n", 1)[0]
    try:
        text = header.decode("latin-1", errors="replace")
    except Exception:
        return ""
    for line in text.split("\r\n")[1:]:
        if line.casefold().startswith("host:"):
            value = line.split(":", 1)[1].strip()
            return value.split("@")[-1].split(":")[0].strip()
    return ""


def _tls_sni(payload: bytes) -> str:
    if len(payload) < 9 or payload[0] != 0x16:
        return ""
    rec_len = struct.unpack("!H", payload[3:5])[0]
    handshake = payload[5:5 + rec_len]
    if len(handshake) < 4 or handshake[0] != 0x01:
        return ""
    body_len = int.from_bytes(handshake[1:4], "big")
    body = handshake[4:4 + body_len]
    if len(body) < 35:
        return ""
    pos = 34
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 2 > len(body):
        return ""
    cipher_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2 + cipher_len
    if pos + 1 > len(body):
        return ""
    comp_len = body[pos]
    pos += 1 + comp_len
    if pos + 2 > len(body):
        return ""
    ext_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    end = min(len(body), pos + ext_len)
    while pos + 4 <= end:
        etype, elen = struct.unpack("!HH", body[pos:pos + 4])
        pos += 4
        data = body[pos:pos + elen]
        pos += elen
        if etype != 0 or len(data) < 5:
            continue
        cursor = 2
        while cursor + 3 <= len(data):
            name_type = data[cursor]
            name_len = struct.unpack("!H", data[cursor + 1:cursor + 3])[0]
            cursor += 3
            raw = data[cursor:cursor + name_len]
            cursor += name_len
            if name_type == 0 and raw:
                return raw.decode("ascii", errors="replace")
    return ""


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)
