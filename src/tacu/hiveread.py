"""Walk a Windows registry hive into one row per value.

The on-disk format (`regf` / `hbin` / `nk` / `vk`) is documented. Hive copies
from `config\\RegBack`, a `.bak` next to SYSTEM/SOFTWARE, or a restore-point
snapshot are the same file. The System Restore catalog itself is not a hive.

Only the standard library is used. The file is memory-mapped and walked from
the root key; values are yielded as they are found.
"""

from __future__ import annotations

import mmap
import struct
from pathlib import Path
from typing import Iterator

from .core import TacuError

HBIN_START = 0x1000
NONE = 0xFFFFFFFF

_TYPE_NAME = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}

KEY_COMP_NAME = 0x0020
VK_COMP_NAME = 0x0001
VK_DATA_IN_OFFSET = 0x80000000


def is_registry_hive(head: bytes) -> bool:
    return len(head) >= 4 and head[:4] == b"regf"


def iter_registry_values(path: Path) -> Iterator[dict[str, object]]:
    """Yield one dict per value: key, name, type, data."""

    size = path.stat().st_size
    if size < HBIN_START + 0x20:
        raise TacuError(f"{path.name} is too small to be a registry hive.")
    with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        if mm[:4] != b"regf":
            raise TacuError(f"{path.name} is not a Windows registry hive (missing regf header).")
        root = struct.unpack_from("<I", mm, 0x24)[0]
        seen: set[int] = set()
        yield from _walk_key(mm, root, "", seen)


def _walk_key(mm: mmap.mmap, offset: int, parent: str, seen: set[int]) -> Iterator[dict[str, object]]:
    if offset in (NONE, 0) or offset in seen:
        return
    seen.add(offset)
    cell = _cell(mm, offset)
    if cell is None or cell[0:2] != b"nk":
        return
    flags = struct.unpack_from("<H", cell, 2)[0]
    name_len = struct.unpack_from("<H", cell, 72)[0]
    raw_name = bytes(cell[76:76 + name_len])
    name = _decode_name(raw_name, ascii_name=bool(flags & KEY_COMP_NAME))
    path = name if not parent else f"{parent}\\{name}"

    value_count, value_list = struct.unpack_from("<II", cell, 36)
    if value_count and value_list not in (NONE, 0):
        yield from _values(mm, path, value_list, value_count)

    subkey_count = struct.unpack_from("<I", cell, 20)[0]
    subkey_list = struct.unpack_from("<I", cell, 28)[0]
    if subkey_count and subkey_list not in (NONE, 0):
        for child in _subkeys(mm, subkey_list):
            yield from _walk_key(mm, child, path, seen)


def _values(mm: mmap.mmap, key: str, list_offset: int, count: int) -> Iterator[dict[str, object]]:
    cell = _cell(mm, list_offset)
    if cell is None:
        return
    # Value list is a packed array of uint32 offsets; no signature.
    available = len(cell) // 4
    for index in range(min(count, available)):
        vk_off = struct.unpack_from("<I", cell, index * 4)[0]
        row = _value(mm, key, vk_off)
        if row is not None:
            yield row


def _value(mm: mmap.mmap, key: str, offset: int) -> dict[str, object] | None:
    cell = _cell(mm, offset)
    if cell is None or cell[0:2] != b"vk":
        return None
    name_len, data_len, data_off, kind, flags = struct.unpack_from("<HIIIH", cell, 2)
    raw_name = bytes(cell[20:20 + name_len]) if name_len else b""
    name = _decode_name(raw_name, ascii_name=bool(flags & VK_COMP_NAME)) or "(Default)"
    data = _value_data(mm, data_len, data_off, kind)
    return {"key": key, "name": name, "type": _TYPE_NAME.get(kind, f"REG_{kind}"), "data": data}


def _value_data(mm: mmap.mmap, data_len: int, data_off: int, kind: int) -> str:
    inline = bool(data_len & VK_DATA_IN_OFFSET)
    length = data_len & 0x7FFFFFFF
    if inline:
        raw = struct.pack("<I", data_off)[:length]
    else:
        raw = _read_data(mm, data_off, length)
    return _format_data(raw, kind)


def _read_data(mm: mmap.mmap, offset: int, length: int) -> bytes:
    cell = _cell(mm, offset)
    if cell is None:
        return b""
    if cell[0:2] == b"db":
        return _big_data(mm, cell, length)
    return bytes(cell[:length])


def _big_data(mm: mmap.mmap, cell: memoryview, length: int) -> bytes:
    if len(cell) < 4:
        return b""
    count = struct.unpack_from("<H", cell, 2)[0]
    parts: list[bytes] = []
    remaining = length
    for index in range(count):
        pos = 4 + index * 4
        if pos + 4 > len(cell) or remaining <= 0:
            break
        piece_off = struct.unpack_from("<I", cell, pos)[0]
        piece = _cell(mm, piece_off)
        if piece is None:
            break
        take = min(len(piece), remaining)
        parts.append(bytes(piece[:take]))
        remaining -= take
    return b"".join(parts)


def _subkeys(mm: mmap.mmap, offset: int) -> list[int]:
    cell = _cell(mm, offset)
    if cell is None or len(cell) < 4:
        return []
    kind = bytes(cell[0:2])
    count = struct.unpack_from("<H", cell, 2)[0]
    if kind in {b"lf", b"lh"}:
        return [
            struct.unpack_from("<I", cell, 4 + index * 8)[0]
            for index in range(count)
            if 4 + index * 8 + 4 <= len(cell)
        ]
    if kind == b"li":
        return [
            struct.unpack_from("<I", cell, 4 + index * 4)[0]
            for index in range(count)
            if 4 + index * 4 + 4 <= len(cell)
        ]
    if kind == b"ri":
        found: list[int] = []
        for index in range(count):
            pos = 4 + index * 4
            if pos + 4 > len(cell):
                break
            found.extend(_subkeys(mm, struct.unpack_from("<I", cell, pos)[0]))
        return found
    return []


def _cell(mm: mmap.mmap, offset: int) -> memoryview | None:
    if offset in (NONE, 0):
        return None
    abs_off = HBIN_START + offset
    if abs_off + 4 > len(mm):
        return None
    size = struct.unpack_from("<i", mm, abs_off)[0]
    length = abs(size)
    if length < 8 or abs_off + length > len(mm):
        return None
    # Skip the size field; remaining bytes are the cell body.
    return memoryview(mm)[abs_off + 4:abs_off + length]


def _decode_name(raw: bytes, *, ascii_name: bool) -> str:
    raw = raw.rstrip(b"\x00")
    if not raw:
        return ""
    if ascii_name:
        return raw.decode("latin-1", errors="replace")
    return raw.decode("utf-16-le", errors="replace")


def _format_data(raw: bytes, kind: int) -> str:
    if kind in {1, 2, 6}:  # SZ, EXPAND_SZ, LINK
        text = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        return text
    if kind == 7:  # MULTI_SZ
        text = raw.decode("utf-16-le", errors="replace")
        parts = [part for part in text.split("\x00") if part]
        return " | ".join(parts)
    if kind == 4 and len(raw) >= 4:
        return str(struct.unpack_from("<I", raw)[0])
    if kind == 5 and len(raw) >= 4:
        return str(struct.unpack_from(">I", raw)[0])
    if kind == 11 and len(raw) >= 8:
        return str(struct.unpack_from("<Q", raw)[0])
    if not raw:
        return ""
    preview = raw[:80]
    printable = sum(1 for byte in preview if 32 <= byte <= 126)
    if printable / len(preview) >= 0.85 and b"\x00" not in preview[:16]:
        return preview.decode("latin-1", errors="replace") + ("…" if len(raw) > 80 else "")
    return preview.hex() + ("…" if len(raw) > 80 else "")
