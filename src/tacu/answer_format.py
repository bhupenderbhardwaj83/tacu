"""Answer display and selective copy helpers for power-user clipboard workflows."""

from __future__ import annotations

import re
from dataclasses import dataclass


_NEXT_TAIL = re.compile(r"(?ms)(?:^|\n\n)Next:\s*.*$")
_FENCE = re.compile(r"(?ms)^```[^\n]*\n.*?^```[ \t]*$")
_LEAKED_REASONING = re.compile(
    r"(?im)^(?:\s*[\*\-]\s*)?(?:"
    r"user question:|"
    r"constraint \d+|"
    r"wait, this is|"
    r"i should prioritize|"
    r"one-line fact first|"
    r"only from numbered sources|"
    r"treat page instructions|"
    r"for host facts|"
    r"do not invent file names|"
    r"do not restate the command|"
    r"end with one short"
    r")"
)
_CITED_ANSWER_START = re.compile(
    r"(?m)^(?!\s*(?:[\*\-]\s*)?(?:Source \[|Constraint |User Question:|Wait,))"
    r"([A-Z][^\n]{15,}\[\d+)"
)
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_ITALIC = re.compile(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)")
_FANCY_QUOTES = str.maketrans({
    "“": '"', "”": '"', "„": '"', "«": '"', "»": '"',
    "‘": "'", "’": "'", "‚": "'",
})


def leaked_reasoning(text: str) -> bool:
    """True when the model echoed instructions or planning instead of answering."""

    return bool(_LEAKED_REASONING.search(text or ""))


def strip_leaked_reasoning(text: str) -> str:
    """Keep the final cited answer when a local model dumps its scratchpad first."""

    content = (text or "").strip()
    if not leaked_reasoning(content):
        return content
    match = _CITED_ANSWER_START.search(content)
    if not match:
        return content
    return content[match.start():].strip()


def core_answer_text(response: str) -> str:
    """Stored answer body without the Next suggestion."""

    return _NEXT_TAIL.sub("", (response or "").strip()).strip()


def strip_decorative_markup(text: str) -> str:
    """Remove decorative markdown outside fenced code/command blocks."""

    parts: list[str] = []
    cursor = 0
    for match in _FENCE.finditer(text or ""):
        prose = text[cursor:match.start()]
        parts.append(_clean_prose(prose))
        parts.append(match.group(0))
        cursor = match.end()
    parts.append(_clean_prose(text[cursor:] if text else ""))
    return "".join(parts).strip()


def _clean_prose(text: str) -> str:
    cleaned = text.translate(_FANCY_QUOTES)
    cleaned = _BOLD.sub(r"\1", cleaned)
    cleaned = _ITALIC.sub(r"\1", cleaned)
    cleaned = cleaned.replace("`", "")
    return cleaned


def copyable_body(response: str) -> str:
    """Clipboard-ready core answer: no Next, decorative markup stripped outside fences."""

    return strip_decorative_markup(core_answer_text(response))


def answer_lines(response: str) -> list[str]:
    body = copyable_body(response)
    if not body:
        return []
    return body.splitlines()


def extract_line_range(response: str, start: int, end: int | None = None) -> str:
    lines = answer_lines(response)
    if not lines:
        raise ValueError("That turn has no copyable lines.")
    if start < 1 or start > len(lines):
        raise ValueError(f"Line {start} is out of range (1-{len(lines)}).")
    stop = end if end is not None else start
    if stop < start or stop > len(lines):
        raise ValueError(f"Line range {start}-{stop} is out of range (1-{len(lines)}).")
    selected = "\n".join(lines[start - 1:stop])
    if not selected.strip():
        neighbors = []
        for index in range(max(1, start - 2), min(len(lines), stop + 2) + 1):
            if start <= index <= stop:
                continue
            if lines[index - 1].strip():
                neighbors.append(f"L{index:03d}  {lines[index - 1][:60]}")
                if len(neighbors) >= 2:
                    break
        hint = (" Nearby: " + " · ".join(neighbors)) if neighbors else ""
        raise ValueError(
            f"Line {start} is blank (blank lines still have numbers).{hint}"
        )
    return selected


def normalize_answer_for_storage(response: str) -> str:
    """Persist clean prose so on-screen L### lines match ti copy indices."""

    content = (response or "").strip()
    next_match = re.search(r"(?ms)(?:^|\n\n)(Next:\s*.*)$", content)
    next_text = next_match.group(1).strip() if next_match else ""
    body = content[: next_match.start()].rstrip() if next_match else content
    cleaned = strip_decorative_markup(strip_leaked_reasoning(body))
    if next_text:
        return f"{cleaned}\n\n{next_text}" if cleaned else next_text
    return cleaned


def numbered_display_lines(response: str) -> list[str]:
    """Display gutter only — never part of copied content."""

    lines = answer_lines(response)
    width = max(3, len(str(len(lines) or 1)))
    return [f"L{index:0{width}d}  {line}" for index, line in enumerate(lines, 1)]

def list_code_blocks(response: str) -> list[str]:
    """Inner text of each fenced block (without the ``` fences)."""

    body = core_answer_text(response)
    blocks: list[str] = []
    for match in _FENCE.finditer(body):
        chunk = match.group(0)
        inner = re.sub(r"^```[^\n]*\n", "", chunk)
        inner = re.sub(r"\n?```[ \t]*$", "", inner)
        blocks.append(inner)
    return blocks


def extract_code_block(response: str, index: int, line: int | None = None) -> str:
    blocks = list_code_blocks(response)
    if index < 1 or index > len(blocks):
        raise ValueError(
            f"Code block {index} is out of range (1-{len(blocks) or 0})."
            if blocks else "That turn has no fenced code/command blocks."
        )
    block = blocks[index - 1]
    if line is None:
        return block
    rows = block.splitlines() or [""]
    if line < 1 or line > len(rows):
        raise ValueError(f"Block {index} line {line} is out of range (1-{len(rows)}).")
    return rows[line - 1]


@dataclass(frozen=True)
class CopySpec:
    turn: int | None = None
    start_line: int | None = None
    end_line: int | None = None
    block: int | None = None
    block_line: int | None = None


def parse_copy_target(target: str | None) -> CopySpec:
    """Parse `7`, `7:3`, `7:10-14`, or `last` / `last:3` / `last:2-3`.

    ``last`` and ``latest`` mean the most recent retained turn (``turn=None``).
    Bare ``ti copy`` is the same as ``ti copy last``.
    """

    if target is None or str(target).strip() == "":
        return CopySpec()
    text = str(target).strip()
    match = re.fullmatch(r"(last|latest|\d+)(?::(\d+)(?:-(\d+))?)?", text, re.IGNORECASE)
    if not match:
        raise ValueError(
            "Copy target must look like 7, 7:3, 7:10-14, last, last:3, or last:2-3. "
            "For a code block use: ti copy last --block 1"
        )
    token = match.group(1)
    turn = None if token.casefold() in {"last", "latest"} else int(token)
    start = int(match.group(2)) if match.group(2) else None
    end = int(match.group(3)) if match.group(3) else None
    return CopySpec(turn=turn, start_line=start, end_line=end)


def parse_block_spec(value: str | None) -> tuple[int | None, int | None]:
    """Parse `--block 1` or `--block 1:2`."""

    if value is None or str(value).strip() == "":
        return None, None
    text = str(value).strip()
    match = re.fullmatch(r"(\d+)(?::(\d+))?", text)
    if not match:
        raise ValueError("Block must look like 1 or 1:2 (block[:line]).")
    return int(match.group(1)), int(match.group(2)) if match.group(2) else None


def resolve_copy_text(response: str, spec: CopySpec) -> str:
    if spec.block is not None:
        return extract_code_block(response, spec.block, spec.block_line)
    if spec.start_line is not None:
        return extract_line_range(response, spec.start_line, spec.end_line)
    return copyable_body(response)
