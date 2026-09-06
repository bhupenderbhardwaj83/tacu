"""What the user asked for, turned into things that can be checked.

"Done" is usually treated as "the last command exited zero", which is why a request
for an index file was satisfied by a Flask app that would not even start. A request
carries claims — a kind of file, a name, a behaviour — and most of them can be
checked without asking anyone's opinion.

Every criterion here is decided by looking at the workspace, never by judgement. A
claim that cannot be checked that way is not invented; it is simply not claimed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Words that name the artefact a request is about.
_KIND_WORDS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("html", (".html", ".htm"), "an HTML page"),
    ("web page", (".html", ".htm"), "an HTML page"),
    ("index file", (".html", ".htm"), "an index page"),
    ("index page", (".html", ".htm"), "an index page"),
    ("stylesheet", (".css",), "a stylesheet"),
    ("shell script", (".sh",), "a shell script"),
    ("bash script", (".sh",), "a shell script"),
    ("python script", (".py",), "a Python script"),
    ("dockerfile", ("dockerfile",), "a Dockerfile"),
)
# "ensure index.html is the default page" asks for the same file as "create
# index.html". Leaving these verbs out meant the request carried no checkable
# claim, so the run reported success having produced nothing.
_CREATES = re.compile(
    r"\b(?:create|creates|creating|make|makes|making|write|writes|writing|generate|"
    r"generates|generating|build|builds|building|add|adds|adding|produce|produces|"
    r"ensure|ensures|ensuring|set ?up|scaffold|serve|start|run)\b", re.I)
_NAMED_FILE = re.compile(r"\b([\w.-]+\.(?:html?|py|js|ts|css|sh|json|ya?ml|toml|md|txt))\b", re.I)
_SERVE_WORDS = re.compile(r"\b(?:serve|server|http|https|listen|port)\b", re.I)


@dataclass(frozen=True)
class Criterion:
    """One checkable claim, phrased the way the user would recognise it."""

    describes: str
    kind: str
    detail: str = ""


def _named_files(intent: str) -> list[str]:
    return [match.group(1) for match in _NAMED_FILE.finditer(intent or "")]


def _wanted_kind(intent: str) -> tuple[tuple[str, ...], str] | None:
    lowered = (intent or "").casefold()
    for phrase, suffixes, described in _KIND_WORDS:
        if phrase in lowered:
            return suffixes, described
    return None


def criteria_for(intent: str) -> list[Criterion]:
    """The checkable claims in a request. Empty when nothing can be checked."""

    if not _CREATES.search(intent or ""):
        return []
    claims: list[Criterion] = []
    named = _named_files(intent)
    for name in named:
        claims.append(Criterion(f"{name} exists", "file_exists", name))
    kind = _wanted_kind(intent)
    if kind and not named:
        suffixes, described = kind
        claims.append(Criterion(f"the workspace contains {described}", "file_of_kind",
                                json.dumps(list(suffixes))))
    for name in named:
        if name.casefold().endswith((".py", ".sh", ".html", ".htm", ".json")):
            claims.append(Criterion(f"{name} is well formed", "parses", name))
    claims.extend(_behaviour_claims(intent, named, kind))
    return claims


# Behaviour a request describes, and the mark it leaves in the artefact. Only
# claims that can be settled by reading the file belong here.
_BEHAVIOURS: tuple[tuple[re.Pattern[str], str, tuple[str, ...], tuple[str, ...]], ...] = (
    (re.compile(r"(?i)\b(?:tak(?:e|es|ing)|accept(?:s|ing)?|ask(?:s|ing)?|enter(?:s|ing)?|"
                r"input|prompt(?:s|ing)?|read(?:s|ing)?)\b.{0,40}"
                r"\b(?:input|name|username|user|value|text)\b"),
     "collects input from the user",
     (".html", ".htm"), ("<input", "<form", "<textarea", "prompt(")),
    (re.compile(r"(?i)\b(?:greet(?:s|ing)?|hello|welcome|hi\b)"),
     "greets the user",
     (".html", ".htm", ".py", ".js"), ("hello", "welcome", "greet", "hi ")),
    (re.compile(r"(?i)\bbutton\b"),
     "has a button",
     (".html", ".htm"), ("<button", "type=\"submit\"", "type='submit'")),
)


def _behaviour_claims(intent: str, named: list[str],
                      kind: tuple[tuple[str, ...], str] | None) -> list[Criterion]:
    suffixes = list(kind[0]) if kind else []
    for name in named:
        suffix = Path(name).suffix.casefold()
        if suffix and suffix not in suffixes:
            suffixes.append(suffix)
    claims: list[Criterion] = []
    for pattern, describes, applies_to, markers in _BEHAVIOURS:
        if not pattern.search(intent or ""):
            continue
        if not any(suffix in applies_to for suffix in suffixes):
            continue
        claims.append(Criterion(f"it {describes}", "contains_any",
                                json.dumps({"suffixes": suffixes, "markers": list(markers)})))
    return claims


def _files_of_kind(workspace: Path, suffixes: list[str]) -> list[Path]:
    found: list[Path] = []
    try:
        for item in workspace.iterdir():
            if not item.is_file():
                continue
            name = item.name.casefold()
            if any(name.endswith(suffix) or name == suffix for suffix in suffixes):
                found.append(item)
    except OSError:
        return []
    return found


def _parses(path: Path) -> tuple[bool, str]:
    """Is this file syntactically sound? Only for kinds we can check honestly."""

    suffix = path.suffix.casefold()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return False, str(error)
    if suffix == ".py":
        try:
            compile(text, str(path), "exec")
        except SyntaxError as error:
            return False, f"line {error.lineno}: {error.msg}"
        return True, ""
    if suffix == ".json":
        try:
            json.loads(text)
        except ValueError as error:
            return False, str(error)
        return True, ""
    if suffix in {".html", ".htm"}:
        lowered = text.casefold()
        if "<html" in lowered or "<!doctype html" in lowered or "<body" in lowered:
            return True, ""
        return False, "no <html>, <!doctype html> or <body> element"
    return True, ""


def check(criteria: list[Criterion], workspace: Path) -> list[tuple[Criterion, bool, str]]:
    """Decide each claim by looking, and say why when one fails."""

    outcome: list[tuple[Criterion, bool, str]] = []
    for item in criteria:
        if item.kind == "file_exists":
            target = workspace / item.detail
            outcome.append((item, target.is_file(), "" if target.is_file() else "not found"))
        elif item.kind == "file_of_kind":
            suffixes = json.loads(item.detail)
            found = _files_of_kind(workspace, suffixes)
            outcome.append((item, bool(found),
                            "" if found else f"no {' or '.join(suffixes)} file in the workspace"))
        elif item.kind == "parses":
            target = workspace / item.detail
            if not target.is_file():
                outcome.append((item, False, "not found"))
            else:
                ok, why = _parses(target)
                outcome.append((item, ok, why))
        elif item.kind == "contains_any":
            spec = json.loads(item.detail)
            found = _files_of_kind(workspace, spec["suffixes"])
            hit = False
            for candidate in found:
                try:
                    text = candidate.read_text(encoding="utf-8", errors="replace").casefold()
                except OSError:
                    continue
                if any(marker.casefold() in text for marker in spec["markers"]):
                    hit = True
                    break
            why = "" if hit else ("nothing in the file suggests it: looked for "
                                  + ", ".join(spec["markers"][:3]))
            outcome.append((item, hit, why))
        else:
            outcome.append((item, True, ""))
    return outcome


def unmet(criteria: list[Criterion], workspace: Path) -> list[tuple[Criterion, str]]:
    return [(item, why) for item, met, why in check(criteria, workspace) if not met]


def summarise(results: list[tuple[Criterion, bool, str]]) -> str:
    """A short report the user can read, listing what was and was not achieved."""

    if not results:
        return ""
    lines: list[str] = []
    for item, met, why in results:
        mark = "met" if met else "not met"
        suffix = f" — {why}" if why and not met else ""
        lines.append(f"  [{mark}] {item.describes}{suffix}")
    return "\n".join(lines)
