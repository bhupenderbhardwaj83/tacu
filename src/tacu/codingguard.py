"""What the coding lane refuses to let happen.

Three rules, each one a failure seen in practice:

  A shell command must not rewrite source. `echo … > app.py` and `sed -i` skip
  the edit tools, so nothing checks the result, nothing records a diff, and a
  file can be replaced by a stub without anything noticing.

  The job is not finished while the code is unproven. Marking every task done
  after changing files, without running anything, is how "I created the files"
  becomes the answer to "make it work".

  A file must be read before it is edited. An edit whose target string was
  guessed fails, and the guesses that do land are the ones that corrupt a file.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

SOURCE_SUFFIXES = (".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go",
                   ".rs", ".rb", ".php", ".java", ".kt", ".c", ".h", ".cpp", ".hpp",
                   ".cs", ".swift", ".sh", ".sql", ".html", ".css", ".json", ".yaml",
                   ".yml", ".toml", ".vue", ".svelte")
_SUFFIX_GROUP = "|".join(suffix.lstrip(".") for suffix in SOURCE_SUFFIXES)

# Shell that writes to a source file instead of editing it.
_SHELL_WRITES_SOURCE = (
    re.compile(rf"(?i)>>?\s*\S*\.(?:{_SUFFIX_GROUP})\b"),
    re.compile(r"(?i)\bsed\s+(?:-\w*\s+)*-i\b|\bsed\s+-i\b"),
    re.compile(rf"(?i)\b(?:rm|mv|cp)\s+(?:-\w+\s+)*\S*\.(?:{_SUFFIX_GROUP})\b"),
    re.compile(rf"(?i)\btee\s+\S*\.(?:{_SUFFIX_GROUP})\b"),
    re.compile(r"(?i)\btruncate\b|\bdd\s+of="),
)
SHELL_WRITE_REFUSAL = (
    "The shell may not write to source files. Use edit_file for a change to an "
    "existing file, or write_file for a new one — those record what changed and "
    "can be undone. Keep the shell for running tests, linters and builds."
)
UNVERIFIED_REFUSAL = (
    "Not yet. You changed {files} and nothing has been run since. Run the tests, "
    "or diagnostics if there are no tests, and get a clean result. Then mark the "
    "list complete."
)
UNREAD_EDIT_REFUSAL = (
    "Read {path} before editing it. An edit whose target text was guessed either "
    "fails or replaces the wrong thing."
)

MUTATING_TOOLS = frozenset({"edit_file", "write_file"})
VERIFYING_TOOLS = frozenset({"run_tests", "diagnostics", "verify"})
_TEST_COMMAND = re.compile(
    r"(?i)\b(?:pytest|unittest|nose|tox|jest|vitest|mocha|cargo\s+test|go\s+test|"
    r"npm\s+(?:test|run\s+test)|pnpm\s+test|yarn\s+test|make\s+(?:test|check)|"
    r"ruff|flake8|mypy|pyright|tsc|eslint)\b")


def shell_writes_source(command: str) -> bool:
    """Would this shell command change a source file behind the edit tools' back?"""

    text = command or ""
    return any(pattern.search(text) for pattern in _SHELL_WRITES_SOURCE)


def command_verifies(command: str) -> bool:
    """Is this shell command a test, a linter, or a type check?"""

    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if not parts:
        return False
    binary, args = Path(parts[0]).name, parts[1:]
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", binary):
        return len(args) >= 2 and args[0] == "-m" and args[1] in {"pytest", "unittest"}
    if binary in {"pytest", "ruff", "flake8", "mypy", "pyright", "tsc", "eslint", "jest", "vitest", "mocha", "tox", "nose"}:
        return True
    return ((binary in {"cargo", "go", "npm", "pnpm", "yarn"} and args[:1] == ["test"])
            or (binary == "npm" and args[:2] == ["run", "test"])
            or (binary == "make" and args[:1] in (["test"], ["check"])))


def wants_server(goal: str) -> bool:
    return bool(re.search(r"\b(?:run|start|serve|launch)\b", goal, re.I)
                and re.search(r"\b(?:server|website|web\s*page|flask)\b", goal, re.I)
                and not (re.search(r"\btests?\b", goal, re.I)
                         and not re.search(r"\b(?:access|browse|listen|server)\b", goal, re.I)))


@dataclass
class CodingGuard:
    """Tracks what the run has changed and what it has proved."""

    workspace: Path
    mutated: set[str] = field(default_factory=set)
    read: set[str] = field(default_factory=set)
    verified: bool = False
    last_check: str = ""
    last_check_failed: bool = False
    require_service: bool = False
    services: dict[str, str] = field(default_factory=dict)

    def _key(self, path: str | None) -> str:
        text = (path or "").strip()
        if not text:
            return ""
        candidate = Path(text)
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        try:
            return candidate.resolve().relative_to(self.workspace.resolve()).as_posix()
        except (OSError, ValueError):
            return text

    def refuse_before(self, tool: str, arguments: dict) -> str | None:
        """The reason this call must not run, or None to let it through."""

        if tool == "shell":
            parts = [str(arguments.get("executable") or "")]
            parts.extend(str(item) for item in (arguments.get("args") or []))
            if shell_writes_source(" ".join(parts)):
                return SHELL_WRITE_REFUSAL
        if tool == "edit_file":
            key = self._key(arguments.get("path"))
            if key and key not in self.read:
                return UNREAD_EDIT_REFUSAL.format(path=key)
        return None

    def observe(self, tool: str, arguments: dict, result: dict) -> None:
        """Update what is changed and what is proved, from what actually ran."""

        failed = (result.get("status") == "error" or int(result.get("exit_code") or 0) != 0
                  or result.get("passed") is False)
        if tool == "read_file" and not failed:
            self.read.add(self._key(arguments.get("path")))
            return
        if tool in MUTATING_TOOLS and not failed:
            if tool == "edit_file" and result.get("changed") is False:
                return
            self.mutated.add(self._key(arguments.get("path")))
            # A change since the last clean run makes that run stale.
            self.verified = False
            self.services.clear()
            if tool == "write_file":
                # Writing a file is also having seen it.
                self.read.add(self._key(arguments.get("path")))
            return
        if tool in VERIFYING_TOOLS:
            if tool == "diagnostics":
                failed = failed or bool(result.get("count")) or not result.get("files_checked")
            if tool == "verify":
                failed = failed or result.get("passed") is not True or result.get("exit_code") != 0
            self.last_check = tool
            self.last_check_failed = failed
            self.verified = not failed
            return
        if tool == "shell":
            parts = [str(arguments.get("executable") or "")]
            parts.extend(str(item) for item in (arguments.get("args") or []))
            if command_verifies(" ".join(parts)):
                self.last_check = " ".join(parts)[:60]
                self.last_check_failed = failed
                self.verified = not failed
        if tool == "service_process":
            service_id = str(result.get("service_id") or arguments.get("service_id") or "")
            if arguments.get("operation") in {"start", "check"}:
                if result.get("healthy") is True and not failed:
                    self.services[service_id] = str(result.get("url") or "")
                    if self.require_service:
                        self.verified = True
                        self.last_check = "HTTP " + self.services[service_id]
                else:
                    self.services.pop(service_id, None)
            elif arguments.get("operation") == "stop":
                self.services.pop(service_id, None)

    def refuse_completion(self) -> str | None:
        """The reason the job cannot be called finished, or None."""

        if self.require_service and not self.services:
            return ("The requested server has not passed an HTTP readiness check since the last edit. "
                    "Use service_process start with a loopback health_url, then check it before finishing.")
        if not self.mutated:
            return None                    # Nothing was changed; nothing to prove.
        if self.verified:
            return None
        if self.last_check and self.last_check_failed:
            return (f"Not yet. {self.last_check} failed after your changes. Fix what it "
                    "reports and run it again until it is clean.")
        return UNVERIFIED_REFUSAL.format(files=", ".join(sorted(self.mutated)[:6]) or "files")
