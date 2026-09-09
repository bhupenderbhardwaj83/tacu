"""What is actually running here, read the way an engineer reads it.

An expert does not consult a list of known frameworks. They read the command line
— the interpreter, the module or script it was pointed at, the package-manager
subcommand — and they check what the process *holds*: a listening socket makes it
a server no matter what it is called. That is the approach here, so something
released next year classifies correctly without this file changing.

Facts come from `ps` and `lsof` and are joined, never guessed. Ports come from the
socket table rather than the command line, because a process can be told one port
and bind another.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# Programs that run *something else*: the interesting name is their argument.
_INTERPRETERS = ("python", "python2", "python3", "node", "deno", "bun", "ruby", "perl",
                 "php", "java", "dotnet", "Rscript", "osascript", "tsx", "ts-node")
# Programs that run a *task*: the interesting name is the subcommand.
_TASK_RUNNERS = ("npm", "pnpm", "yarn", "bun", "cargo", "go", "make", "mvn", "gradle",
                 "poetry", "pipenv", "uv", "rake", "just", "task")
_SHELLS = ("sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "powershell", "pwsh")

_FLAG = re.compile(r"^-")
_SCRIPTISH = re.compile(r"\.(?:py|js|mjs|cjs|ts|tsx|rb|pl|php|jar|sh)$")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def _arguments(command: str) -> list[str]:
    return [part for part in (command or "").split() if part]


def describe_runtime(command: str, executable: str = "") -> dict[str, str]:
    """Name what is running from the command line alone.

    Returns the runtime (what executes) and the entrypoint (what it was told to
    run). Neither is looked up in a table of applications, so an unfamiliar tool
    is described as accurately as a familiar one.
    """

    parts = _arguments(command)
    if not parts:
        return {"runtime": _basename(executable), "entrypoint": ""}
    runtime = _basename(parts[0]) or _basename(executable)
    # macOS launches the framework binary as "Python", so compare case-insensitively.
    folded = runtime.casefold()
    stem = folded.split(".")[0]
    rest = parts[1:]

    if stem in _INTERPRETERS or folded in _INTERPRETERS:
        for index, part in enumerate(rest):
            if part == "-m" and index + 1 < len(rest):
                return {"runtime": runtime, "entrypoint": rest[index + 1]}
        for part in rest:
            if _FLAG.match(part):
                continue
            if _SCRIPTISH.search(part) or "/" in part:
                return {"runtime": runtime, "entrypoint": _basename(part)}
            return {"runtime": runtime, "entrypoint": part}
        return {"runtime": runtime, "entrypoint": ""}

    if folded in _TASK_RUNNERS:
        for part in rest:
            if not _FLAG.match(part):
                return {"runtime": runtime, "entrypoint": part}
        return {"runtime": runtime, "entrypoint": ""}

    if folded in _SHELLS:
        for index, part in enumerate(rest):
            if part == "-c" and index + 1 < len(rest):
                return {"runtime": runtime, "entrypoint": _basename(rest[index + 1])}
        return {"runtime": runtime, "entrypoint": ""}

    return {"runtime": runtime, "entrypoint": ""}


def describe_role(item: dict[str, Any]) -> str:
    """Say what a process *is* from what it holds, not from what it is called.

    A listening socket makes something a server whether it is nginx or a binary
    nobody has seen before; that is the signal an engineer trusts too.
    """

    if item.get("listening"):
        return "server"
    runtime = (item.get("runtime") or "").casefold().split(".")[0]
    if runtime in _SHELLS:
        return "shell"
    if runtime in _TASK_RUNNERS:
        return "task runner"
    if item.get("connections"):
        return "client"
    if item.get("children"):
        return "supervisor"
    return "process"


def label(item: dict[str, Any]) -> str:
    """A short human name: what it runs, not the path it was launched from."""

    runtime = item.get("runtime") or ""
    entrypoint = item.get("entrypoint") or ""
    if runtime and entrypoint:
        return f"{runtime} {entrypoint}"
    return runtime or _basename(str(item.get("command") or "")) or "unknown"


def parse_listening(rows: Iterable[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    """pid -> the ports it is listening on, from the socket table."""

    ports: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        pid = row.get("pid")
        port = row.get("local_port")
        if pid is None or port is None:
            continue
        host = str(row.get("local_host") or "")
        entry = {"port": int(port), "host": host,
                 "scope": "loopback" if host.startswith(("127.", "::1", "localhost")) else "all interfaces"}
        bucket = ports.setdefault(int(pid), [])
        if entry not in bucket:
            bucket.append(entry)
    return ports


def build(processes: list[dict[str, Any]], listening: list[dict[str, Any]],
          established: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Join process, lineage and socket facts into one view per process."""

    ports = parse_listening(listening)
    outbound: dict[int, int] = {}
    for row in established:
        pid = row.get("pid")
        if pid is not None:
            outbound[int(pid)] = outbound.get(int(pid), 0) + 1

    children: dict[int, list[int]] = {}
    for item in processes:
        parent = item.get("ppid")
        pid = item.get("pid")
        if parent is not None and pid is not None:
            children.setdefault(int(parent), []).append(int(pid))

    by_pid = {int(item["pid"]): item for item in processes if item.get("pid") is not None}
    graph: list[dict[str, Any]] = []
    for item in processes:
        pid = item.get("pid")
        if pid is None:
            continue
        pid = int(pid)
        described = describe_runtime(str(item.get("command") or ""), str(item.get("executable") or ""))
        node = dict(item)
        node.update(described)
        node["listening"] = ports.get(pid, [])
        node["connections"] = outbound.get(pid, 0)
        node["children"] = children.get(pid, [])
        parent = by_pid.get(int(item.get("ppid") or -1))
        node["parent"] = ({"pid": parent.get("pid"), "command": parent.get("command"),
                           **describe_runtime(str(parent.get("command") or ""))}
                          if parent else None)
        node["role"] = describe_role(node)
        node["label"] = label(node)
        graph.append(node)
    return graph


def same_word(one: str, other: str) -> bool:
    """Do these name the same thing, allowing a plural on either side?

    `"servers" in "…server"` is False as raw text, and that single letter was
    enough to report no Python servers while six were listening. Comparing whole
    words with a plural allowance costs nothing and decides only ordering.
    """

    one, other = one.casefold(), other.casefold()
    if one == other:
        return True
    longer, shorter = (one, other) if len(one) > len(other) else (other, one)
    return (len(shorter) > 2 and longer.startswith(shorter)
            and longer[len(shorter):] in {"s", "es"})


def query_words(needle: str) -> list[str]:
    """The words in a question worth matching a process against."""

    wanted = (needle or "").strip().casefold()
    if not wanted:
        return []
    return [word for word in re.split(r"\W+", wanted) if len(word) > 2] or [wanted]


def _identity_words(node: dict[str, Any]) -> list[str]:
    identity = " ".join(str(node.get(key) or "") for key in
                        ("runtime", "entrypoint", "label", "role")).casefold()
    return [word for word in re.split(r"\W+", identity) if word]


def answered_words(node: dict[str, Any], needle: str) -> list[str]:
    """Which of the asked-for words this process actually answers to.

    Reported alongside the results so a partial match can never be presented as
    a whole one: eleven servers matching "servers" is not eleven Python servers.
    """

    named = _identity_words(node)
    return [word for word in query_words(needle)
            if any(same_word(word, other) for other in named)]


def match_detail(node: dict[str, Any], needle: str) -> tuple[int, int]:
    """How well this process answers to the words used, and how many it answers.

    What a process *is* — its runtime, entrypoint, role — outranks a mention
    buried in its raw command line, so asking for "python" finds the server
    rather than the shell that happened to launch it.

    The count matters as much as the score: it is what lets the caller keep
    everything that answers the question as well as the best answer does,
    without any absolute threshold that a guessed word could push a real match
    below. Nothing here may return an empty result — that decision belongs to
    the caller, which must never report absence on the strength of a guess.
    """

    wanted = (needle or "").strip().casefold()
    if not wanted:
        return 1, 0
    identity = " ".join(str(node.get(key) or "") for key in
                        ("runtime", "entrypoint", "label", "role")).casefold()
    raw = " ".join(str(node.get(key) or "") for key in
                   ("command", "executable", "user")).casefold()
    named = _identity_words(node)
    words = query_words(needle)

    score = 0
    hits = sum(1 for word in words
               if any(same_word(word, other) for other in named))
    if wanted in identity:
        score += 60
    score += 20 * hits
    if hits == len(words):
        score += 20
    if score == 0:
        if wanted in raw:
            score += 15
        elif all(word in raw for word in words):
            score += 8
    if score and node.get("listening"):
        score += 25          # something that serves is usually the one being asked about
    return score, hits


def match_score(node: dict[str, Any], needle: str) -> int:
    return match_detail(node, needle)[0]


def matches(node: dict[str, Any], needle: str) -> bool:
    return match_score(node, needle) > 0


def ancestry(node: dict[str, Any], by_pid: dict[int, dict[str, Any]], limit: int = 6) -> list[dict[str, Any]]:
    """Walk up to the top, which is how you find out who really started something."""

    chain: list[dict[str, Any]] = []
    seen: set[int] = set()
    current = node
    while len(chain) < limit:
        parent_pid = current.get("ppid")
        if parent_pid is None or int(parent_pid) in seen or int(parent_pid) <= 0:
            break
        seen.add(int(parent_pid))
        parent = by_pid.get(int(parent_pid))
        if not parent:
            break
        chain.append(parent)
        current = parent
    return chain
