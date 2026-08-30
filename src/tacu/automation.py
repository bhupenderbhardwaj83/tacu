"""Intent planning and deterministic policy for guided and autonomous execution."""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import TacuError
from .providers import ModelProvider
from .routing import (
    apply_known_file_edit, coding_file_create_spec, connection_state_from_intent, directory_target_from_intent,
    extract_file_delete, extract_file_write, file_edit_target, intent_is_file_edit,
    HOST_MUTATE_KEYS, intent_wants_host_mutate,
    native_inputs_json, native_steps_for_intent, prefers_coding_write, script_body_for_intent,
    search_query_from_intent, wants_content_search,
)

PLANNER_SCHEMA = "tacu.command-plan/v1"
MAX_AUTONOMOUS_STEPS = 5

BLOCKED_EXECUTABLES = {
    "sudo", "su", "doas", "shutdown", "reboot", "halt", "poweroff", "mkfs", "fdisk",
    "diskutil", "dd", "launchctl", "systemctl", "service", "reg", "reg.exe",
    "newfs", "csrutil", "spctl", "nvram",
}
NESTED_SHELLS = {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
SAFE_READ_EXECUTABLES = {
    "ls", "pwd", "whoami", "id", "uname", "date", "stat", "file", "wc", "head", "tail",
    "cat", "find", "rg", "grep", "egrep", "fgrep", "sort", "uniq", "cut", "tr", "du", "df",
    "ps", "pgrep", "lsof", "ifconfig", "ip", "netstat", "ss", "route", "arp", "env", "printenv",
    "which", "where", "where.exe", "realpath", "readlink", "tree", "jq", "yq",
    "dig", "nslookup", "host", "ping", "traceroute", "tracert", "echo", "printf",
    "mdfind", "locate",
}
METADATA_READ_EXECUTABLES = {"ls", "stat", "file", "realpath", "readlink", "find", "tree", "du", "mdfind", "locate"}
NON_RECURSIVE_METADATA_EXECUTABLES = {"ls", "stat", "file", "realpath", "readlink"}
SAFE_WORKSPACE_MUTATIONS = {"mkdir", "touch"}
SAFE_WORKSPACE_RUNNERS = {"python", "python3", "node", "ruby", "perl", "bash", "sh", "zsh"}
NETWORK_TRANSFER_EXECUTABLES = {"curl", "wget", "scp", "sftp", "rsync", "ssh"}
FILESYSTEM_ARGUMENT_EXECUTABLES = {
    "cat", "head", "tail", "less", "stat", "file", "du", "tree", "rm", "rmdir", "mv", "cp",
    "mkdir", "touch", "chmod", "chown", "readlink", "realpath", "tee",
}
CONTENT_READ_EXECUTABLES = {
    "cat", "head", "tail", "less", "rg", "grep", "egrep", "fgrep", "awk", "sed", "jq", "yq",
}
SENSITIVE_FILE_NAMES = {".netrc", ".npmrc", ".pypirc", "credentials", "credentials.json", "config.json"}
PROTECTED_SYSTEM_PARTS = {"system", "usr", "bin", "sbin", "etc", "windows"}
DEVICE_PARTS = {"dev", "boot", "recovery"}
PROMPT_EXECUTABLES = {
    "rm", "rmdir", "mv", "cp", "install", "chmod", "chown", "kill", "killall", "pkill",
    "curl", "wget", "ssh", "scp", "sftp", "rsync", "nmap", "nxc", "netexec", "hydra",
    "docker", "podman", "kubectl", "helm", "brew", "apt", "apt-get", "dnf", "yum", "pacman",
    "pip", "pip3", "npm", "pnpm", "yarn", "cargo", "go", "make", "cmake", "tee",
}
SAFE_GIT_ACTIONS = {"status", "diff", "log", "show", "branch", "rev-parse", "ls-files", "grep"}
SAFE_DOCKER_ACTIONS = {"ps", "inspect", "logs", "images", "stats", "version", "info"}
SENSITIVE_PARTS = {
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".git", ".env", ".netrc",
    "keychain", "credentials", "credential", "secrets", "secret", "id_rsa", "id_ed25519",
    "shadow", "sudoers", "authorized_keys", "known_hosts", "wallet", "keystore",
}
SENSITIVE_ARGUMENTS = re.compile(
    r"(?i)(?:--?(?:password|passwd|token|secret|api[-_]?key|authorization)|bearer\s+|private[-_]?key)"
)
SHELL_OPERATORS = {"|", "||", "&&", ";", ">", ">>", "<", "2>", "2>&1", "$(", "`"}


@dataclass(frozen=True)
class CommandStep:
    executable: str
    args: tuple[str, ...]
    cwd: str
    purpose: str
    native_tool: str | None = None
    native_operation: str | None = None
    native_inputs: str = "{}"

    @property
    def argv(self) -> list[str]:
        return [self.executable, *self.args]

    @property
    def display(self) -> str:
        if self.native_tool and self.native_operation:
            extras = []
            try:
                payload = json.loads(self.native_inputs) if self.native_inputs else {}
            except json.JSONDecodeError:
                payload = {}
            for key, value in payload.items():
                if key == "operation" or value in (None, "", []):
                    continue
                bulky = key in {"content", "old_text", "new_text"} or (
                    isinstance(value, str) and "\n" in value
                )
                extras.append(f"{key}={len(str(value))} bytes" if bulky else f"{key}={value}")
            if self.native_tool in _NO_OPERATION_TOOLS:
                inner = ", ".join(extras) or self.native_operation
            else:
                inner = ", ".join([self.native_operation, *extras])
            return f"{self.native_tool}({inner})"
        return shlex.join(self.argv)

    @property
    def is_native(self) -> bool:
        return bool(self.native_tool and self.native_operation)


@dataclass(frozen=True)
class CommandPlan:
    summary: str
    steps: tuple[CommandStep, ...]
    raw: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    level: str  # allow (green), log (yellow), prompt (orange), block (red)
    reasons: tuple[str, ...]
    action: str = "inspect"
    zones: tuple[str, ...] = ()
    information_risk: str = "normal"

    @property
    def requires_permission(self) -> bool:
        return self.level == "prompt"

    @property
    def autonomous(self) -> bool:
        return self.level in {"allow", "log"}


def computer_search_roots() -> tuple[Path, ...]:
    """Useful metadata-search roots readable as the current user; never filesystem root."""

    candidates = [Path.home()]
    system = platform.system()
    if system == "Darwin":
        candidates.extend((Path("/Applications"), Path("/System/Applications"), Path("/opt"), Path("/usr/local")))
    elif system == "Windows":
        for name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            if os.environ.get(name):
                candidates.append(Path(os.environ[name]))
    else:
        candidates.extend((Path("/opt"), Path("/usr/local")))
    unique: list[Path] = []
    for candidate in candidates:
        resolved = candidate.expanduser().resolve(strict=False)
        if candidate.exists() and resolved not in unique:
            unique.append(resolved)
    return tuple(unique)


def _named_item(intent: str) -> tuple[str, str] | None:
    match = re.search(
        r"(?i)\b(folder|directory|file)\s+(?:named|called)\s+['\"]?([^'\"?/\\]+?)['\"]?(?:\s+(?:on|in|across)\b|\s*$)",
        intent.strip(),
    )
    if not match:
        return None
    kind = "directory" if match.group(1).casefold() in {"folder", "directory"} else "file"
    name = match.group(2).strip()
    return (kind, name) if name and len(name) <= 255 else None


def _adapt_computer_search(step: CommandStep, workspace: Path, intent: str) -> CommandStep:
    """Normalize whole-computer name searches instead of trusting model command syntax."""

    executable = Path(step.executable).name.casefold()
    named = _named_item(intent)
    if named and executable in {"find", "mdfind", "locate"}:
        kind, name = named
        if platform.system() == "Darwin" and shutil.which("mdfind") and "'" not in name and "\\" not in name:
            query = f"kMDItemFSName == '{name}'cd"
            return CommandStep("mdfind", (query,), ".", step.purpose)
        roots = tuple(str(path) for path in computer_search_roots())
        type_letter = "d" if kind == "directory" else "f"
        return CommandStep("find", roots + ("-type", type_letter, "-iname", name), ".", step.purpose)
    if executable == "find" and step.args[:1] == ("/",):
        roots = tuple(str(path) for path in computer_search_roots())
        return CommandStep(step.executable, roots + step.args[1:], ".", step.purpose)
    if executable in {"mdfind", "locate"}:
        return CommandStep(step.executable, step.args, ".", step.purpose)
    return step


def environment_snapshot(workspace: Path) -> dict[str, Any]:
    candidates = sorted(SAFE_READ_EXECUTABLES | SAFE_WORKSPACE_MUTATIONS | PROMPT_EXECUTABLES | {"git"})
    return {
        "os": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "shell": Path(os.environ.get("SHELL", "")).name,
        "workspace": str(workspace),
        "home": str(Path.home()),
        "computer_search_roots": [str(path) for path in computer_search_roots()],
        "available_executables": [name for name in candidates if shutil.which(name)],
    }


def _planner_prompt(intent: str, workspace: Path, max_steps: int, *, retry: bool = False) -> list[dict[str, str]]:
    snapshot = json.dumps(environment_snapshot(workspace), separators=(",", ":"))
    system = f"""You plan argument-safe terminal commands for TACU. Return ONLY one JSON object using schema {PLANNER_SCHEMA}:
{{"summary":"short plan","steps":[{{"executable":"rg","args":["TODO","."],"cwd":".","purpose":"find TODO markers"}}]}}
Rules:
- Produce 1 to {max_steps} ordered steps.
- Use only an executable plus an argument array. Never use shell code, pipes, redirection, command substitution, sudo, or inline interpreter code.
- Prefer an installed native executable from the environment snapshot.
- Never use GNU-only flags such as ps --sort on macOS. Do not put | or head in the argument array.
- The workspace is the write boundary, not the metadata-search boundary.
- To create a file with content inside the workspace, propose a single write-oriented step.
  Do not use tee (it waits on stdin). Do not use echo alone (it only prints to the terminal).
  Prefer touch only when creating an empty file. TACU rewrites create-file plans to a native
  filesystem.write or write_file using the user's filename and quoted content when possible.
- For searching text inside files, prefer the search_code tool over grep/rg pipelines.
- For reading a workspace file, prefer read_file over cat/head/tail.
- Never invent website or HTML content unless the user asked for a website or HTML page.
- For whole-computer filename or folder discovery, use the listed computer_search_roots. On macOS prefer mdfind.
- Never scan filesystem root, /proc, /sys, or /dev. Never propose sudo.
- Keep file-content reads and all writes inside the workspace unless the user explicitly requests an exact outside path.
- Do not claim commands ran. Do not include Markdown or commentary.
The output is only a proposal; deterministic TACU policy decides whether execution is allowed."""
    user = f"Environment: {snapshot}\nUser intent: {intent}"
    if retry:
        user += (
            "\nThe previous reply was not valid TACU plan JSON. Reply with only the JSON object. "
            "If the user asked for translation or explanation rather than a host command, "
            'return {"summary":"language","steps":[]}.'
        )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _json_object(text: str) -> dict[str, Any]:
    from .harness import loads_json_value

    try:
        value = loads_json_value(text)
    except TacuError as error:
        raise TacuError("The model returned malformed command-plan JSON. Nothing was executed.") from error
    if isinstance(value, list):
        return {"steps": value}
    if not isinstance(value, dict):
        raise TacuError("The model returned an invalid command plan. Nothing was executed.")
    return value


_NO_OPERATION_TOOLS = {
    "read_file", "write_file", "edit_file", "search_code", "repo_map", "inspect_symbol",
    "run_tests", "diagnostics",
}


def _native_step(item: dict[str, Any]) -> CommandStep:
    inputs = dict(item.get("inputs") or {})
    if item["tool"] in _NO_OPERATION_TOOLS:
        inputs.pop("operation", None)
    else:
        inputs.setdefault("operation", item["operation"])
    return CommandStep(
        item["tool"], (item["operation"],), ".", str(item.get("purpose") or item["operation"]),
        native_tool=item["tool"], native_operation=item["operation"],
        native_inputs=native_inputs_json(inputs),
    )


def _step_from_capability(item: dict[str, Any]) -> CommandStep:
    """Shell CRUD runs as argv so the security gate applies; other tools stay native."""

    if item.get("tool") == "shell":
        inputs = dict(item.get("inputs") or {})
        executable = str(inputs.get("executable") or "").strip()
        args = tuple(str(arg) for arg in (inputs.get("args") or []) if isinstance(arg, str))
        cwd = str(inputs.get("cwd") or ".")
        return CommandStep(
            executable, args, cwd, str(item.get("purpose") or "run command"),
        )
    return _native_step(item)


def _content_search_needle(args: list[str]) -> str | None:
    skip_next = False
    value_flags = {"-e", "-f", "-m", "-A", "-B", "-C", "-g", "--glob", "--max-count"}
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in value_flags:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if arg in {".", "./"}:
            continue
        return arg
    return None


def _invalid_mdfind(args: tuple[str, ...] | list[str]) -> bool:
    known = {"-onlyin", "-name", "-live", "-count", "-attr", "-0", "-s", "-interpret", "-literal"}
    for arg in args:
        flag = arg.split("=", 1)[0]
        if flag.startswith("-") and flag not in known and not any(arg.startswith(item + " ") for item in known):
            if flag.startswith("-t") or flag in {"-q", "-t"} or " " in arg:
                return True
    return False


def native_instead_of_shell(question: str, argv: list[str] | tuple[str, ...]) -> CommandStep | None:
    """Replace host-inspection CLIs with OS-aware native recipes when the question matches."""

    if not argv:
        return None
    executable = Path(str(argv[0])).name.casefold()
    args = [str(item) for item in argv[1:]]
    joined = " ".join(args).casefold()
    matches = native_steps_for_intent(question)

    def prefer(operation: str | None = None, tool: str | None = None) -> CommandStep | None:
        for item in matches:
            if tool and item["tool"] != tool:
                continue
            if operation and item["operation"] != operation:
                continue
            return _native_step(item)
        if tool or operation:
            return None
        return _native_step(matches[0]) if matches else None

    gnu_ps = executable == "ps" and (
        any(arg.startswith("--") for arg in args) or "%cpu" in joined or "%mem" in joined
    )
    if executable == "ps" and (matches or gnu_ps):
        operation = "top_memory" if any(token in (question.casefold() + " " + joined)
                                        for token in ("ram", "memory", "rss", "%mem")) else "top_cpu"
        return prefer(operation, "process") or _native_step({
            "tool": "process", "operation": operation,
            "inputs": {"operation": operation, "limit": 10},
            "purpose": "List top processes using a native OS recipe",
        })
    lsof_network = executable == "lsof" and (
        any(arg.startswith("-i") or arg.upper() == "ESTABLISHED" or "tcp" in arg.casefold()
            for arg in args)
        or "lsof" in question.casefold()
        or (matches and matches[0]["tool"] == "network")
    )
    if executable in {"netstat", "ss"} or lsof_network:
        state = connection_state_from_intent(question)
        return prefer(tool="network") or _native_step({
            "tool": "network", "operation": "connections",
            "inputs": {"operation": "connections", "state": state, "limit": 10},
            "purpose": "List TCP connections",
        })
    if executable in {"ifconfig", "ipconfig"} or (executable == "ip" and (
            not args or args[:1] in (["addr"], ["address"], ["-json"]) or "addr" in joined)):
        return prefer("interfaces", "network") or _native_step({
            "tool": "network", "operation": "interfaces",
            "inputs": {"operation": "interfaces"},
            "purpose": "Inspect network interfaces and the primary address",
        })
    if executable == "uname":
        return prefer("hostname", "system") or _native_step({
            "tool": "system", "operation": "hostname",
            "inputs": {"operation": "hostname"},
            "purpose": "Report the local hostname",
        })
    if executable == "mdls":
        return prefer(tool="application") or prefer(tool="filesystem")
    if executable in {"pwd", "ls", "dir"} and matches and matches[0]["tool"] == "system":
        return prefer(tool="system")
    if executable == "docker" and (
            not args or args[0] in {"ps", "images", "logs", "stats", "inspect", "rm", "rmi", "pull",
                                    "start", "stop", "network", "volume"} or matches):
        if args[:1] == ["images"] or (
                args[:1] == ["image"] and "ls" in joined
        ) or ("image" in question.casefold() and "container" not in question.casefold()):
            operation = "images"
        elif args[:1] == ["logs"] or "log" in question.casefold():
            operation = "logs"
        elif args[:1] == ["stats"]:
            operation = "stats"
        elif args[:1] == ["inspect"]:
            operation = "inspect"
        elif args[:1] == ["network"]:
            operation = "networks"
        elif args[:1] == ["volume"]:
            operation = "volumes"
        elif args[:1] in (["rm"], ["rmi"], ["pull"], ["start"], ["stop"]):
            operation = args[0]
        else:
            operation = "ps"
        return prefer(tool="docker") or _native_step({
            "tool": "docker", "operation": operation, "inputs": {"operation": operation},
            "purpose": "Inspect Docker Engine",
        })
    if executable == "launchctl":
        return prefer(tool="service") or _native_step({
            "tool": "service", "operation": "list", "inputs": {"operation": "list", "limit": 40},
            "purpose": "List launchd services",
        })
    if executable == "brew":
        operation = "outdated" if "outdated" in joined else (
            "search" if "search" in joined else ("info" if "info" in joined else "list"))
        return prefer(tool="package") or _native_step({
            "tool": "package", "operation": operation, "inputs": {"operation": operation},
            "purpose": "Inspect Homebrew packages",
        })
    if executable in {"codesign", "spctl"}:
        return prefer(tool="security")
    if executable in {"df", "diskutil", "pmset", "system_profiler"}:
        return prefer(tool="system") or _native_step({
            "tool": "system", "operation": "storage" if executable in {"df", "diskutil"} else (
                "power" if executable == "pmset" else "system_profile"),
            "inputs": {"operation": "storage" if executable in {"df", "diskutil"} else (
                "power" if executable == "pmset" else "system_profile")},
            "purpose": "Inspect system hardware or storage",
        })
    if executable in {"route", "arp", "dscacheutil", "dig", "nslookup"}:
        return prefer(tool="network")
    if executable in {"find", "tree"}:
        spec = extract_file_write(question)
        if spec and prefers_coding_write(question, spec["name"]):
            body = str(spec.get("content") or "") or (script_body_for_intent(question, spec["name"]) or "")
            if body.strip():
                return _native_step({
                    "tool": "write_file", "operation": "write",
                    "inputs": {
                        "path": spec["name"], "content": body,
                        "overwrite": True, "create_parents": True,
                    },
                    "purpose": f"Create `{spec['name']}` in the workspace",
                })
        mapped = prefer("map", "repo_map") or prefer(tool="repo_map")
        if mapped:
            return mapped
    if executable in {"python", "python3"} and args[:2] == ["-m", "http.server"]:
        return prefer("serve", "filesystem") or _native_step({
            "tool": "filesystem", "operation": "serve",
            "inputs": {"operation": "serve", "port": 8000, "open_browser": "chrome" in question.casefold()},
            "purpose": "Serve the workspace over HTTP on 127.0.0.1",
        })
    if executable in {"rm", "rmdir"}:
        delete = prefer("delete", "filesystem")
        if delete:
            return delete
        spec = extract_file_delete(question)
        if spec:
            return _native_step({
                "tool": "filesystem", "operation": "delete",
                "inputs": {"operation": "delete", "name": spec["name"]},
                "purpose": f"Remove `{spec['name']}` from the workspace",
            })
    if executable in {"touch", "printf", "echo", "tee"}:
        spec = extract_file_write(question)
        body = str((spec or {}).get("content") or "")
        if spec and prefers_coding_write(question, spec["name"]):
            if not body.strip():
                body = script_body_for_intent(question, spec["name"]) or ""
            if body.strip():
                return _native_step({
                    "tool": "write_file", "operation": "write",
                    "inputs": {
                        "path": spec["name"], "content": body,
                        "overwrite": True, "create_parents": True,
                    },
                    "purpose": f"Create `{spec['name']}` in the workspace",
                })
            return None
        write = prefer("write", "filesystem")
        if write:
            return write
        if spec and body.strip():
            return _native_step({
                "tool": "filesystem", "operation": "write",
                "inputs": {
                    "operation": "write", "name": spec["name"], "content": body,
                    "overwrite": True,
                },
                "purpose": f"Create `{spec['name']}` in the workspace",
            })
    if executable in {"rg", "grep"} and wants_content_search(question):
        needle = _content_search_needle(args) or search_query_from_intent(question)
        if needle:
            glob = ""
            regex = executable == "grep" and any(flag in args for flag in ("-E", "-P", "-G"))
            case_sensitive = "-i" not in args and "--ignore-case" not in args
            for index, arg in enumerate(args):
                if arg in {"-g", "--glob"} and index + 1 < len(args):
                    glob = args[index + 1]
                elif arg.startswith("--glob="):
                    glob = arg.split("=", 1)[1]
            inputs: dict[str, Any] = {
                "query": needle, "path": ".", "regex": regex, "case_sensitive": case_sensitive,
            }
            if glob:
                inputs["glob"] = glob
            return _native_step({
                "tool": "search_code", "operation": "search",
                "inputs": inputs,
                "purpose": f"Search files for {needle}",
            })
    if executable in {"cat", "head", "tail"}:
        if intent_is_file_edit(question) or extract_file_write(question):
            return None
        path = next((arg for arg in args if not arg.startswith("-") and arg != "--"), None)
        if path and not Path(path).expanduser().is_absolute():
            end = 400 if executable == "cat" else 80
            return _native_step({
                "tool": "read_file", "operation": "read",
                "inputs": {"path": path, "start_line": 1, "end_line": end},
                "purpose": f"Read `{path}`",
            })
    if executable in {"open"} and any(word in question.casefold() for word in ("chrome", "browser", "http.server")):
        return prefer("serve", "filesystem")
    if executable in {"curl", "wget"} and (
        _looks_like_public_ip_fetch(args) or any(
            phrase in question.casefold()
            for phrase in ("public ip", "external ip", "wan ip", "internet traffic", "internet ip")
        )
    ):
        return prefer("public_ip", "network") or _native_step({
            "tool": "network", "operation": "public_ip",
            "inputs": {"operation": "public_ip"},
            "purpose": "Look up the public IP used for internet traffic",
        })
    if executable in {"find", "grep", "mdfind"} and matches and matches[0]["tool"] in {"filesystem", "application", "git"}:
        return prefer()
    if any(arg in SHELL_OPERATORS or arg == "|" for arg in args) or any("|" in arg for arg in args):
        rewritten = prefer()
        if rewritten:
            return rewritten
    return None


def _collapse_native_site_steps(steps: list[CommandStep]) -> list[CommandStep]:
    """If native write/serve recipes exist, drop leftover echo/tee/touch/http.server shells."""

    native_writes = [step for step in steps if step.is_native and step.native_operation in {"write", "serve"}]
    if not native_writes:
        return steps
    ordered: list[CommandStep] = []
    seen: set[str] = set()
    for operation in ("write", "serve"):
        for step in native_writes:
            if step.native_operation == operation and operation not in seen:
                ordered.append(step)
                seen.add(operation)
    return ordered


def _rewrite_incompatible_step(step: CommandStep, intent: str) -> CommandStep:
    """Replace GNU-only syntax, pipes, and invalid Spotlight flags with native recipes."""

    if step.is_native:
        return step
    replacement = native_instead_of_shell(intent, step.argv)
    if replacement:
        return replacement
    executable = Path(step.executable).name.casefold()
    if executable == "cd":
        target = directory_target_from_intent(intent)
        raise TacuError(
            "TACU cannot change this shell's directory; cd would only affect a child process. "
            f"Run: cd {shlex.quote(str(target))}"
        )
    args = list(step.args)
    native_matches = native_steps_for_intent(intent)
    if executable == "mdfind" and _invalid_mdfind(args) and native_matches:
        return _native_step(native_matches[0])
    if executable == "ollama" and args[:1] == ["list"] and any(
            word in intent.casefold() for word in ("running", "loaded", "ps")):
        return _native_step({"tool": "ollama", "operation": "running_models",
                             "inputs": {"operation": "running_models"},
                             "purpose": "List currently loaded Ollama models"})
    return step


def _host_mutate_blocked(steps: list[dict[str, Any]], *, allow_host_mutate: bool) -> None:
    from .routing import HOST_MUTATE_KEYS

    if allow_host_mutate:
        return
    if any((item.get("tool"), item.get("operation")) in HOST_MUTATE_KEYS for item in steps):
        raise TacuError(
            "Host mutations (kill/install/service/docker start-stop) require reviewed "
            "execution. Re-run with: ti do …"
        )


def _plan_from_capability_steps(steps: list[dict[str, Any]], *, raw: str,
                                summary: str, allow_host_mutate: bool) -> CommandPlan:
    _host_mutate_blocked(steps, allow_host_mutate=allow_host_mutate)
    return CommandPlan(summary, tuple(_step_from_capability(item) for item in steps), raw=raw)


def _rewrite_shell_steps(steps_payload: list[Any], intent: str) -> list[CommandStep]:
    rewritten: list[CommandStep] = []
    for item in steps_payload:
        if not isinstance(item, dict):
            continue
        executable = str(item.get("executable") or "").strip()
        args = item.get("args") or []
        if not executable or not isinstance(args, list):
            continue
        replacement = native_instead_of_shell(intent, [executable, *[str(arg) for arg in args]])
        if replacement and replacement.is_native:
            rewritten.append(replacement)
    return rewritten


def _salvage_model_plan(raw: str, intent: str, workspace: Path, limit: int, *,
                        allow_shell: bool, allow_host_mutate: bool,
                        cap_error: TacuError) -> CommandPlan | None:
    from .harness import (
        parse_file_body, steps_look_like_capabilities,
        steps_look_like_shell, validate_capability_step, write_file_step_from_body,
    )

    payload: dict[str, Any] | None = None
    try:
        payload = _json_object(raw)
    except TacuError:
        payload = None
    steps_payload = payload.get("steps") if isinstance(payload, dict) else None
    if isinstance(steps_payload, list) and steps_look_like_capabilities(steps_payload):
        try:
            capability_steps = [
                validate_capability_step(item, index=index, workspace=workspace)
                for index, item in enumerate(steps_payload, 1) if isinstance(item, dict)
            ]
            if capability_steps:
                if not (intent_is_file_edit(intent) and _capability_steps_are_read_only(capability_steps)):
                    return _plan_from_capability_steps(
                        capability_steps, raw=raw,
                        summary=str((payload or {}).get("summary") or intent),
                        allow_host_mutate=allow_host_mutate,
                    )
        except TacuError:
            pass
    if isinstance(steps_payload, list) and steps_look_like_shell(steps_payload):
        rewritten = _rewrite_shell_steps(steps_payload, intent)
        if rewritten and not (
            intent_is_file_edit(intent)
            and all(step.native_tool == "read_file" or step.native_operation == "read" for step in rewritten)
        ):
            return CommandPlan(
                "Capability plan rewritten from shell argv", tuple(rewritten[:limit]), raw=raw,
            )
        if allow_shell and payload is not None:
            return _plan_from_shell_payload(payload, intent, workspace, limit, raw=raw)
    spec = extract_file_write(intent)
    if spec:
        body = parse_file_body(raw, default_name=spec["name"])
        content = str((body or {}).get("content") or spec.get("content") or "")
        path = str((body or {}).get("path") or spec["name"])
        if not content.strip() and prefers_coding_write(intent, spec["name"]):
            content = script_body_for_intent(intent, spec["name"]) or ""
            path = spec["name"]
        if content.strip():
            if prefers_coding_write(intent, path):
                step = write_file_step_from_body(
                    path, content, workspace=workspace,
                    purpose=f"Create `{path}` in the workspace",
                )
            else:
                step = validate_capability_step({
                    "tool": "filesystem",
                    "operation": "write",
                    "inputs": {"name": path, "content": content, "overwrite": True},
                    "purpose": f"Create `{path}` in the workspace",
                }, index=1, workspace=workspace)
            return _plan_from_capability_steps(
                [step], raw=raw, summary=f"Create `{path}`", allow_host_mutate=allow_host_mutate,
            )
    edited = _native_edit_plan(intent, workspace)
    if edited:
        return edited
    if intent_is_file_edit(intent):
        body = parse_file_body(raw, default_name=file_edit_target(intent) or "program.py")
        if body and str(body.get("content") or "").strip():
            step = write_file_step_from_body(
                body["path"], body["content"], workspace=workspace,
                purpose=f"Edit `{body['path']}` in the workspace",
            )
            return _plan_from_capability_steps(
                [step], raw=raw, summary=f"Edit `{body['path']}`", allow_host_mutate=allow_host_mutate,
            )
    if not allow_shell:
        raise TacuError(
            f"{cap_error} ti auto only accepts capability plans from the shortlist "
            "(no invented shell argv). For reviewed shell commands use: ti do …"
        ) from cap_error
    return None


def _plan_coding_file_from_model(client: ModelProvider, intent: str, workspace: Path) -> CommandPlan | None:
    from .harness import file_write_body_prompt, parse_file_body, write_file_step_from_body

    spec = coding_file_create_spec(intent)
    if not spec:
        return None
    messages = file_write_body_prompt(intent, workspace, spec["name"])
    raw = "".join(client.chat(messages, stream=False)).strip()
    body = parse_file_body(raw, default_name=spec["name"])
    content = (body or {}).get("content") or ""
    path = (body or {}).get("path") or spec["name"]
    if not str(content).strip():
        content = script_body_for_intent(intent, spec["name"]) or ""
        path = spec["name"]
    if not str(content).strip():
        return None
    step = write_file_step_from_body(
        path, str(content), workspace=workspace, purpose=f"Create `{path}` in the workspace",
    )
    return CommandPlan(f"Create `{path}`", tuple([_native_step(step)]), raw=raw)


def _plan_edit_from_model(client: ModelProvider, intent: str, workspace: Path) -> CommandPlan | None:
    from .harness import file_write_body_prompt, parse_file_body, write_file_step_from_body

    path = file_edit_target(intent)
    if not path:
        return None
    target = workspace / path
    current = ""
    try:
        if target.is_file():
            current = target.read_text(encoding="utf-8", errors="replace")[:8_000]
    except OSError:
        return None
    messages = file_write_body_prompt(intent, workspace, path)
    if current:
        messages[-1]["content"] += (
            f"\nCurrent file:\n{current}\nReturn the FULL updated file in content. Do not omit existing lines."
        )
    raw = "".join(client.chat(messages, stream=False)).strip()
    body = parse_file_body(raw, default_name=path)
    content = str((body or {}).get("content") or "")
    out_path = str((body or {}).get("path") or path)
    try:
        original = target.read_text(encoding="utf-8") if target.is_file() else ""
    except OSError:
        original = ""
    native_updated = apply_known_file_edit(intent, path, original) if original else None
    if native_updated and native_updated != original:
        content, out_path = native_updated, path
    elif not content.strip():
        return None
    step = write_file_step_from_body(
        out_path, content, workspace=workspace, purpose=f"Edit `{out_path}` in the workspace",
    )
    return CommandPlan(f"Edit `{out_path}`", tuple([_native_step(step)]), raw=raw)


def _capability_steps_are_read_only(steps: list[dict[str, Any]]) -> bool:
    if not steps:
        return True
    mutating = {"write_file", "edit_file"}
    return all(
        item.get("tool") not in mutating and item.get("operation") in {"read", None}
        for item in steps
    )


def _native_edit_plan(intent: str, workspace: Path) -> CommandPlan | None:
    path = file_edit_target(intent)
    if not path or Path(path).is_absolute() or ".." in Path(path).parts:
        return None
    root = workspace.expanduser().resolve(strict=False)
    target = (root / path).resolve(strict=False)
    if os_critical_path(target):
        return None
    if target != root and root not in target.parents:
        return None
    if not target.is_file():
        return None
    try:
        original = target.read_text(encoding="utf-8")
    except OSError:
        return None
    updated = apply_known_file_edit(intent, path, original)
    if updated is None or updated == original:
        return None
    step = _native_step({
        "tool": "write_file",
        "operation": "write",
        "inputs": {
            "path": path, "content": updated, "overwrite": True, "create_parents": True,
        },
        "purpose": f"Edit `{path}` in the workspace",
    })
    return CommandPlan(f"Edit `{path}`", (step,), raw="native-capability")


def create_plan(client: ModelProvider, intent: str, workspace: Path,
                max_steps: int = MAX_AUTONOMOUS_STEPS,
                failure_code: str | None = None,
                *, allow_shell: bool = False, allow_host_mutate: bool = False,
                critic_evidence: str | None = None) -> CommandPlan:
    limit = min(MAX_AUTONOMOUS_STEPS, max(1, max_steps))
    if not failure_code:
        if intent_wants_host_mutate(intent):
            mutate = native_steps_for_intent(intent, include_host_mutate=True)[:limit]
            mutate = [item for item in mutate if (item.get("tool"), item.get("operation")) in HOST_MUTATE_KEYS]
            if not allow_host_mutate:
                name = (mutate[0].get("inputs") or {}).get("name") if mutate else None
                example = f"ti do stop the container named {name}" if name else "ti do …"
                raise TacuError(
                    "That changes container, model, process, or Git state. "
                    f"Reviewed execution only. Re-run with: {example}"
                )
            if mutate:
                return CommandPlan(
                    mutate[0]["purpose"],
                    tuple(_step_from_capability(item) for item in mutate),
                    raw="native-capability",
                )
            raise TacuError(
                "That change needs an explicit target. Example: "
                "ti do stop the container named myness-searxng"
            )
        native = native_steps_for_intent(intent)[:limit]
        if native:
            return CommandPlan(
                native[0]["purpose"] if len(native) == 1 else "Use native OS recipes for this host question",
                tuple(_step_from_capability(item) for item in native),
                raw="native-capability",
            )
    edited = _native_edit_plan(intent, workspace)
    if edited:
        return edited
    last_error: TacuError | None = None
    tried_file_body = False
    for attempt in range(2):
        try:
            return _plan_from_model(
                client, intent, workspace, limit,
                retry=attempt > 0, failure_code=failure_code,
                allow_shell=allow_shell, allow_host_mutate=allow_host_mutate,
                critic_evidence=critic_evidence,
            )
        except TacuError as error:
            last_error = error
            if not tried_file_body:
                tried_file_body = True
                recovered = (
                    _plan_coding_file_from_model(client, intent, workspace)
                    or _plan_edit_from_model(client, intent, workspace)
                )
                if recovered:
                    return recovered
    assert last_error is not None
    raise last_error


def _plan_from_model(client: ModelProvider, intent: str, workspace: Path, limit: int, *,
                     retry: bool = False, failure_code: str | None = None,
                     allow_shell: bool = False, allow_host_mutate: bool = False,
                     critic_evidence: str | None = None) -> CommandPlan:
    from .harness import capability_planner_prompt, parse_capability_plan

    cap_messages = capability_planner_prompt(
        intent, workspace, limit, failure_code=failure_code,
        include_host_mutate=allow_host_mutate, critic_evidence=critic_evidence,
    )
    if retry and not failure_code:
        cap_messages[-1]["content"] += (
            "\nPrevious reply was invalid. Return only capability-plan JSON from the shortlist, "
            'or {"path":"file.name","content":"complete file"} for a create-file ask.'
        )
    raw = "".join(client.chat(cap_messages, stream=False)).strip()
    try:
        capability_steps = parse_capability_plan(raw, limit=limit, workspace=workspace)
        if intent_is_file_edit(intent) and _capability_steps_are_read_only(capability_steps):
            raise TacuError("edit_missing_mutation")
        return _plan_from_capability_steps(
            capability_steps, raw=raw, summary="Capability plan from shortlist",
            allow_host_mutate=allow_host_mutate,
        )
    except TacuError as cap_error:
        salvaged = _salvage_model_plan(
            raw, intent, workspace, limit,
            allow_shell=allow_shell, allow_host_mutate=allow_host_mutate, cap_error=cap_error,
        )
        if salvaged:
            return salvaged
        if retry:
            raise cap_error

    # Reviewed path only (`ti do`): one shell-planner fallback after capability failure.
    legacy = _planner_prompt(intent, workspace, limit, retry=True)
    if failure_code:
        legacy[-1]["content"] += (
            f"\nPrevious failure code: {failure_code}. Prefer filesystem write/serve, never tee."
        )
    raw = "".join(client.chat(legacy, stream=False)).strip()
    return _plan_from_shell_payload(_json_object(raw), intent, workspace, limit, raw=raw)


def _plan_from_shell_payload(payload: dict[str, Any], intent: str, workspace: Path, limit: int, *,
                             raw: str) -> CommandPlan:
    from .harness import steps_look_like_capabilities, validate_capability_step

    steps_payload = payload.get("steps")
    if not isinstance(steps_payload, list) or not steps_payload:
        raise TacuError("The model returned no executable steps. Nothing was executed.")
    if len(steps_payload) > limit:
        raise TacuError(f"The plan exceeded the {limit}-step limit. Nothing was executed.")
    if steps_look_like_capabilities(steps_payload):
        capability_steps = [
            validate_capability_step(item, index=index, workspace=workspace)
            for index, item in enumerate(steps_payload, 1) if isinstance(item, dict)
        ]
        return CommandPlan(
            str(payload.get("summary") or intent),
            tuple(_native_step(item) for item in capability_steps),
            raw=raw,
        )
    steps: list[CommandStep] = []
    for index, item in enumerate(steps_payload, 1):
        if not isinstance(item, dict):
            raise TacuError(f"Plan step {index} is not an object. Nothing was executed.")
        executable = item.get("executable")
        args = item.get("args", [])
        cwd = item.get("cwd", ".")
        purpose = item.get("purpose", "Run the proposed command")
        if not isinstance(executable, str) or not executable.strip() or any(character.isspace() for character in executable):
            raise TacuError(f"Plan step {index} has an invalid executable. Nothing was executed.")
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise TacuError(f"Plan step {index} args must be strings. Nothing was executed.")
        args = [arg for arg in args if arg != ""]
        if Path(executable).name.casefold() == "docker":
            args = [arg for arg in args if arg.strip() != ""]
        if not isinstance(cwd, str) or not isinstance(purpose, str):
            raise TacuError(f"Plan step {index} has invalid metadata. Nothing was executed.")
        if len(args) > 100 or sum(len(arg) for arg in args) > 20_000:
            raise TacuError(f"Plan step {index} is too large. Nothing was executed.")
        step = CommandStep(executable.strip(), tuple(args), cwd, purpose.strip())
        adapted = _adapt_computer_search(step, workspace, intent)
        steps.append(_rewrite_incompatible_step(adapted, intent))
    steps = _collapse_native_site_steps(steps)
    return CommandPlan(str(payload.get("summary") or intent), tuple(steps), raw)


def command_from_text(text: str, previous: CommandStep) -> CommandStep:
    try:
        words = shlex.split(text, posix=os.name != "nt")
    except ValueError as error:
        raise TacuError(f"Could not parse the edited command: {error}") from error
    if not words:
        raise TacuError("The edited command is empty.")
    return CommandStep(words[0], tuple(words[1:]), previous.cwd, previous.purpose)


def _inside(path: Path, root: Path) -> bool:
    try:
        resolved, workspace = path.resolve(strict=False), root.resolve(strict=False)
        return resolved == workspace or workspace in resolved.parents
    except OSError:
        return False


def _working_directory(step: CommandStep, workspace: Path) -> Path:
    cwd = Path(step.cwd).expanduser()
    return (cwd if cwd.is_absolute() else workspace / cwd).resolve(strict=False)


def _sensitive_path(path: Path) -> bool:
    parts = {part.casefold() for part in path.parts}
    name = path.name.casefold()
    return (
        bool(parts & SENSITIVE_PARTS)
        or any(part.startswith(".env") for part in parts)
        or name in SENSITIVE_FILE_NAMES
        or name.startswith(("credentials", "secrets"))
        or path.suffix.casefold() in {".pem", ".key", ".p12", ".pfx"}
        or "keychains" in parts
    )


def _zone(path: Path, workspace: Path) -> str:
    resolved = path.expanduser().resolve(strict=False)
    if _sensitive_path(resolved):
        return "Z4-sensitive"
    if _inside(resolved, workspace):
        return "Z1-workspace"
    home = Path.home().resolve(strict=False)
    if any(_inside(resolved, root) for root in (home / "Desktop", home / "Downloads")):
        return "Z2-user-files"
    if _inside(resolved, home):
        return "Z3-home"
    lowered = {part.casefold() for part in resolved.parts}
    if "applications" in lowered:
        return "Z5-applications"
    if "library" in lowered:
        return "Z6-library"
    if lowered & DEVICE_PARTS:
        return "Z8-device-boot"
    if os_critical_path(resolved) or lowered & PROTECTED_SYSTEM_PARTS or resolved == Path(resolved.anchor):
        return "Z7-system"
    return "Z3-external-user-readable"


def _looks_like_path(value: str) -> bool:
    return value in {".", "..", "/", "~"} or value.startswith(("/", "~", "./", "../")) or "/" in value or "\\" in value


def _argument_paths(step: CommandStep, workspace: Path) -> list[Path]:
    """Resolve likely path operands without treating patterns, hosts, or URLs as files."""

    executable = Path(step.executable).name.casefold()
    try:
        working = _working_directory(step, workspace)
    except OSError:
        return []
    values: list[str] = []
    args = list(step.args)
    if executable == "find":
        for arg in args:
            if arg.startswith("-"):
                break
            values.append(arg)
    elif executable in {"rg", "grep", "egrep", "fgrep"}:
        positional = [arg for arg in args if not arg.startswith("-")]
        values.extend(positional[1:])
    elif executable in {"chmod", "chown"}:
        positional = [arg for arg in args if not arg.startswith("-")]
        values.extend(positional[1:])
    elif executable in FILESYSTEM_ARGUMENT_EXECUTABLES:
        values.extend(arg for arg in args if not arg.startswith("-"))
    for index, arg in enumerate(args):
        lower = arg.casefold()
        if lower in {"-o", "--output", "-t", "--upload-file", "--key", "--cert", "--cacert"} and index + 1 < len(args):
            values.append(args[index + 1])
        elif lower.startswith(("--output=", "--upload-file=", "--key=", "--cert=", "--cacert=")):
            values.append(arg.split("=", 1)[1])
        elif executable == "git" and lower.startswith("--output="):
            values.append(arg.split("=", 1)[1])
        elif _looks_like_path(arg) and "://" not in arg and not arg.startswith("-"):
            values.append(arg)
    resolved: list[Path] = []
    for value in values:
        if not value or "://" in value:
            continue
        candidate = Path(value).expanduser()
        path = (candidate if candidate.is_absolute() else working / candidate).resolve(strict=False)
        if path not in resolved:
            resolved.append(path)
    return resolved


def _recursive_flag(args: list[str]) -> bool:
    return any(
        arg in {"-r", "-R", "-rf", "-fr", "--recursive"}
        or (arg.startswith("-") and not arg.startswith("--") and "r" in arg.casefold())
        for arg in args
    )


def _looks_like_public_ip_fetch(args: list[str]) -> bool:
    joined = " ".join(args).casefold()
    return any(marker in joined for marker in (
        "ifconfig.me", "icanhazip.com", "api.ipify.org", "ident.me",
        "checkip.amazonaws.com", "ipinfo.io/ip",
    ))


def _curl_writes_or_uploads(args: list[str]) -> bool:
    mutating = {
        "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii",
        "-F", "--form", "--form-string", "-T", "--upload-file",
        "-o", "--output", "-O", "--remote-name",
    }
    for index, arg in enumerate(args):
        if arg in mutating or arg.startswith((
            "--data", "--upload-file=", "--output=", "--form", "--data-raw=", "--data-binary=",
        )):
            return True
        if arg in {"-X", "--request"} and index + 1 < len(args) and args[index + 1].upper() not in {"GET", "HEAD"}:
            return True
        if arg.startswith("-X") and len(arg) > 2 and arg[2:].upper() not in {"GET", "HEAD"}:
            return True
    return False


def _network_transfer_reason(executable: str, args: list[str]) -> str:
    if executable in {"curl", "wget"}:
        if _curl_writes_or_uploads(args):
            return f"{executable} can send, upload, or write data over the network"
        return f"{executable} contacts the internet to retrieve a URL"
    return f"{executable} can change local, network, process, package, or remote state"


def _hard_red_reason(executable: str, args: list[str], paths: list[Path], workspace: Path) -> str | None:
    zones = {_zone(path, workspace) for path in paths}
    if any(os_critical_path(path) for path in paths) or zones & {"Z7-system", "Z8-device-boot"}:
        if executable in MUTATING_EXECUTABLES or executable in {"rm", "rmdir", "chmod", "chown"}:
            return "OS-critical paths cannot be created, edited, or deleted"
    if executable in {"rm", "rmdir"} and _recursive_flag(args):
        home = Path.home().resolve(strict=False)
        if any(path == home or path == Path(path.anchor) for path in paths):
            return "catastrophic broad recursive deletion"
    if executable in NETWORK_TRANSFER_EXECUTABLES and any(_sensitive_path(path) for path in paths):
        return "credential or secret exfiltration through a network-capable command"
    return None


def _decision(level: str, reasons: list[str] | tuple[str, ...], *, action: str,
              paths: list[Path], workspace: Path, information: str = "normal") -> PolicyDecision:
    unique = tuple(dict.fromkeys(str(reason) for reason in reasons if reason))
    zones = tuple(dict.fromkeys(_zone(path, workspace) for path in paths))
    return PolicyDecision(level, unique, action, zones, information)


def _path_reasons(step: CommandStep, workspace: Path) -> list[str]:
    reasons: list[str] = []
    try:
        cwd = Path(step.cwd).expanduser()
        working = (cwd if cwd.is_absolute() else workspace / cwd).resolve(strict=False)
    except OSError:
        return ["working directory cannot be resolved"]
    if not _inside(working, workspace):
        reasons.append("working directory is outside the selected workspace")
    for raw in step.args:
        value = raw.split("=", 1)[1] if raw.startswith("-") and "=" in raw else raw
        if "://" in value or not (value.startswith(("/", "~", ".")) or "/" in value or "\\" in value):
            continue
        candidate = Path(value).expanduser()
        resolved = candidate if candidate.is_absolute() else working / candidate
        parts = {part.casefold() for part in resolved.parts}
        if parts & SENSITIVE_PARTS or any(part.startswith(".env") for part in parts):
            reasons.append(f"sensitive path referenced: {value}")
        elif not _inside(resolved, workspace):
            reasons.append(f"path is outside the selected workspace: {value}")
    return reasons


MUTATING_EXECUTABLES = {
    "rm", "rmdir", "mv", "cp", "chmod", "chown", "touch", "mkdir", "tee", "install", "ln",
}


def os_critical_path(path: Path) -> bool:
    """True for OS/boot/system locations that TACU must never create, edit, or delete."""

    try:
        resolved = path.expanduser().resolve(strict=False)
    except OSError:
        return True
    if os.name == "nt":
        roots = [Path(os.environ.get("SystemRoot", r"C:\Windows"))]
        return any(resolved == root or root in resolved.parents for root in roots)
    # macOS maps /var and /tmp under /private; keep scratch dirs writable.
    scratch = (
        Path("/tmp"), Path("/private/tmp"), Path("/var/tmp"), Path("/private/var/tmp"),
        Path("/var/folders"), Path("/private/var/folders"),
    )
    if any(resolved == item or item in resolved.parents for item in scratch):
        return False
    roots = [
        Path("/System"), Path("/usr"), Path("/bin"), Path("/sbin"),
        Path("/etc"), Path("/private/etc"),
        Path("/dev"), Path("/boot"),
        Path("/var/db"), Path("/private/var/db"),
        Path("/var/root"), Path("/private/var/root"),
        Path("/Library/Apple"), Path("/Library/OSAnalytics"),
    ]
    return any(resolved == root or root in resolved.parents for root in roots)


NATIVE_HOST_MUTATE_OPERATIONS = {
    "kill", "start", "stop", "restart", "install", "upgrade", "remove",
    "pull", "exec", "compose", "copy", "move", "rm", "rmi", "push", "commit", "add",
}


def _native_target_paths(step: CommandStep, workspace: Path) -> list[Path]:
    """Resolve path-like fields from a native tool payload."""

    try:
        payload = json.loads(step.native_inputs or "{}")
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        return []
    root = workspace.expanduser().resolve(strict=False)
    found: list[Path] = []
    for key in ("path", "name", "root", "target"):
        value = payload.get(key)
        if not value or not isinstance(value, str):
            continue
        candidate = Path(value).expanduser()
        resolved = (candidate if candidate.is_absolute() else root / candidate).resolve(strict=False)
        if resolved not in found:
            found.append(resolved)
    return found


def _evaluate_native_policy(step: CommandStep, workspace: Path) -> PolicyDecision:
    """Permission gate for native tools.

    - OS-critical files: never create/edit/delete
    - Secrets (keys, passwords, credentials): do not read without permission
    - Delete: always ask
    - Create/edit outside the workspace: ask
    - Create/edit/read inside the workspace: allowed (writes are audited)
    """

    operation = (step.native_operation or "").casefold()
    tool = (step.native_tool or "").casefold()
    paths = _native_target_paths(step, workspace)
    sensitive = any(_sensitive_path(path) for path in paths)
    outside = [path for path in paths if not _inside(path, workspace)]
    mutating = operation in {"write", "edit", "delete", "remove", "serve"}
    if any(os_critical_path(path) for path in paths) and mutating:
        return _decision(
            "block",
            ["OS-critical paths cannot be created, edited, or deleted"],
            action="catastrophic", paths=paths, workspace=workspace,
        )
    if operation == "delete":
        return _decision(
            "prompt", ["deletes a file — confirm before removing it"],
            action="reviewed-action", paths=paths, workspace=workspace,
            information="sensitive" if sensitive else "normal",
        )
    if sensitive and (operation == "read" or tool == "read_file"):
        return _decision(
            "prompt", ["reads credentials or secrets"],
            action="reviewed-action", paths=paths, workspace=workspace, information="sensitive",
        )
    if sensitive and operation in {"write", "edit"}:
        return _decision(
            "prompt", ["would change a credentials or secrets file"],
            action="reviewed-action", paths=paths, workspace=workspace, information="sensitive",
        )
    if outside and operation in {"write", "edit"}:
        return _decision(
            "prompt", ["path is outside the selected workspace; approve to create or edit there"],
            action="reviewed-action", paths=paths, workspace=workspace,
        )
    if outside and (operation == "read" or tool == "read_file"):
        return _decision(
            "prompt", ["reads a file outside the selected workspace"],
            action="reviewed-action", paths=paths, workspace=workspace,
            information="sensitive" if sensitive else "normal",
        )
    if operation == "serve":
        return _decision(
            "prompt", ["opens a local HTTP server on 127.0.0.1"],
            action="reviewed-action", paths=paths, workspace=workspace,
        )
    if operation in NATIVE_HOST_MUTATE_OPERATIONS:
        return _decision(
            "prompt",
            [f"{step.native_tool}.{step.native_operation} changes process, package, or container state"],
            action="reviewed-action", paths=paths, workspace=workspace,
        )
    if operation == "open" and outside:
        return _decision(
            "prompt", ["opens a file outside the selected workspace"],
            action="reviewed-action", paths=paths, workspace=workspace,
        )
    if operation in {"write", "edit"}:
        return _decision(
            "log", ["workspace file create or edit; before/after evidence is audited"],
            action="workspace-mutation", paths=paths, workspace=workspace,
        )
    return _decision(
        "allow", ["native OS recipe; current OS user permissions apply"],
        action="inspect", paths=paths, workspace=workspace,
        information="sensitive" if sensitive else "normal",
    )


def evaluate_policy(step: CommandStep, workspace: Path) -> PolicyDecision:
    """Classify execution effects independently from information sensitivity.

    CRUD inside the workspace is easy. Destructive or out-of-workspace work
    asks first. OS-critical paths are never changed.
    """

    if step.is_native:
        return _evaluate_native_policy(step, workspace)

    executable = Path(step.executable).name.casefold()
    args = list(step.args)
    paths = _argument_paths(step, workspace)
    sensitive = any(_sensitive_path(path) for path in paths)

    if executable in BLOCKED_EXECUTABLES or executable.startswith("mkfs."):
        return _decision("block", [f"{executable} can alter privileged, boot, disk, or security state"],
                         action="system-change", paths=paths, workspace=workspace)
    if executable in NESTED_SHELLS and any(arg.casefold() in {"-c", "-lc", "/c"} for arg in args):
        return _decision("block", ["nested shell execution bypasses argument-safe policy"],
                         action="arbitrary-code", paths=paths, workspace=workspace)
    if executable in {"python", "python3", "node", "ruby", "perl"} and any(arg in {"-c", "-e"} for arg in args):
        return _decision("block", ["inline interpreter code can perform unbounded actions"],
                         action="arbitrary-code", paths=paths, workspace=workspace)
    if any(arg in SHELL_OPERATORS for arg in args) or any("$(" in arg or "`" in arg for arg in args):
        return _decision("block", ["shell operators or command substitution are not permitted in autopilot"],
                         action="compound-shell", paths=paths, workspace=workspace)

    red = _hard_red_reason(executable, args, paths, workspace)
    if red:
        return _decision("block", [red], action="catastrophic", paths=paths, workspace=workspace,
                         information="sensitive" if sensitive else "normal")

    reasons: list[str] = []
    if "/" in step.executable or "\\" in step.executable:
        reasons.append("explicit executable paths require review")
    if SENSITIVE_ARGUMENTS.search(" ".join(args)):
        reasons.append("credential- or secret-bearing argument detected")

    path_reasons = _path_reasons(step, workspace)
    outside_reasons = [reason for reason in path_reasons if "outside the selected workspace" in reason]
    other_path_reasons = [reason for reason in path_reasons if reason not in outside_reasons]
    metadata_path_errors = [reason for reason in other_path_reasons
                            if not reason.startswith("sensitive path referenced")]
    if executable in NON_RECURSIVE_METADATA_EXECUTABLES:
        reasons.extend(metadata_path_errors)
    elif executable in {"mdfind", "locate"}:
        reasons.extend(metadata_path_errors)
    elif executable in {"find", "tree", "du"}:
        allowed_roots = computer_search_roots()
        unsafe_outside = []
        for reason in outside_reasons:
            value = reason.rsplit(": ", 1)[-1]
            candidate = Path(value).expanduser()
            resolved = (candidate if candidate.is_absolute() else workspace / candidate).resolve(strict=False)
            if not any(_inside(resolved, root) for root in allowed_roots):
                unsafe_outside.append(reason)
        reasons.extend(metadata_path_errors + unsafe_outside)
    else:
        reasons.extend(path_reasons)

    lowered_args = [arg.casefold() for arg in args]
    if executable == "find" and any(
        arg in {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls"}
        for arg in lowered_args
    ):
        reasons.append("find arguments can execute commands, delete entries, or write files")
    if executable == "rg" and any(
        arg == "--pre" or arg.startswith("--pre=") or arg == "--pre-glob" or arg.startswith("--pre-glob=")
        for arg in lowered_args
    ):
        reasons.append("ripgrep preprocessor arguments can execute another program")
    if executable in {"env", "printenv"} and any(not arg.startswith("-") and "=" not in arg for arg in args):
        reasons.append(f"{executable} arguments can execute another program")
    if executable == "git":
        action = next((arg for arg in args if not arg.startswith("-")), "")
        if action not in SAFE_GIT_ACTIONS:
            reasons.append(f"git {action or 'operation'} changes repository or remote state")
        if any(arg == "--output" or arg.startswith("--output=") for arg in lowered_args):
            reasons.append("git output option writes a file")
    elif executable in {"docker", "podman"}:
        action = next((arg for arg in args if not arg.startswith("-")), "")
        if action not in SAFE_DOCKER_ACTIONS:
            reasons.append(f"{executable} {action or 'operation'} changes container state")
    elif executable in PROMPT_EXECUTABLES:
        reasons.append(_network_transfer_reason(executable, args))
    elif executable in SAFE_WORKSPACE_MUTATIONS:
        pass
    elif executable in SAFE_WORKSPACE_RUNNERS:
        if outside_reasons:
            reasons.extend(outside_reasons)
        elif other_path_reasons:
            reasons.extend([reason for reason in other_path_reasons if reason.startswith("sensitive path")])
    elif executable not in SAFE_READ_EXECUTABLES:
        reasons.append(f"{executable} has no deterministic autonomous policy")

    information = "sensitive" if sensitive or any("secret" in reason or "credential" in reason for reason in reasons) else "normal"
    if reasons:
        return _decision("prompt", reasons, action="reviewed-action", paths=paths, workspace=workspace,
                         information=information)
    if executable in SAFE_WORKSPACE_MUTATIONS:
        return _decision("log", [f"{executable} is a reversible workspace mutation; before/after evidence is audited"],
                         action="workspace-mutation", paths=paths, workspace=workspace, information=information)
    if executable in SAFE_WORKSPACE_RUNNERS:
        return _decision("log", [f"{executable} runs a workspace program; output is audited"],
                         action="workspace-run", paths=paths, workspace=workspace, information=information)
    scope = "computer metadata search" if executable in METADATA_READ_EXECUTABLES else "read-only inspection"
    return _decision("allow", [f"{scope}; current OS user permissions apply"],
                     action="inspect", paths=paths, workspace=workspace, information=information)
