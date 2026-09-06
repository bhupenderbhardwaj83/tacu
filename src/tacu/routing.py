"""Capability index: map natural-language host intent to native domain tools."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SIMPLE_WEBSITE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Simple Website</title>
</head>
<body>
  <h1>Hello World</h1>
  <p>This is a simple website served by TACU.</p>
</body>
</html>
"""


def normalize_intent_text(intent: str) -> str:
    text = " ".join(intent.casefold().split())
    return text.replace("crearte", "create").replace("creaet", "create").replace("http server", "http.server")


def intent_is_delete(intent: str) -> bool:
    text = normalize_intent_text(intent)
    if intent_host_domain(intent) in {"docker", "ollama"}:
        return False
    return bool(re.search(r"\b(remove|delete|unlink|erase|trash|rm)\b", text))


def intent_host_domain(intent: str) -> str | None:
    """Which host catalog owns this ask: docker, ollama, or git. None means not those families."""

    text = normalize_intent_text(intent)
    if "ollama" in text:
        return "ollama"
    if "docker" in text or re.search(r"\bcontainers?\b", text):
        return "docker"
    if re.search(r"\bgit\b", text) or any(
            phrase in text for phrase in ("git repo", "git repository", "git project", "git directory")):
        return "git"
    return None


def intent_is_site_create(intent: str) -> bool:
    """True only for create/serve of a website — not merely mentioning index.html."""

    if intent_is_delete(intent):
        return False
    text = normalize_intent_text(intent)
    creating = bool(re.search(r"\b(create|write|make|touch|save|serve)\b", text))
    site = bool(re.search(r"\b(html|website|index\.html|http\.server)\b", text))
    return creating and site


def intent_is_file_create(intent: str) -> bool:
    """True when the user asked to create/write a file (any kind) in the workspace."""

    if intent_is_delete(intent):
        return False
    text = normalize_intent_text(intent)
    if intent_is_site_create(intent):
        return True
    if re.search(
        r"\b(create|write|make|touch|save)\b.{0,80}\b(file|text file|note|message|document|script|source|"
        r"program|\.txt|\.md|\.json|\.csv|\.py|\.sh|\.js|\.ts)\b",
        text,
    ):
        return True
    if re.search(
        r"\b(create|write|make|save)\b.{0,80}\b(content|containing|that says|following)\b",
        text,
    ):
        return True
    return bool(re.search(
        r"\bwrite (?:a |the )?file\b|\bcreate (?:a |an )?(?:text |python |shell )?file\b|"
        r"\bcreate (?:a |an )?python program\b",
        text,
    ))


def _quoted_spans(intent: str) -> list[str]:
    spans = [match.group(1) for match in re.finditer(r'[\"“]([^\"”]+)[\"”]', intent)]
    if spans:
        return [span.strip() for span in spans if span.strip()]
    # Tolerate a missing opening quote: ... in it" body "
    loose = re.search(
        r'(?is)(?:content(?:\s+in\s+it)?|containing|that says|following(?:\s+content)?(?:\s+in\s+it)?)\s*"\s*(.+?)\s*"\s*$',
        intent,
    )
    if loose:
        return [loose.group(1).strip()]
    return []


def _default_created_filename(intent: str, *, site: bool) -> str:
    """Filename when the user asked to create a file but did not name it."""

    text = normalize_intent_text(intent)
    if site:
        return "index.html"
    if re.search(r"\b(python|\.py)\b", text):
        return "program.py"
    if re.search(r"\b(javascript|node|\.js)\b", text):
        return "program.js"
    if re.search(r"\b(typescript|\.ts)\b", text):
        return "program.ts"
    if re.search(r"\b(shell|bash|zsh|\.sh)\b", text):
        return "script.sh"
    if re.search(r"\b(markdown|\.md)\b", text):
        return "note.md"
    if re.search(r"\b(json|\.json)\b", text):
        return "data.json"
    if re.search(r"\b(text file|txt|note)\b", text):
        return "note.txt"
    return "note.txt"


def extract_file_write(intent: str) -> dict[str, Any] | None:
    """Deterministically extract workspace file name + body from a create/write ask.

    Website HTML is used only when the user asked for a site/HTML page and did not
    supply their own body text. Never invent HTML for a plain text-file request.
    Never invent program source — empty content means the model must write it.
    """

    if not intent_is_file_create(intent):
        return None
    site = intent_is_site_create(intent)
    quotes = _quoted_spans(intent)
    content: str | None = None
    # Prefer spans introduced as content, not as a filename.
    marked = re.search(
        r'(?is)(?:with\s+the\s+following\s+content(?:\s+in\s+it)?|content(?:\s+in\s+it)?|'
        r'containing|that says|saying|with(?:\s+the)?\s+text)\s*:?\s*[\"“](.+?)[\"”]',
        intent,
    )
    if marked:
        content = marked.group(1).strip()
    elif quotes:
        for span in quotes:
            if not re.fullmatch(r"[\w.+-]+\.[A-Za-z0-9]{1,8}", span):
                content = span
                break

    name: str | None = None
    named = re.search(
        r"(?i)(?:named|called|file\s+name(?:d)?|as)\s+[\'\"`]?([\w.+-]+\.[A-Za-z0-9]{1,8})",
        intent,
    )
    if named:
        name = named.group(1)
    else:
        for match in re.finditer(r"\b([\w.+-]+\.[A-Za-z0-9]{1,8})\b", intent):
            token = match.group(1)
            if content and token in content:
                continue
            if token.casefold() in {"index.html", "index.htm"} or token.casefold().endswith(
                (".txt", ".md", ".json", ".csv", ".py", ".sh", ".js", ".ts", ".tsx",
                 ".html", ".htm", ".log", ".yml", ".yaml", ".rb", ".go")
            ):
                name = token
                break

    name_inferred = name is None
    if not name:
        name = _default_created_filename(intent, site=site)

    content_supplied = content is not None
    if content is None:
        if site:
            content = SIMPLE_WEBSITE_HTML
            content_supplied = True
        else:
            # Create-without-body: do not invent HTML or program source.
            content = ""

    return {
        "name": name,
        "content": content,
        "name_inferred": name_inferred,
        "content_supplied": content_supplied,
    }


def extract_file_delete(intent: str) -> dict[str, str] | None:
    """Filename to remove when the ask is a delete — never a write."""

    if not intent_is_delete(intent):
        return None
    named = re.search(
        r"(?i)(?:named|called)\s+[\'\"`]?([\w.+-]+\.[A-Za-z0-9]{1,8})",
        intent,
    )
    if named:
        return {"name": named.group(1)}
    match = re.search(r"\b([\w.+-]+\.[A-Za-z0-9]{1,8})\b", intent)
    if match:
        return {"name": match.group(1)}
    return None


def intent_mutates_workspace(intent: str) -> bool:
    """True when files may be created, served, or deleted — prompt if cwd ≠ workspace."""

    return bool(
        extract_file_write(intent)
        or extract_file_delete(intent)
        or intent_is_delete(intent)
        or intent_is_file_edit(intent)
        or intent_writes_or_serves(intent)
    )


def intent_writes_or_serves(intent: str) -> bool:
    """True when this ask would create a file or start a local server."""

    text = normalize_intent_text(intent)
    if extract_file_write(intent) or intent_is_file_edit(intent):
        return True
    if any(item["operation"] in {"write", "serve"} for item in native_steps_for_intent(intent)):
        return True
    serving = bool(re.search(
        r"\b(http\.server|local server|serve this|open in chrome|load it with chrome)\b",
        text,
    ))
    creating = bool(re.search(r"\b(create|write|make|touch|save|mkdir)\b", text))
    fileish = bool(re.search(
        r"\b(file|folder|directory|text|note|message|html|website|index\.html|\.txt|\.md)\b",
        text,
    ))
    return serving or (creating and fileish)


_EXPLANATORY = re.compile(
    r"(?i)(?:"
    r"\bexplain\b|\bexplanation\b|"
    r"\bdifference between\b|"
    r"\bhow (?:does|do|would|can) .*\bwork\b|"
    r"\bwhy (?:does|do|is|are|would)\b|"
    r"\bwhat (?:does|do) .*\bmean\b|"
    r"\bmeaning of\b|"
    r"\bdefine\b|"
    r"\bwhat (?:is|are) an? \b"
    r")"
)


def intent_is_explanatory(intent: str) -> bool:
    """True when the question asks what something *is*, not what this machine holds.

    Host words are often the subject of a lesson ("explain RAM versus disk"), so
    `ti ask` must answer those in words. Anything without this framing is a real
    question about the machine and may use a native tool.
    """

    return bool(_EXPLANATORY.search(intent or ""))


@dataclass(frozen=True)
class Capability:
    tool: str
    operation: str
    phrases: tuple[str, ...]
    entities: tuple[str, ...]
    purpose: str
    risk: str = "read"


CAPABILITIES: tuple[Capability, ...] = (
    Capability("process", "top_cpu",
               ("top cpu", "highest cpu", "most cpu", "cpu usage", "cpu consuming", "consuming most cpu",
                "process using cpu", "cpu hog", "which process is consuming", "running most cpu",
                "top process running most cpu", "process consuming most cpu", "top running process",
                "top processes", "running processes", "most processing", "consuming most processing",
                "processing power", "cpu load"),
               ("cpu", "process", "pid", "processing"),
               "List top processes by CPU usage"),
    Capability("process", "top_memory",
               ("top ram", "top memory", "highest ram", "most ram", "most memory", "memory usage",
                "ram consuming", "consuming most ram", "consuming most memory", "process using memory",
                "memory hog", "sorted by rss", "most rss", "as per memory", "memory consuming",
                "running memory"),
               ("ram", "memory", "rss", "process"),
               "List top processes by memory usage"),
    Capability("process", "find",
               ("find process", "which process named", "process called"),
               ("process", "pid"),
               "Find processes by name"),
    Capability("forensics", "sweep",
               ("am i compromised", "is my machine compromised", "security check", "endpoint check",
                "forensic check", "forensics", "check my computer for", "health check for malware",
                "is my computer hacked", "am i hacked", "scan my machine", "compromise check",
                "check for malware", "check for backdoor", "security sweep", "is this machine safe",
                "check my machine", "check this machine", "check my computer", "malware",
                "scan for malware", "any malware", "infected", "is my laptop safe"),
               ("compromised", "hacked", "malware", "backdoor", "forensic", "compromise"),
               "Correlated endpoint compromise sweep: outbound, listeners, persistence, secrets"),
    Capability("forensics", "outbound",
               ("calling home", "call home", "callback home", "phoning home", "beaconing",
                "suspicious connection", "suspicious connections", "unexpected connection",
                "command and control", "exfiltrating", "exfiltration", "data leaving"),
               ("beacon", "c2", "callback", "exfil", "suspicious"),
               "Outbound connections correlated with the owning process and its signature"),
    Capability("forensics", "secret_access",
               ("stealing my password", "stealing passwords", "reading my ssh", "stealing secrets",
                "stealing credentials", "reading my credentials", "accessing my keys",
                "process reading secrets", "who is reading my aws", "credential theft",
                "stealing my tokens", "reading my private key", "stealing my aws",
                "stealing my credentials", "steal my credentials", "process stealing",
                "stealing my git", "stealing my cloud", "who is reading my", "reading my keys",
                "stealing my", "steal my", "stealing the",
                "leaking my credentials", "harvesting credentials"),
               ("credential", "credentials", "secrets", "password", "passwords", "token", "keys"),
               "Processes currently holding credential files open"),
    Capability("forensics", "persistence",
               ("persistence", "startup items", "launch agents", "launch daemons", "auto start",
                "starts automatically", "what runs at login", "what starts on boot", "startup programs"),
               ("persistence", "startup", "autostart", "launchd", "systemd"),
               "Entries configured to start automatically"),
    Capability("forensics", "listening",
               ("exposed port", "exposed ports", "listening to the network", "reachable from outside",
                "backdoor listening", "who can reach my machine"),
               ("exposed", "reachable"),
               "Listening sockets with the owning process, separating loopback from exposed"),
    Capability("network", "connections",
               ("tcp connection", "established connection", "connections established", "outbound connection",
                "destination port", "destination ports", "top destinations", "foreign address",
                "active connections", "using lsof", "established on tcp", "destinations have connection",
                "tcp 443 connection", "connections in other state", "not established",
                "connected to", "connection to", "connection with", "connecting to",
                "am i connected", "talking to", "communicating with", "reaching out to",
                "outbound to", "traffic to", "connections to"),
               ("tcp", "udp", "port", "connection", "outbound", "destination", "established", "lsof"),
               "List TCP connections and rank destination ports"),
    Capability("network", "listening_ports",
               ("listening port", "listen on", "what is listening", "open ports", "ports are open",
                "what ports are open"),
               ("listen", "listening", "port", "socket"),
               "List listening TCP ports"),
    Capability("network", "port_owner",
               ("owns port", "own this port", "process on port", "what is listening on", "who is listening"),
               ("port", "pid", "listen"),
               "Identify the process that owns a TCP port"),
    Capability("network", "interfaces",
               ("primary ip", "lan address", "network interface", "my ip address", "ip address assigned",
                "ip address", "my ip", "system name and ip", "hostname and ip"),
               ("interface", "ip", "address"),
               "Inspect network interfaces and the primary address"),
    Capability("network", "public_ip",
               ("public ip", "external ip", "wan ip", "internet ip", "ip on the internet",
                "going on internet", "internet traffic", "my public ip", "what is my public",
                "public address"),
               ("public", "external", "wan", "internet"),
               "Look up the public IP used for internet traffic"),
    Capability("system", "datetime",
               ("what is the date", "what date is", "todays date", "today's date", "current date",
                "what time is it", "current time", "date and time", "time and date", "what day is",
                "what day of the week", "current day", "what year is", "current year", "local time",
                "system time", "system date", "what is the time", "time right now", "date right now"),
               ("date", "time", "today", "day", "year", "clock", "timezone"),
               "Report the current local date, time, day, and timezone from this machine's clock"),
    Capability("system", "hostname",
               ("system name", "hostname", "computer name", "machine name", "what is my system name",
                "my system name", "host name"),
               ("hostname", "computer"),
               "Report the local hostname"),
    Capability("system", "cwd",
               ("current directory", "full path of the current", "working directory", "where am i",
                "share the full path", "pwd of", "current workspace", "workspace we are in",
                "what is the current workspace", "show directory", "show current directory",
                "which directory am i", "what directory am i", "directory am i in",
                "which folder am i", "folder am i in", "which directory is this",
                "print working directory", "where are we"),
               ("cwd", "pwd", "workspace"),
               "Report the current working directory and TACU workspace"),
    Capability("system", "listing",
               ("how many files", "count files", "files and folders", "files in current",
                "how many folders", "how many items"),
               (),
               "Count files and folders in the current directory"),
    Capability("system", "os_version",
               ("os version", "macos version", "operating system", "what os"),
               ("macos", "darwin", "linux", "windows"),
               "Report operating system version"),
    Capability("system", "memory",
               ("how much ram", "system memory", "installed memory", "total ram"),
               ("ram", "memory"),
               "Report system memory"),
    Capability("application", "list",
               ("installed apps", "installed applications", "applications folder", "apps in applications",
                "tell me installed apps"),
               ("application", "app"),
               "List installed applications"),
    Capability("application", "find",
               ("app named", "app that contain", "application named", "contain falcon", "app containing"),
               ("application", "app"),
               "Find an installed application by name"),
    Capability("application", "version",
               ("app version", "application version", "what version is"),
               ("version", "application", "app"),
               "Read installed application version metadata"),
    Capability("application", "metadata",
               ("when was the app installed", "when was", "install date", "installed on",
                "app installed", "application installed", "creation date of the app"),
               ("application", "app", "installed"),
               "Read when an application was installed"),
    Capability("application", "running",
               ("running application", "is the app running", "running apps"),
               ("application", "running"),
               "See whether an application is running"),
    Capability("docker", "ps",
               ("running docker", "docker containers", "docker ps", "running containers",
                "show running docker", "which docker container", "docker container is running",
                "which containers are running"),
               ("docker", "container"),
               "List running Docker containers"),
    Capability("docker", "images",
               ("docker images", "installed docker images"),
               ("docker", "image"),
               "List Docker images"),
    Capability("git", "is_repo",
               ("git directory", "git repo", "git repository", "is this git", "current directory a git"),
               ("git",),
               "Check whether the current directory is a Git repository"),
    Capability("git", "find_repos",
               ("find all", "directories that", "git directories", "git repos on"),
               ("git",),
               "Find Git repositories under a directory"),
    Capability("git", "status",
               ("git status", "uncommitted", "working tree", "what changed in git",
                "git changes", "dirty worktree"),
               ("git", "status"),
               "Show Git status for the current repository"),
    Capability("git", "log",
               ("git log", "recent commits", "commit history", "last commits"),
               ("git", "commit", "log"),
               "Show recent Git commits"),
    Capability("git", "diff",
               ("git diff", "unstaged diff", "what did i change"),
               ("git", "diff"),
               "Show Git unstaged diffstat"),
    Capability("git", "branch",
               ("git branch", "current branch", "which branch", "list branches"),
               ("git", "branch"),
               "List Git branches"),
    Capability("git", "remote",
               ("git remote", "remote url", "origin url", "git remotes"),
               ("git", "remote"),
               "List Git remotes"),
    Capability("filesystem", "write",
               ("create a", "create an", "create a text file", "create a file", "write a file",
                "make a file", "text file with", "file with the following", "save a file",
                "create index.html", "make a simple", "basic website", "simple website",
                "simple index.html", "hello world html"),
               ("file", "text", "html", "website", "content"),
               "Create a file with content in the workspace",
               risk="mutate"),
    Capability("filesystem", "delete",
               ("remove the", "delete the", "remove file", "delete file", "rm the",
                "remove index.html", "delete index.html"),
               ("remove", "delete", "file"),
               "Remove a workspace file",
               risk="mutate"),
    Capability("filesystem", "serve",
               ("http server", "http.server", "python http", "local server", "serve this",
                "load it with chrome", "open in chrome", "preview in browser"),
               ("server", "chrome", "browser", "http"),
               "Serve the workspace over HTTP on 127.0.0.1 and open it",
               risk="mutate"),
    Capability("filesystem", "find",
               ("file named", "folder named", "full path of", "full path for", "full path",
                "file which has", "folder which has", "image files", "files in the downloads",
                "file in", "with name", "has snake", "in its name", "all images", "images on",
                "find all images", "images on desktop", "photos on"),
               (),
               "Find files or folders by name"),
    Capability("filesystem", "open",
               ("open the image", "open this image", "open the file", "preview the image",
                "can you open", "open image"),
               (),
               "Open a file with the OS default application"),
    Capability("filesystem", "read",
               ("read the content", "read this file", "read the file", "show the content of",
                "read the contents"),
               (),
               "Read a bounded preview of a local file"),
    Capability("read_file", "read",
               ("read the source", "read this script", "read numbered", "show lines of",
                "read file range", "numbered lines", "show the contents", "show me the contents",
                "cat the file", "read the file"),
               (),
               "Read a workspace file with numbered lines"),
    Capability("write_file", "write",
               ("create a python", "python script", "python program", "write a script", "shell script",
                "source file", "create a .py", "write source", "program file"),
               ("script", "source", "python", "program"),
               "Create a source or script file in the workspace",
               risk="mutate"),
    Capability("edit_file", "edit",
               ("replace the text", "edit the file", "change the code", "exact replace",
                "replace in file", "edit program", "add at the top", "add to the file",
                "add at the bottom", "append to the file", "prepend to the file"),
               (),
               "Replace exact text in a workspace file",
               risk="mutate"),
    Capability("search_code", "search",
               ("search code", "search the code", "search files for", "grep for", "ripgrep",
                "find todo", "todo markers", "text in files", "search text", "search for todo"),
               (),
               "Search file contents for text"),
    Capability("repo_map", "map",
               ("map this project", "directory tree", "repo map", "map the repo",
                "project tree", "map this directory", "map the directory", "map the workspace"),
               (),
               "Map a workspace directory tree"),
    Capability("repo_map", "find",
               ("files matching", "glob for", "files named", "find files matching"),
               (),
               "Find workspace files by name or glob"),
    Capability("inspect_symbol", "inspect",
               ("where is function", "where is class", "find the definition", "inspect symbol",
                "definition of", "where is def"),
               ("symbol", "function", "class"),
               "Find a function or class definition"),
    Capability("run_tests", "run",
               ("run the tests", "run tests", "run pytest", "run unit tests", "run the test suite"),
               ("pytest", "unittest"),
               "Run the workspace test suite"),
    Capability("diagnostics", "check",
               ("syntax errors", "lint this", "check syntax", "diagnostics for"),
               (),
               "Check a workspace file for syntax errors"),
    Capability("shell", "run",
               ("run the program", "run program.py", "execute the script", "run this python",
                "execute program.py", "run the script", "run this file"),
               ("run", "execute"),
               "Run a workspace script without nested shell interpolation",
               risk="mutate"),
    Capability("ollama", "running_models",
               ("running ollama", "loaded model", "ollama ps", "currently running ollama",
                "running ollama models"),
               ("ollama", "model"),
               "List currently loaded Ollama models"),
    Capability("ollama", "installed_models",
               ("installed ollama", "ollama list", "which models are installed",
                "which ollama models", "ollama models", "models on this machine",
                "models are there", "what models are installed", "list ollama models"),
               ("ollama", "model"),
               "List installed Ollama models"),
    Capability("ollama", "model_info",
               ("ollama show", "model info", "ollama model details"),
               ("ollama", "model"),
               "Show details for one installed Ollama model"),
    Capability("process", "open_files",
               ("open files", "files open by", "what files does", "lsof -p"),
               ("pid", "lsof"),
               "List files a process has open"),
    Capability("process", "tree",
               ("process tree", "child processes", "parent process"),
               ("pid", "process"),
               "Show a process parent/child tree"),
    Capability("network", "routes",
               ("routing table", "default route", "network routes", "netstat -rn"),
               ("route",),
               "Show the routing table"),
    Capability("network", "dns",
               ("dns server", "dns resolver", "which dns", "scutil --dns"),
               ("dns", "resolver"),
               "Show configured DNS resolvers"),
    Capability("network", "arp",
               ("arp table", "arp cache", "neighbor table"),
               ("arp",),
               "Show the ARP neighbor table"),
    Capability("network", "resolve",
               ("resolve hostname", "dns lookup", "what ip is", "look up host",
                "resolve to", "resolves to", "reverse dns", "which hostname", "what hostname"),
               ("dns", "hostname", "nslookup", "ptr"),
               "Resolve a hostname or reverse-lookup an IP"),
    Capability("system", "storage",
               ("disk space", "free disk", "disk usage", "how much disk", "storage space", "df -h"),
               ("disk", "storage", "volume"),
               "Report mounted disk space"),
    Capability("system", "power",
               ("battery", "charging", "power status", "how much battery"),
               ("battery", "power"),
               "Report battery and power status"),
    Capability("system", "cpu",
               ("how many cpus", "cpu count", "processor count"),
               ("cpu", "processor"),
               "Report CPU count"),
    Capability("filesystem", "disk_usage",
               ("folder size", "directory size", "du of"),
               ("size",),
               "Measure a folder's disk usage"),
    Capability("filesystem", "hash",
               ("file hash", "sha256", "checksum of"),
               ("hash", "sha256"),
               "SHA-256 hash a local file"),
    Capability("filesystem", "metadata",
               ("file metadata", "file permissions", "file size of", "stat of"),
               ("stat",),
               "Read file metadata and permissions"),
    Capability("application", "signature",
               ("app signature", "codesign of", "who signed"),
               ("codesign", "signature"),
               "Read an application code signature"),
    Capability("service", "list",
               ("launchd", "launchctl list", "running services", "list services",
                "list launchctl", "launchctl services"),
               ("service", "launchd", "launchctl"),
               "List launchd services"),
    Capability("service", "find",
               ("find service", "service named", "launch agent"),
               ("service", "launchd"),
               "Find a launchd service by name"),
    Capability("service", "status",
               ("service status", "is the service running"),
               ("service", "launchctl"),
               "Show one launchd service status"),
    Capability("package", "list",
               ("brew list", "installed brew", "installed packages", "homebrew packages"),
               ("brew", "package", "formula"),
               "List installed Homebrew packages"),
    Capability("package", "outdated",
               ("brew outdated", "outdated packages", "packages to update", "outdated brew"),
               ("brew", "package"),
               "List outdated Homebrew packages"),
    Capability("package", "info",
               ("brew info", "package info", "formula info"),
               ("brew", "package"),
               "Show Homebrew package metadata"),
    Capability("package", "search",
               ("brew search", "search packages", "search brew"),
               ("brew", "package"),
               "Search Homebrew packages"),
    Capability("security", "gatekeeper",
               ("gatekeeper", "spctl status", "sip status"),
               ("gatekeeper", "spctl"),
               "Report Gatekeeper status"),
    Capability("security", "codesign",
               ("codesign", "code signature", "signed by"),
               ("codesign", "signature"),
               "Inspect a path's code signature"),
    Capability("security", "quarantine",
               ("quarantine", "com.apple.quarantine", "downloaded from internet"),
               ("quarantine", "xattr"),
               "Read the macOS quarantine attribute"),
    Capability("security", "hash",
               ("sha256 of", "hash of this file"),
               ("sha256", "hash"),
               "Hash a file"),
    Capability("docker", "logs",
               ("docker logs", "container logs"),
               ("docker", "container", "log"),
               "Read recent Docker container logs"),
    Capability("docker", "stats",
               ("docker stats", "container cpu", "container memory"),
               ("docker", "container"),
               "Show Docker container resource stats"),
    # High-value Mac ops that exist in tools but were missing from the planner catalog.
    Capability("application", "open",
               ("open google chrome", "open chrome", "open safari", "open firefox",
                "open the app", "open application", "launch application", "launch the app",
                "open browser", "launch browser", "open in chrome", "open in safari",
                "open in firefox", "launch chrome", "open website", "open the website",
                "open the site", "launch the site", "open url", "browse to"),
               ("open", "launch", "browser", "website", "site", "url"),
               "Open an installed application, optionally at a web address",
               risk="host_mutate"),
    Capability("process", "graph",
               ("what is running on port", "which process is using port", "what is using port",
                "who is on port", "process on port", "running on port", "owns port",
                "which process is running", "what process is running", "is running",
                "what servers are running", "which servers are running", "what is serving",
                "what is listening", "servers running", "dev server", "which server",
                "what is my", "process running my", "who is running", "is there a process",
                "find the server", "which app is running", "what is running",
                "still up", "already running", "up and running"),
               ("server", "servers", "port", "running", "listening", "process"),
               "Correlate processes with their lineage, runtime and listening ports"),
    Capability("process", "list",
               ("list processes", "all processes", "ps aux", "show processes",
                "list running processes", "running processes", "list all process",
                "show me processes", "what processes are running"),
               ("process", "pid"),
               "List processes"),
    Capability("process", "inspect",
               ("inspect process", "process details", "process info", "tell me about pid",
                "about process with id", "process with id", "process with pid", "about pid",
                "tell me about process", "all about process", "details of process",
                "what is pid", "which process is", "info on pid", "who owns pid",
                "what is this process", "identify process", "what is process",
                "which process has", "process running with"),
               ("process", "pid"),
               "Inspect one process by PID"),
    Capability("network", "primary_ip",
               ("primary ipv4", "main lan ip", "primary address only"),
               ("ip", "primary"),
               "Report the primary IPv4 address"),
    Capability("system", "hardware",
               ("hardware overview", "mac model", "machine model", "serial number", "system profiler hardware"),
               ("hardware", "model"),
               "Report Mac hardware overview"),
    Capability("system", "uptime",
               ("system uptime", "how long has", "boot time", "how long up"),
               ("uptime",),
               "Report system uptime"),
    Capability("system", "environment",
               ("environment variable", "env var", "printenv", "what is my path"),
               ("environment", "env"),
               "Inspect environment variables"),
    Capability("filesystem", "list",
               ("list files", "list directory", "ls the", "directory listing"),
               ("list", "directory"),
               "List files in a directory"),
    Capability("filesystem", "size",
               ("how big is the file", "file size", "bytes of"),
               ("size",),
               "Report a file's size"),
    Capability("docker", "inspect",
               ("docker inspect", "inspect container", "container details", "inspect its",
                "base image", "container network", "container name and"),
               ("docker", "container", "image", "network"),
               "Inspect a Docker container (name, image, networks)"),
    Capability("docker", "containers",
               ("all docker containers", "docker container ls", "stopped containers"),
               ("docker", "container"),
               "List Docker containers including stopped"),
    Capability("docker", "networks",
               ("docker networks", "container networks", "list docker networks"),
               ("docker", "network"),
               "List Docker networks"),
    Capability("docker", "volumes",
               ("docker volumes", "list docker volumes"),
               ("docker", "volume"),
               "List Docker volumes"),
    Capability("security", "process_signature",
               ("process signature", "signed process", "codesign of process"),
               ("codesign", "process", "signature"),
               "Inspect a running process code signature"),
    # Remaining read ops from tool SPECs.
    Capability("network", "connections_by_port",
               ("connections by port", "connections on port", "who connects to port",
                "traffic on port"),
               ("port", "connection"),
               "Group or list connections for one port"),
    Capability("system", "system_profile",
               ("system profile", "system_profiler", "full hardware profile", "sphardware"),
               ("hardware", "profiler"),
               "Run a compact system_profiler hardware report"),
    Capability("filesystem", "permissions",
               ("file permissions", "chmod of", "mode of the file", "who can read this file"),
               ("permissions", "mode"),
               "Read POSIX permissions for a file"),
    Capability("security", "permissions",
               ("acl permissions", "security permissions", "file acl"),
               ("permissions", "acl"),
               "Inspect security-oriented permissions metadata"),
    Capability("service", "inspect",
               ("inspect service", "launchd inspect", "service plist"),
               ("service", "launchd"),
               "Inspect a launchd service definition"),
    # Host mutations — cataloged for reviewed ti do only (risk=host_mutate).
    Capability("process", "kill",
               ("kill process", "kill pid", "terminate process", "sigterm", "sigkill",
                "stop the process", "end process"),
               ("kill", "pid", "process"),
               "Terminate a process by PID (reviewed)",
               risk="host_mutate"),
    Capability("docker", "start",
               ("start container", "docker start", "start the container"),
               ("docker", "container", "start"),
               "Start a Docker container (reviewed)",
               risk="host_mutate"),
    Capability("docker", "stop",
               ("stop container", "docker stop", "stop the container"),
               ("docker", "container", "stop"),
               "Stop a Docker container (reviewed)",
               risk="host_mutate"),
    Capability("docker", "rm",
               ("docker rm", "remove container", "delete container", "remove the container",
                "delete the docker container"),
               ("docker", "container", "remove", "delete"),
               "Remove a Docker container (reviewed)",
               risk="host_mutate"),
    Capability("docker", "rmi",
               ("docker rmi", "remove image", "delete image", "delete docker image",
                "remove docker image"),
               ("docker", "image", "remove", "delete"),
               "Remove a Docker image (reviewed)",
               risk="host_mutate"),
    Capability("docker", "pull",
               ("docker pull", "pull image", "pull docker image"),
               ("docker", "image", "pull"),
               "Pull a Docker image (reviewed)",
               risk="host_mutate"),
    Capability("ollama", "pull",
               ("ollama pull", "pull model", "download ollama model"),
               ("ollama", "model", "pull"),
               "Pull an Ollama model (reviewed)",
               risk="host_mutate"),
    Capability("ollama", "rm",
               ("ollama rm", "delete ollama model", "remove ollama model", "delete the model"),
               ("ollama", "model", "remove", "delete"),
               "Delete an installed Ollama model (reviewed)",
               risk="host_mutate"),
    Capability("ollama", "stop",
               ("ollama stop", "unload ollama", "stop ollama model", "unload the model"),
               ("ollama", "model", "stop"),
               "Stop a loaded Ollama model (reviewed)",
               risk="host_mutate"),
    Capability("git", "add",
               ("git add", "stage file", "stage the file"),
               ("git", "add", "stage"),
               "Stage a file in Git (reviewed)",
               risk="host_mutate"),
    Capability("git", "commit",
               ("git commit", "commit changes", "commit the changes"),
               ("git", "commit"),
               "Create a Git commit (reviewed)",
               risk="host_mutate"),
    Capability("git", "push",
               ("git push", "push commits", "push to origin"),
               ("git", "push"),
               "Push Git commits (reviewed; never --force)",
               risk="host_mutate"),
    Capability("service", "start",
               ("start service", "launchctl start", "start the service"),
               ("service", "launchctl", "start"),
               "Start a launchd service (reviewed)",
               risk="host_mutate"),
    Capability("service", "stop",
               ("stop service", "launchctl stop", "stop the service"),
               ("service", "launchctl", "stop"),
               "Stop a launchd service (reviewed)",
               risk="host_mutate"),
    Capability("service", "restart",
               ("restart service", "launchctl kickstart", "restart the service"),
               ("service", "launchctl", "restart"),
               "Restart a launchd service (reviewed)",
               risk="host_mutate"),
    Capability("package", "install",
               ("brew install", "install package", "install formula", "install the package"),
               ("brew", "package", "install"),
               "Install a Homebrew package (reviewed)",
               risk="host_mutate"),
    Capability("package", "upgrade",
               ("brew upgrade", "upgrade package", "upgrade formula", "update the package"),
               ("brew", "package", "upgrade"),
               "Upgrade a Homebrew package (reviewed)",
               risk="host_mutate"),
    Capability("package", "remove",
               ("brew uninstall", "brew remove", "uninstall package", "remove package",
                "remove formula"),
               ("brew", "package", "remove", "uninstall"),
               "Remove a Homebrew package (reviewed)",
               risk="host_mutate"),
)


HOST_MUTATE_KEYS = frozenset(
    (item.tool, item.operation) for item in CAPABILITIES if item.risk == "host_mutate"
)
HOST_MUTATE_OPERATIONS = frozenset(operation for _tool, operation in HOST_MUTATE_KEYS)


def intent_wants_host_mutate(intent: str) -> bool:
    text = normalize_intent_text(intent)
    # "open index.html in google chrome" launches something too, even though the
    # application is not the word right after the verb.
    if re.search(r"(?i)\b(?:open|launch|start|run)\b", text) and app_to_open_from_intent(intent):
        return True
    return bool(re.search(
        r"\b(kill|terminate|sigterm|sigkill|brew install|brew upgrade|brew uninstall|brew remove|"
        r"(?:open|launch|start)\s+(?:up\s+)?(?:the\s+)?(?:app(?:lication)?|browser|chrome|safari|"
        r"firefox|edge|brave|terminal|finder)\b|"
        r"(?:open|launch|browse)\s+(?:to\s+)?(?:the\s+)?[^\s]*\.(?:com|org|net|io|dev|in|co|ai)\b|"
        r"install (?:the )?(?:package|formula)|upgrade (?:the )?(?:package|formula)|"
        r"uninstall (?:the )?(?:package|formula)|"
        r"(?:start|stop|restart) (?:the )?(?:service|container|docker)|"
        r"(?:start|stop|restart)\b.{0,48}\bcontainers?\b|"
        r"(?:start|stop|remove|delete)\s+[A-Za-z0-9._/-]+\s+container|"
        r"docker (?:start|stop|rm|rmi|pull)|"
        r"ollama (?:pull|rm|stop)|"
        r"(?:delete|remove) (?:the )?(?:docker )?(?:container|image|model)|"
        r"git (?:add|commit|push)|(?:stage|commit|push) (?:the )?(?:file|changes|commits)|"
        r"launchctl (?:start|stop|kickstart))\b",
        text,
    ))


def limit_from_intent(intent: str, default: int = 10) -> int:
    match = re.search(r"\b(?:top|first|highest)\s+(\d{1,3})\b", intent.casefold())
    if match:
        return max(1, min(int(match.group(1)), 50))
    if re.search(r"\bten\b", intent.casefold()):
        return 10
    return default


# "pid 92894", "process with id 92894", "process 92894", "id 92894". A bare number is
# not enough: "top 5 processes" must not read 5 as a pid.
_PID_PATTERNS = (
    r"\bpid\s*[:=#]?\s*(\d{1,7})\b",
    r"\bprocess(?:es)?\s+(?:with\s+)?(?:the\s+)?(?:id|pid|number)\s*[:=#]?\s*(\d{1,7})\b",
    r"\bprocess(?:es)?\s+[#]?(\d{2,7})\b",
    r"\b(?:id|identifier)\s*[:=#]?\s*(\d{3,7})\b",
)


# Words that describe the *asking*, not the thing asked about. Removing them leaves
# the words that name a runtime, an entrypoint or a role.
_PROCESS_QUESTION_WORDS = frozenset((
    "what", "which", "who", "whom", "whose", "where", "when", "why", "how", "is", "are",
    "was", "were", "the", "a", "an", "my", "me", "mine", "our", "this", "that", "these",
    "those", "there", "here", "on", "in", "at", "of", "for", "with", "and", "or", "to",
    "do", "does", "did", "am", "i", "you", "it", "its", "please", "tell", "show", "find",
    "list", "give", "get", "can", "could", "would", "should", "any", "all", "some",
    "machine", "computer", "laptop", "system", "box", "host", "currently", "right", "now",
    "process", "processes", "pid", "app", "apps", "application", "applications",
    "running", "run", "runs", "started", "using", "used", "up",
))


_ROLE_WORDS = frozenset(("server", "servers", "service", "services", "daemon", "daemons",
                         "listener", "listeners", "port", "ports"))


def process_query_from_intent(intent: str) -> str:
    """The words in a process question that actually name something.

    "which process is running my python http server" -> "python http server". What is
    left is matched against what each process *is*, so nothing needs to be enumerated
    here in advance.
    """

    words = [word for word in re.split(r"[^A-Za-z0-9._+-]+", intent or "") if word]
    kept = [word for word in words
            if word.casefold() not in _PROCESS_QUESTION_WORDS and not word.isdigit()]
    if kept and all(word.casefold() in _ROLE_WORDS for word in kept):
        # "what servers are running" names a role, not a program: the default
        # listening view already answers it.
        return ""
    return " ".join(kept).strip()


def _pid_from_intent(intent: str) -> int | None:
    for pattern in _PID_PATTERNS:
        match = re.search(pattern, intent, flags=re.I)
        if match:
            value = int(match.group(1))
            if 1 <= value <= 4_194_304:
                return value
    return None


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b"
)


def _ipv4_from_intent(intent: str) -> str | None:
    match = _IPV4_RE.search(intent)
    return match.group(0) if match else None


def intent_wants_dns_lookup(intent: str) -> bool:
    """True when hostname/resolve refers to a name or IP, not this Mac's system name."""

    text = normalize_intent_text(intent)
    if _ipv4_from_intent(intent) and any(phrase in text for phrase in (
        "hostname", "host name", "resolve", "dns", "ptr", "nslookup", "look up", "lookup",
        "whois", "belong",
    )):
        return True
    return any(phrase in text for phrase in (
        "resolve to", "resolves to", "reverse dns", "ptr record",
        "which hostname", "what hostname does", "hostname does",
        "resolve hostname", "dns lookup",
    ))


def _host_from_intent(intent: str) -> str | None:
    ipv4 = _ipv4_from_intent(intent)
    if ipv4:
        return ipv4
    quoted = _quoted_name_from_intent(intent)
    if quoted and "." in quoted:
        return quoted
    match = re.search(r"\b((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b", intent)
    return match.group(1) if match else None


def _port_from_intent(intent: str) -> int | None:
    match = re.search(r"\bport\s+(\d{2,5})\b", intent.casefold()) or re.search(r"\b(\d{2,5})\b", intent)
    if not match:
        return None
    value = int(match.group(1))
    return value if 1 <= value <= 65535 else None


_APP_NAME_STOPWORDS = {
    "that", "the", "this", "a", "an", "any", "in", "on", "my", "is", "are",
    "folder", "directory", "file", "files", "apps", "application", "applications",
}


def connection_state_from_intent(intent: str) -> str:
    """Map connection-state language onto a native network filter."""

    text = " ".join(intent.casefold().split())
    if re.search(
            r"\b(?:other than|except|excluding|besides|meaning not)\b.{0,40}\bestablished\b"
            r"|\bother(?:\s+\w+){0,3}\s+than\b.{0,20}\bestablished\b"
            r"|\bestablished\b.{0,24}\b(?:not|other)\b"
            r"|\bnot\b.{0,24}\bestablished\b",
            text,
    ):
        return "NOT_ESTABLISHED"
    if re.search(r"\b(?:time[-\s]?wait|close[-\s]?wait|syn[-\s]?sent|fin[-\s]?wait)\b", text):
        token = re.search(r"\b(time[-\s]?wait|close[-\s]?wait|syn[-\s]?sent|fin[-\s]?wait)\b", text)
        return (token.group(1) if token else "ESTABLISHED").upper().replace(" ", "-").replace("_", "-")
    if "listen" in text and "established" not in text:
        return "LISTEN"
    if re.search(r"\b(?:all states|any state|every state)\b", text):
        return "ANY"
    return "ESTABLISHED"


# A bare domain still names a site; anything with a scheme must be http(s).
_URL_IN_INTENT = re.compile(
    r"\bhttps?://[^\s'\"]+|\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:com|org|net|io|dev|ai|co|in|uk|edu|gov|app|me|tv|news|xyz)\b(?:/[^\s'\"]*)?",
    re.I)
# Trailing words that describe the app rather than name it.
_APP_TAIL = re.compile(r"(?i)\s+(?:web\s+)?(?:browser|app|application|window|program)\s*$")
_APP_AFTER_OPEN = re.compile(
    r"(?i)\b(?:open|launch|start|run)\s+(?:up\s+)?(?:the\s+)?(?:app(?:lication)?\s+)?"
    r"(.+?)(?=\s+(?:and|then|with|at|to|on|in|from|,)\b|$)")
_APP_AFTER_IN = re.compile(
    r"(?i)\b(?:in|on|using|via|with)\s+(?:the\s+)?([A-Za-z][\w .+-]*?)\s*$")


def url_from_intent(intent: str) -> str | None:
    """The address a request names, normalised to something openable."""

    match = _URL_IN_INTENT.search(intent or "")
    if not match:
        return None
    found = match.group(0).rstrip(".,;:'\"")
    if found.casefold().startswith(("http://", "https://")):
        return found
    return f"https://{found}"


# "on it", "in there" — a pronoun points back at something, it does not name an app.
_PRONOUNS = frozenset(("it", "this", "that", "them", "those", "these", "there", "here",
                       "one", "same", "browser", "app", "application"))


def _clean_app_name(raw: str) -> str:
    name = raw.strip().strip("'\"`.,")
    name = _APP_TAIL.sub("", name).strip()
    if _URL_IN_INTENT.search(name):
        name = _URL_IN_INTENT.sub("", name).strip()
    lowered = name.casefold()
    if lowered in _APP_NAME_STOPWORDS or lowered in _PRONOUNS:
        return ""
    # "run program.py" runs a script; only a bundle is named like a file.
    if "/" in name or (re.search(r"\.[A-Za-z0-9]{1,8}$", name) and not lowered.endswith(".app")):
        return ""
    return name


def app_to_open_from_intent(intent: str) -> str | None:
    """Which application a request wants launched.

    Only the phrase is taken here; matching it to something installed is the
    application tool's job, so "google chrome" finds "Google Chrome.app" without
    anything needing to know that name in advance.
    """

    text = (intent or "").strip()
    without_url = _URL_IN_INTENT.sub(" ", text)
    trailing = _APP_AFTER_IN.search(without_url)
    if trailing:
        name = _clean_app_name(trailing.group(1))
        if name:
            return name
    leading = _APP_AFTER_OPEN.search(without_url)
    if leading:
        name = _clean_app_name(leading.group(1))
        if name:
            return name
    return None


def _app_name_from_intent(intent: str) -> str | None:
    path_match = re.search(r"(/Applications/[^/\s]+(?:\s[^/\s]+)*\.app)", intent)
    if path_match:
        from pathlib import Path as _Path
        return _Path(path_match.group(1)).stem
    installed = re.search(
        r"(?i)when was (?:the )?(?:app(?:lication)? )?(?:named |called )?(.+?)(?:\.app)? installed",
        intent,
    )
    if installed:
        token = installed.group(1).strip().strip("'\"`")
        if token and token.casefold() not in _APP_NAME_STOPWORDS:
            return token
    dated = re.search(
        r"(?i)(?:install(?:ation)? date|created) (?:of|for) (?:the )?(?:app(?:lication)? )?(.+?)(?:\.app)?$",
        intent.strip(),
    )
    if dated:
        token = dated.group(1).strip().strip("'\"`")
        if token and token.casefold() not in _APP_NAME_STOPWORDS:
            return token
    match = re.search(
        r"(?:contain(?:s|ing)?|named|called)\s+['\"]?([A-Za-z0-9._+-]+)['\"]?",
        intent,
        flags=re.I,
    )
    if match:
        return match.group(1)
    match = re.search(
        r"\b(?:app(?:lication)?|version of)\s+['\"]?([A-Za-z0-9._+-]+)['\"]?|"
        r"\b([A-Za-z0-9._+-]+)\s+(?:application\s+)?version\b",
        intent,
        flags=re.I,
    )
    if not match:
        return None
    token = next((group for group in match.groups() if group), None)
    if not token or token.casefold() in _APP_NAME_STOPWORDS:
        return None
    return token


def docker_target_from_intent(intent: str) -> str | None:
    """Container or image name from quotes, 'named X', or 'stop X container'."""

    quoted = _quoted_name_from_intent(intent)
    if quoted and quoted.casefold() not in {"container", "image", "docker", "the", "a"}:
        return quoted
    named = re.search(
        r"(?i)(?:container|image)\s+named\s+[\"']?([A-Za-z0-9][A-Za-z0-9._/-]*)",
        intent,
    )
    if named:
        return named.group(1)
    named = re.search(r"(?i)\bnamed\s+[\"']?([A-Za-z0-9][A-Za-z0-9._/-]*)", intent)
    if named and named.group(1).casefold() not in {"the", "a", "an", "container", "image"}:
        return named.group(1)
    match = re.search(
        r"(?i)\b(?:stop|start|remove|delete|rm)\s+(?:the\s+)?(?:docker\s+)?"
        r"(?:container\s+)?[\"']?([A-Za-z0-9][A-Za-z0-9._/-]*)(?:\s+container)?\b",
        intent,
    )
    if match:
        token = match.group(1)
        if token.casefold() not in {"the", "a", "an", "this", "that", "container", "image", "docker"}:
            return token
    return None


def _quoted_name_from_intent(intent: str) -> str | None:
    match = re.search(r"['`]([^'`]+)['`]|\"([^\"]+)\"", intent)
    if not match:
        return None
    return (match.group(1) or match.group(2) or "").strip() or None


def _filename_from_intent(intent: str) -> str | None:
    filenames = _filenames_from_intent(intent)
    if filenames:
        return filenames[0]
    match = re.search(r"(?i)(?:named|called|with name|has)\s+['\"]?([A-Za-z0-9._+-]+)['\"]?", intent)
    if not match:
        return None
    token = match.group(1)
    if token.casefold() in {"the", "a", "an", "this", "that", "any", "file", "folder", "directory"}:
        return None
    return token


# Suffixes that end an address rather than a file. A path separator or a scheme
# settles it either way, so only the bare "name.suffix" case needs this.
_ADDRESS_SUFFIXES = frozenset((
    "com", "org", "net", "io", "dev", "ai", "co", "in", "uk", "us", "eu", "de", "fr",
    "edu", "gov", "mil", "int", "app", "me", "tv", "news", "xyz", "info", "biz", "online",
    "site", "shop", "cloud", "tech", "store", "blog", "live", "world", "today", "gg",
))


def _looks_like_a_domain(value: str) -> bool:
    if "/" in value:
        return False
    suffix = value.rsplit(".", 1)[-1].casefold()
    return suffix in _ADDRESS_SUFFIXES


def _filenames_from_intent(intent: str) -> list[str]:
    """Return explicit file paths in mention order, without guessing names.

    Multiple paths matter for comparisons: a single-file native shortcut would
    otherwise claim to plan a comparison after inspecting only the first file.
    """

    pattern = r"(?<![\w./-])((?:[A-Za-z0-9_.+-]+[\\/])*[A-Za-z0-9_.+-]+\.[A-Za-z0-9]{1,8})\b"
    found: list[str] = []
    for match in re.finditer(pattern, intent):
        value = match.group(1).replace("\\", "/")
        if _looks_like_a_domain(value):
            # apple.com has the shape of a filename and is not one. Reading it as a
            # path turns "open apple.com" into a hunt for files that never existed.
            continue
        if value not in found:
            found.append(value)
    return found


def intent_is_file_edit(intent: str) -> bool:
    """True when the user asked to change an existing workspace file, not merely read it."""

    if intent_is_delete(intent) or intent_is_file_create(intent):
        return False
    text = normalize_intent_text(intent)
    has_file = bool(_filename_from_intent(intent) or re.search(
        r"\b(file|script|program|code|source)\b", text,
    ))
    if not has_file:
        return False
    if re.search(r"\b(edit|modify|update|patch|prepend|append|insert)\b", text):
        return True
    if re.search(r"\b(change|replace)\b", text):
        return True
    if re.search(
        r"\badd\b.{0,80}\b(to|into|at the top|at the bottom|at the start|at the end|"
        r"before|after|existing)\b",
        text,
    ):
        return True
    return False


def file_edit_target(intent: str) -> str | None:
    if not intent_is_file_edit(intent):
        return None
    return _filename_from_intent(intent)


def intent_is_file_read(intent: str) -> bool:
    """True when the user asked to view an existing file, not create or edit it."""

    if intent_is_file_edit(intent) or intent_is_file_create(intent) or intent_is_delete(intent):
        return False
    text = normalize_intent_text(intent)
    has_name = bool(_filename_from_intent(intent))
    has_body = bool(re.search(r"\b(contents?|source|file|script|code)\b", text))
    if not has_name and not has_body:
        return False
    return bool(re.search(r"\b(read|cat|show|display|print|view|dump)\b", text))


def _glob_from_intent(intent: str) -> str | None:
    match = re.search(r"(?i)files matching\s+[\"']?([*\w.?-]+)[\"']?", intent)
    if match:
        return match.group(1)
    match = re.search(r"(\*[\w.?*]+|[\w.?-]+\.\*)", intent)
    if match:
        return match.group(1)
    return None


def _symbol_from_intent(intent: str) -> str | None:
    match = re.search(
        r"(?i)(?:function|class|def|symbol)\s+[\"']?([A-Za-z_][\w]*)",
        intent,
    )
    if match:
        token = match.group(1)
        if token.casefold() not in {"named", "called", "the", "a", "this"}:
            return token
    match = re.search(
        r"(?i)(?:where is|definition of|inspect(?: the)?)\s+[\"']?([A-Za-z_][\w]*)",
        intent,
    )
    if match:
        token = match.group(1)
        if token.casefold() not in {
            "function", "class", "symbol", "the", "a", "this", "file", "its", "it",
            "that", "code", "container", "docker", "model", "network", "image", "git",
            "repo", "branch",
        }:
            return token
    return None


def intent_content_needles(intent: str) -> list[str]:
    """Literal strings the critic can look for after a mutation. Never invents source."""

    needles: list[str] = []
    for span in _quoted_spans(intent):
        if re.fullmatch(r"[\w.+-]+\.[A-Za-z0-9]{1,8}", span):
            continue
        if span.strip():
            needles.append(span.strip())
    return needles


def apply_known_file_edit(intent: str, path: str, original: str) -> str | None:
    """Exact quoted replace only. Invented prepends/appends belong to the model + critic."""

    text = normalize_intent_text(intent)
    quotes = [span for span in _quoted_spans(intent)
              if not re.fullmatch(r"[\w.+-]+\.[A-Za-z0-9]{1,8}", span)]
    old = new = None
    quoted_swap = re.search(
        r"""(?is)replace\s+[\"']([^\"']+)[\"']\s+with\s+[\"']([^\"']+)[\"']""",
        intent,
    )
    if quoted_swap:
        old, new = quoted_swap.group(1), quoted_swap.group(2)
    elif len(quotes) >= 2 and re.search(r"\b(replace|change)\b", text):
        old, new = quotes[0], quotes[1]
    else:
        token_swap = re.search(r"(?i)\breplace\s+(\S+)\s+with\s+(\S+)", intent)
        if token_swap:
            old, new = token_swap.group(1).strip("\"'"), token_swap.group(2).strip("\"',.")
    if old and new is not None and old in original:
        return original.replace(old, new, 1)
    return None


def workspace_run_from_intent(intent: str) -> dict[str, Any] | None:
    """Argv-safe interpreter/script run. None when this is a create/edit/delete ask."""

    if intent_is_file_edit(intent) or extract_file_write(intent) or intent_is_delete(intent):
        return None
    text = normalize_intent_text(intent)
    if not re.search(r"\b(run|execute|launch)\b", text):
        return None
    if re.search(r"\b(tests?|pytest|unittest)\b", text):
        return None
    name = _filename_from_intent(intent)
    if not name or "/" in name or ".." in name:
        return None
    suffix = Path(name).suffix.casefold()
    if suffix == ".py":
        return {"executable": "python3", "args": [name], "cwd": "."}
    if suffix in {".sh", ".bash", ".zsh"}:
        return {"executable": "bash", "args": [name], "cwd": "."}
    if suffix in {".js", ".mjs"}:
        return {"executable": "node", "args": [name], "cwd": "."}
    return None


# Frontier-style tool families: one specialized contract per job, like Claude/Codex.
TOOL_FAMILIES: dict[str, tuple[tuple[str, str], ...]] = {
    "read": (("read_file", "read"), ("filesystem", "read")),
    "write": (("write_file", "write"), ("filesystem", "write")),
    "edit": (("edit_file", "edit"), ("write_file", "write")),
    "delete": (("filesystem", "delete"),),
    "search": (("search_code", "search"),),
    "glob": (("repo_map", "find"), ("repo_map", "map")),
    "run": (("shell", "run"),),
    "test": (("run_tests", "run"),),
    "inspect": (("inspect_symbol", "inspect"), ("diagnostics", "check")),
}


def intent_tool_family(intent: str) -> str:
    """Which specialized tool family this ask needs. host = OS metadata, not workspace CRUD."""

    if intent_is_delete(intent) or extract_file_delete(intent):
        return "delete"
    if intent_is_file_edit(intent):
        return "edit"
    if extract_file_write(intent) or intent_is_file_create(intent) or intent_is_site_create(intent):
        return "write"
    if workspace_run_from_intent(intent):
        return "run"
    if intent_host_domain(intent):
        return "host"
    text = normalize_intent_text(intent)
    if re.search(r"\brun(?:ning)? (?:the )?(tests?|pytest|unittest|test suite)\b", text):
        return "test"
    if _symbol_from_intent(intent):
        return "inspect"
    if wants_content_search(intent):
        return "search"
    if is_name_find_intent(intent) or _glob_from_intent(intent):
        return "glob"
    if intent_is_file_read(intent):
        return "read"
    return "host"


def _root_from_intent(intent: str) -> str | None:
    text = intent.casefold()
    home = __import__("pathlib").Path.home()
    if "download" in text:
        return str(home / "Downloads")
    if "desktop" in text:
        return str(home / "Desktop")
    if "application" in text and "folder" in text:
        return "/Applications"
    if "documents" in text:
        return str(home / "Documents")
    return None


def is_shell_cd_intent(intent: str) -> bool:
    """True when the user asked TACU to change *this* shell's working directory."""

    text = " ".join(intent.casefold().split())
    return bool(re.search(
        r"\b(?:cd|chdir)\b|change(?: the)? directory|take me to|cd me into|"
        r"(?:move|put) me (?:in|into|to)|go into the",
        text,
    ))


def directory_target_from_intent(intent: str) -> "Path":
    from pathlib import Path
    root = _root_from_intent(intent)
    if root:
        return Path(root)
    if re.search(r"\bhome\b", intent.casefold()):
        return Path.home()
    return Path.home() / "Desktop"


_CODE_SUFFIXES = {
    ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".tsx", ".rb", ".go",
    ".rs", ".java", ".c", ".h", ".cpp", ".cs",
}
_CODING_TOOLS = {"read_file", "write_file", "edit_file", "search_code", "repo_map", "inspect_symbol"}
_WORKSPACE_NATIVE_TOOLS = _CODING_TOOLS | {"run_tests", "diagnostics", "shell"}


def is_name_find_intent(intent: str) -> bool:
    """True for filename/folder discovery, not content search."""

    text = normalize_intent_text(intent)
    if any(phrase in text for phrase in (
        "file named", "folder named", "directory named", "directory called",
        "folder called", "images on", "all images", "in its name",
        "file which has", "folder which has", "photos on",
    )):
        return True
    if any(word in text for word in ("desktop", "download", "documents")) and not any(
            word in text for word in ("todo", "grep", "search code", "search files")):
        return True
    return False


def prefers_coding_write(intent: str, path: str) -> bool:
    """Prefer write_file for scripts/source; filesystem.write for notes and HTML."""

    if intent_is_site_create(intent):
        return False
    suffix = Path(path).suffix.casefold()
    if suffix in _CODE_SUFFIXES:
        return True
    text = normalize_intent_text(intent)
    return any(phrase in text for phrase in (
        "python script", "python program", "shell script", "source file", "create a python",
        "write a script", "bash script", "program file",
    ))


def coding_file_create_spec(intent: str) -> dict[str, Any] | None:
    """Filename + body slots when the user asked to create a source or script file."""

    spec = extract_file_write(intent)
    if spec and prefers_coding_write(intent, spec["name"]):
        return spec
    return None


_DIR_MAP_SH = """#!/bin/sh
set -eu
root="${1:-.}"
if [ ! -d "$root" ]; then
  echo "Not a directory: $root" >&2
  exit 1
fi
find "$root" | sort
"""

_DIR_MAP_PY = '''#!/usr/bin/env python3
"""Print a recursive map of a directory tree."""
from __future__ import annotations

import os
import sys


def map_directory(root: str) -> None:
    if not os.path.isdir(root):
        raise SystemExit(f"Not a directory: {root}")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        print(dirpath)
        for name in sorted(filenames):
            print(os.path.join(dirpath, name))


if __name__ == "__main__":
    map_directory(sys.argv[1] if len(sys.argv) > 1 else ".")
'''


def _wants_directory_map_script(intent: str) -> bool:
    text = normalize_intent_text(intent)
    has_dir = bool(re.search(r"\b(director(?:y|ies)|folder|folders)\b", text))
    has_map = bool(re.search(r"\b(maps?|tree)\b", text))
    return has_dir and has_map


def script_body_for_intent(intent: str, name: str) -> str | None:
    """High-confidence native source for common create-script asks.

    Arbitrary programs still come from the model. OS-critical paths stay blocked
    by write_file; this only fills a workspace file body.
    """

    suffix = Path(name).suffix.casefold()
    if not _wants_directory_map_script(intent):
        return None
    if suffix == ".sh":
        return _DIR_MAP_SH
    if suffix == ".py":
        return _DIR_MAP_PY
    return None


def wants_content_search(intent: str) -> bool:
    """True for searching inside files, not creating files or finding by name."""

    if is_name_find_intent(intent):
        return False
    if extract_file_write(intent):
        return False
    text = normalize_intent_text(intent)
    return bool(
        re.search(r"\b(search|grep|ripgrep|todo|fixme)\b", text)
        or re.search(r"\bfind\s+(text|code|todo)\b", text)
        or "text in files" in text
    )


def search_query_from_intent(intent: str) -> str | None:
    if not wants_content_search(intent):
        return None
    quotes = _quoted_spans(intent)
    if quotes:
        first = quotes[0]
        if not re.fullmatch(r"[\w.+-]+\.[A-Za-z0-9]{1,8}", first):
            return first
    text = normalize_intent_text(intent)
    for token in ("todo", "fixme"):
        if re.search(rf"\b{token}\b", text):
            return token.upper()
    match = re.search(
        r"(?i)(?:search(?:\s+(?:the\s+)?code)?(?:\s+for)?|grep(?:\s+for)?|"
        r"find(?:\s+(?:text|code))?)\s+[\"']?([\w.+-]+)[\"']?",
        intent,
    )
    if match:
        token = match.group(1)
        if token.casefold() not in {"the", "a", "an", "all", "this", "files", "code", "text", "markers"}:
            return token
    return None


def _coding_native_inputs(capability: Capability, intent: str, filename: str | None,
                          quoted: str | None) -> dict[str, Any] | None:
    if capability.tool == "search_code":
        if is_name_find_intent(intent) or not wants_content_search(intent):
            return None
        query = search_query_from_intent(intent)
        if not query:
            return None
        return {"query": query, "path": ".", "regex": False, "case_sensitive": False}
    if capability.tool == "read_file":
        if intent_is_file_edit(intent) or extract_file_write(intent) or intent_is_delete(intent):
            return None
        path = filename or quoted
        if not path or not re.search(r"\.[A-Za-z0-9]{1,8}$", path):
            path = _filename_from_intent(intent)
        if not path:
            return None
        return {"path": path, "start_line": 1}
    if capability.tool == "write_file":
        spec = extract_file_write(intent)
        if not spec or not prefers_coding_write(intent, spec["name"]):
            return None
        content = str(spec.get("content") or "")
        if not content.strip():
            content = script_body_for_intent(intent, spec["name"]) or ""
        if not content.strip():
            return None
        return {"path": spec["name"], "content": content, "overwrite": True, "create_parents": True}
    if capability.tool == "edit_file":
        return None
    if capability.tool == "inspect_symbol":
        symbol = _symbol_from_intent(intent)
        if not symbol:
            return None
        path = filename if filename and Path(filename).suffix.casefold() in _CODE_SUFFIXES else "."
        return {"symbol": symbol, "path": path, "references": True}
    if capability.tool == "run_tests":
        if not re.search(r"\b(tests?|pytest|unittest)\b", normalize_intent_text(intent)):
            return None
        return {"target": ".", "framework": "auto"}
    if capability.tool == "diagnostics":
        path = filename or quoted
        if not path:
            return None
        return {"path": path}
    if capability.tool == "shell":
        return workspace_run_from_intent(intent)
    if capability.tool == "repo_map":
        if is_name_find_intent(intent) and "project" not in normalize_intent_text(intent):
            return None
        if capability.operation == "find":
            name = _glob_from_intent(intent) or filename or quoted
            if not name:
                return None
            kind = "directory" if "director" in normalize_intent_text(intent) or "folder" in normalize_intent_text(intent) else "file"
            return {"root": ".", "name": name, "kind": kind, "depth": 20}
        return {"root": ".", "depth": 3}
    return None


def _entity_hit(text: str, entity: str) -> bool:
    return bool(re.search(rf"\b{re.escape(entity)}s?\b", text))


def score_capability(intent: str, capability: Capability) -> int:
    text = normalize_intent_text(intent)
    score = 0
    phrase_hit = False
    for phrase in capability.phrases:
        if phrase in text:
            score += 50
            phrase_hit = True
    hits = sum(1 for entity in capability.entities if _entity_hit(text, entity))
    if hits:
        score += 12 * hits
    domain = intent_host_domain(intent)
    if capability.tool == "forensics" and phrase_hit:
        # A forensic question names the thing at risk — git, docker, aws credentials —
        # without being a question about that tool. Its own phrasing decides it.
        return score
    if domain:
        if capability.tool == domain:
            score += 15
        elif capability.tool in _CODING_TOOLS:
            score -= 140
        elif domain == "ollama" and capability.tool == "process":
            score -= 140
        elif capability.tool != domain:
            score -= 80
    cpuish = any(word in text for word in ("cpu", "processing", "processor", "%cpu", "compute"))
    if capability.tool == "process" and "process" in text and cpuish:
        score += 20
    if capability.tool == "process" and "process" in text and any(word in text for word in ("ram", "memory")):
        score += 20
    if capability.operation == "top_cpu" and any(word in text for word in ("ram", "memory", "rss")) and not cpuish:
        score -= 80
    if capability.operation == "top_memory" and any(word in text for word in ("ram", "memory", "rss")):
        score += 35
    if capability.operation == "top_cpu" and "top" in text and "process" in text:
        score += 35
    if capability.operation == "top_cpu" and cpuish:
        score += 30
    if capability.operation == "connections" and "destination" in text:
        score += 25
    if capability.operation == "top_cpu" and not cpuish and "top" not in text:
        score -= 40
    if capability.tool == "process" and capability.operation == "graph":
        # "is vite running", "is my dev server still running" — asking whether one
        # named thing is up, which the listing operations cannot answer.
        if re.search(r"\bis\s+\S.{0,30}?\brunning\b", text):
            score += 50
        # A ranking or a plain listing is answered better by the operations built
        # for it; the graph is for finding a particular thing.
        if any(word in text for word in ("top ", "highest", "most cpu", "most memory",
                                         "consuming", "as per memory", "by memory", "by cpu")):
            score -= 60
        if re.search(r"\b(?:list|show)\s+(?:all\s+)?(?:running\s+)?process(?:es)?\b", text):
            score -= 60
    if capability.operation == "list" and capability.tool == "process":
        if any(word in text for word in ("top", "cpu", "memory", "ram", "rss", "processing")):
            score -= 60
        elif not phrase_hit and "list" not in text and "all process" not in text:
            # A curated phrase already decided this is a listing question.
            score -= 40
    if capability.operation == "inspect" and capability.tool == "process":
        # Inspecting one process only makes sense when the question names one.
        if _pid_from_intent(intent) is None:
            score -= 50
        if any(word in text for word in ("top", "cpu", "memory", "ram", "highest")):
            score -= 40
    if capability.risk == "host_mutate":
        if intent_wants_host_mutate(intent):
            score += 55
        else:
            score -= 80
    if capability.operation == "kill" and re.search(r"\bpid\s+\d+", text):
        score += 25
    if capability.tool == "package" and capability.operation in {"install", "upgrade", "remove"}:
        if "brew" in text or "package" in text or "formula" in text:
            score += 20
    if capability.tool == "service" and capability.operation in {"start", "stop", "restart", "inspect"}:
        if any(word in text for word in ("service", "launchd", "launchctl")):
            score += 20
    if capability.operation == "connections_by_port" and "port" in text:
        score += 25
    if capability.operation == "system_profile" and any(
            phrase in text for phrase in ("system profile", "system_profiler", "hardware profile")):
        score += 35
    if capability.operation == "tree" and not any(word in text for word in ("tree", "parent", "child")):
        score -= 50
    if capability.operation == "open_files" and "open file" not in text and "lsof" not in text:
        score -= 50
    if capability.tool == "ollama":
        if "ollama" not in text and "ollama" not in intent.casefold():
            score -= 80
        elif capability.operation == "installed_models" and any(
                phrase in text for phrase in ("model", "models", "ollama list")):
            if any(word in text for word in ("running", "loaded", "ollama ps")):
                score -= 30
            else:
                score += 55
        elif capability.operation == "running_models" and any(
                word in text for word in ("running", "loaded", "ollama ps")):
            score += 55
    if capability.tool == "application":
        install_ask = ((".app" in text) or ("install date" in text)
                       or ("when was" in text and "installed" in text))
        if not any(word in text for word in ("app", "application", "version")) and not install_ask:
            score -= 40
        elif install_ask and capability.operation == "metadata":
            score += 35
    if capability.operation == "hostname":
        if intent_wants_dns_lookup(intent):
            score -= 120
        elif any(phrase in text for phrase in ("hostname", "system name", "computer name", "machine name", "host name")):
            score += 25
        else:
            score -= 50
    if capability.operation == "resolve":
        if intent_wants_dns_lookup(intent) or _host_from_intent(intent):
            score += 45
        else:
            score -= 40
    if capability.operation == "public_ip":
        if any(phrase in text for phrase in ("public ip", "external ip", "wan ip", "internet traffic",
                                             "internet ip", "public address")):
            score += 40
        else:
            score -= 60
    if capability.operation == "interfaces":
        if any(phrase in text for phrase in ("public ip", "external ip", "wan ip", "internet traffic",
                                             "internet ip", "public address")):
            score -= 80
        elif any(phrase in text for phrase in ("ip address", "my ip", "primary ip")):
            score += 20
    if capability.tool == "application" and capability.operation == "open":
        # An openable name plus an opening verb is what an open request looks like;
        # no list of application names is needed to recognise one.
        if app_to_open_from_intent(intent) or url_from_intent(intent):
            score += 60
        else:
            score -= 40
    if capability.tool == "docker" and "docker" not in text and "container" not in text:
        score -= 80
    if capability.tool == "docker" and capability.operation == "inspect":
        if any(word in text for word in ("inspect", "network", "base image", "details")):
            score += 35
        else:
            score -= 45
    if capability.tool == "docker" and capability.operation == "images" and "inspect" in text:
        score -= 50
    if capability.tool == "docker" and capability.operation == "containers" and "running" in text and "stopped" not in text:
        score -= 80
    if capability.tool == "docker" and capability.operation in {"start", "stop"} and capability.operation in text and "container" in text:
        score += 80
    if capability.tool == "git" and "git" not in text:
        score -= 80
    if capability.operation == "find_repos" and "find" not in text and "directories" not in text:
        score -= 40
    if capability.operation == "is_repo" and "find" in text:
        score -= 30
    if capability.tool == "filesystem" and "computer" in text:
        score -= 80
    if capability.tool == "filesystem" and re.search(r"\bcd\b|change(?: the)? directory", text):
        score -= 80
    if capability.tool == "filesystem" and capability.operation == "open" and "open" not in text:
        score -= 50
    if capability.tool == "filesystem" and capability.operation == "find":
        if any(word in text for word in ("desktop", "download", "documents")):
            score += 40
        if any(word in text for word in ("image", "photo", "png", "jpg", "jpeg")):
            score += 35
        if any(word in text for word in ("create", "write", "website", "http.server", "html", "remove", "delete")):
            score -= 80
        if not any(word in text for word in ("file", "folder", "image", "photo", "path", "named", "snake",
                                             "desktop", "download")):
            score -= 40
    if capability.tool in _CODING_TOOLS and is_name_find_intent(intent) and capability.tool != "repo_map":
        score -= 90
    if capability.tool == "search_code":
        if not wants_content_search(intent):
            score -= 90
        elif search_query_from_intent(intent):
            score += 45
        else:
            score -= 40
    if capability.tool == "repo_map":
        if coding_file_create_spec(intent):
            score -= 90
        if is_name_find_intent(intent) and "project" not in text and "repo" not in text:
            score -= 80
        if capability.operation == "map" and "map" not in text and "tree" not in text:
            score -= 40
        if capability.operation == "find":
            if _glob_from_intent(intent) or any(
                    phrase in text for phrase in ("glob", "files named", "files matching", "matching")):
                score += 40
            else:
                score -= 40
    if capability.tool == "read_file":
        if intent_is_file_edit(intent) or extract_file_write(intent) or intent_is_delete(intent):
            score -= 90
        elif intent_is_file_read(intent) and _filename_from_intent(intent):
            score += 55
        name = _filename_from_intent(intent)
        if name and Path(name).suffix.casefold() in _CODE_SUFFIXES:
            score += 40
        elif not intent_is_file_read(intent) and not any(phrase in text for phrase in capability.phrases) and "read" not in text:
            score -= 40
    if capability.tool == "inspect_symbol":
        if _symbol_from_intent(intent):
            score += 55
        else:
            score -= 50
    if capability.tool == "run_tests":
        if re.search(r"\brun(?:ning)? (?:the )?(tests?|pytest|test suite)\b", text):
            score += 55
        else:
            score -= 50
    if capability.tool == "diagnostics":
        if any(phrase in text for phrase in ("syntax", "lint", "diagnostic")):
            score += 50
        else:
            score -= 50
    if capability.tool == "shell":
        if workspace_run_from_intent(intent):
            score += 70
        else:
            score -= 80
    if capability.tool == "filesystem" and capability.operation == "read":
        if intent_is_file_edit(intent) or extract_file_write(intent):
            score -= 90
        name = _filename_from_intent(intent)
        if name and Path(name).suffix.casefold() in _CODE_SUFFIXES:
            score -= 25
    if capability.tool == "write_file":
        spec = extract_file_write(intent)
        if spec and not intent_is_delete(intent) and prefers_coding_write(intent, spec["name"]):
            score += 70
        elif intent_is_file_edit(intent):
            score += 45
        else:
            score -= 50
    if capability.tool == "edit_file":
        if intent_is_file_edit(intent) or any(
                phrase in text for phrase in ("replace", "edit the", "change the code", "old_text")):
            score += 50
        else:
            score -= 50
    if capability.tool == "filesystem" and capability.operation == "write":
        spec = extract_file_write(intent)
        if spec and not intent_is_delete(intent):
            score += 15 if prefers_coding_write(intent, spec["name"]) else 55
        else:
            score -= 80
    elif capability.operation == "write" and capability.tool not in {"write_file", "filesystem"}:
        if extract_file_write(intent) and not intent_is_delete(intent):
            score += 55
        else:
            score -= 80
    if capability.operation == "delete":
        if intent_is_delete(intent):
            score += 70
        else:
            score -= 80
    if capability.operation == "serve":
        if intent_is_delete(intent):
            score -= 80
        elif any(phrase in text for phrase in ("http.server", "chrome", "local server", "python http")):
            score += 45
        else:
            score -= 50
    if capability.operation == "cwd" and not any(
            word in text for word in ("directory", "pwd", "cwd", "workspace", "where")):
        score -= 40
    if capability.tool == "service" and not any(
            word in text for word in ("service", "launchd", "launchctl", "launch agent", "daemon")):
        score -= 80
    if capability.tool == "package" and not any(
            word in text for word in ("brew", "package", "formula", "homebrew", "cask")):
        score -= 80
    if capability.tool == "security" and not any(
            word in text for word in ("codesign", "gatekeeper", "quarantine", "sha256", "signature", "spctl", "xattr", "hash")):
        score -= 80
    if capability.operation == "storage" and not any(word in text for word in ("disk", "storage", "volume")):
        score -= 50
    if capability.operation == "power" and "battery" not in text and "power" not in text and "charg" not in text:
        score -= 50
    if capability.tool == "network" and capability.operation in {"routes", "dns", "arp", "resolve"}:
        if capability.operation not in text and capability.operation.replace("_", " ") not in text:
            if not any(phrase in text for phrase in capability.phrases):
                score -= 40
    return score


# Shared shortlist gates — native hits and planner shortlist use the same confidence bar.
SHORTLIST_MIN_SCORE = 40
SHORTLIST_LIMIT_NATIVE = 5
SHORTLIST_LIMIT_PLANNER = 7


def shortlist_capabilities(intent: str, *, limit: int = SHORTLIST_LIMIT_NATIVE,
                           min_score: int = SHORTLIST_MIN_SCORE) -> list[tuple[int, Capability]]:
    ranked = sorted(((score_capability(intent, item), item) for item in CAPABILITIES),
                    key=lambda pair: pair[0], reverse=True)
    return [(score, item) for score, item in ranked if score >= min_score][:limit]


# Words that join two separate instructions. "and" alone does not qualify: "open
# chrome and launch apple.com" is one action described in two clauses.
_CHAIN_SPLIT = re.compile(r"(?i)\s*(?:,\s*)?\b(?:and\s+then|then|after\s+that|"
                          r"once\s+(?:that\s+is\s+)?done|followed\s+by|next)\b\s*")
_REFERS_BACK = re.compile(r"(?i)\b(?:it|that|this|the file|the page|them)\b")


def chained_steps_for_intent(intent: str, *,
                             include_host_mutate: bool = False) -> list[dict[str, Any]]:
    """Plan a request that asks for more than one thing.

    The whole request is tried first, so a single action described in two clauses
    stays one step. Only when nothing matches as a whole is it split, and a later
    part that refers back ("open *it*") is pointed at what an earlier part created.
    """

    parts = [part.strip() for part in _CHAIN_SPLIT.split(intent or "") if part.strip()]
    if len(parts) < 2:
        # One instruction, however many clauses: "open chrome and launch apple.com".
        return native_steps_for_intent(intent, include_host_mutate=include_host_mutate)
    steps: list[dict[str, Any]] = []
    produced: list[str] = []
    covered = 0
    for part in parts:
        planned = native_steps_for_intent(part, include_host_mutate=include_host_mutate)
        if not planned and _REFERS_BACK.search(part) and produced:
            planned = native_steps_for_intent(
                _REFERS_BACK.sub(produced[-1], part, count=1),
                include_host_mutate=include_host_mutate)
        for step in planned:
            inputs = step.get("inputs") or {}
            # "open it" after writing index.html means that file.
            if (step.get("tool"), step.get("operation")) == ("application", "open") \
                    and produced and not inputs.get("url") and not inputs.get("path"):
                if _REFERS_BACK.search(part):
                    inputs["path"] = produced[-1]
            name = inputs.get("path") or inputs.get("name")
            if step.get("tool") in {"write_file", "filesystem"} and name:
                produced.append(str(name))
        if planned:
            covered += 1
        steps.extend(planned)
    # Every part must be planned. Returning half a chain would quietly drop the
    # instruction we could not place, which is worse than letting the planner see
    # the whole request.
    if covered == len(parts):
        return steps
    # Some part of an explicit chain has no native step. Answering with the parts we
    # do recognise would quietly drop an instruction, so hand the whole request to
    # the planner instead of doing half of it.
    return []


def native_steps_for_intent(intent: str, *, include_host_mutate: bool = False) -> list[dict[str, Any]]:
    """Native hit: definitive read recipes, plus coding file writes for scripts.

    Host mutations are included only when include_host_mutate is true (ti do).
    """

    matches = list(shortlist_capabilities(intent))
    domain = intent_host_domain(intent)
    if include_host_mutate and intent_wants_host_mutate(intent):
        seen_caps = {(item.tool, item.operation) for _score, item in matches}
        extras: list[tuple[int, Capability]] = []
        for cap in CAPABILITIES:
            if cap.risk != "host_mutate":
                continue
            if domain and cap.tool != domain:
                continue
            if (cap.tool, cap.operation) in seen_caps:
                continue
            extras.append((max(score_capability(intent, cap), SHORTLIST_MIN_SCORE + 10), cap))
        # Rank the whole field by score. Prepending the host-mutate candidates put a
        # floor-scored one ahead of a capability that actually matched the words, so
        # "launch apple.com" was answered by docker start.
        matches = sorted(extras + matches, key=lambda pair: -pair[0])
    if not matches:
        return []
    steps: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    limit = limit_from_intent(intent)
    port = _port_from_intent(intent)
    pid = _pid_from_intent(intent)
    host = _host_from_intent(intent)
    app = _app_name_from_intent(intent)
    quoted = _quoted_name_from_intent(intent)
    filename = _filename_from_intent(intent)
    explicit_files = _filenames_from_intent(intent)
    docker_name = docker_target_from_intent(intent)
    root = _root_from_intent(intent)
    coding_create = coding_file_create_spec(intent) is not None
    editing = intent_is_file_edit(intent)
    write_spec = extract_file_write(intent)
    delete_spec = extract_file_delete(intent)
    if intent_is_file_read(intent) and len(explicit_files) > 1:
        return [
            {
                "tool": "read_file",
                "operation": "read",
                "inputs": {"path": path, "start_line": 1},
                "purpose": f"Read {path} for the requested multi-file comparison",
                "score": SHORTLIST_MIN_SCORE + 40,
            }
            for path in explicit_files[:3]
        ]
    for score, capability in matches:
        if coding_create and capability.tool != "write_file":
            continue
        if editing and capability.operation == "read":
            continue
        note_write = (
            capability.tool == "filesystem" and capability.operation == "write"
            and write_spec and write_spec.get("content_supplied")
            and not prefers_coding_write(intent, write_spec["name"])
            and not intent_is_site_create(intent)
        )
        named_delete = capability.tool == "filesystem" and capability.operation == "delete" and delete_spec
        coding_write = capability.tool == "write_file"
        workspace_run = capability.tool == "shell" and workspace_run_from_intent(intent)
        allow_this_mutate = (
            include_host_mutate and capability.risk == "host_mutate" and intent_wants_host_mutate(intent)
            and (not domain or capability.tool == domain)
        )
        if capability.risk != "read" and not coding_write and not note_write and not named_delete and not workspace_run and not allow_this_mutate:
            continue
        domain = intent_host_domain(intent)
        if domain and capability.tool in _CODING_TOOLS:
            continue
        # Forensics is deliberately cross-domain: "is something stealing my git
        # credentials" names git but is not a question for the git tool.
        if domain and capability.tool != domain and capability.tool != "forensics":
            continue
        if capability.operation == "serve":
            continue
        if capability.operation == "write" and capability.tool == "filesystem" and not note_write:
            continue
        key = (capability.tool, capability.operation)
        if key in seen:
            continue
        seen.add(key)
        if capability.tool in _WORKSPACE_NATIVE_TOOLS:
            built = _coding_native_inputs(capability, intent, filename, quoted)
            if built is None:
                continue
            steps.append({
                "tool": capability.tool,
                "operation": capability.operation,
                "inputs": built,
                "purpose": capability.purpose,
                "score": score,
            })
            if len(steps) >= 3:
                break
            continue
        inputs: dict[str, Any] = {"operation": capability.operation}
        if capability.tool in {"process", "network", "filesystem", "git"}:
            if capability.operation not in {"write", "serve", "delete"}:
                inputs["limit"] = limit
        if capability.tool == "application":
            inputs["limit"] = limit_from_intent(intent, default=40)
        if capability.operation in {"connections", "port_owner"} and port:
            inputs["port"] = port
        if capability.tool == "application" and capability.operation == "open":
            wanted = app_to_open_from_intent(intent)
            address = url_from_intent(intent)
            if not wanted and not address:
                continue
            if wanted:
                inputs["name"] = wanted
            if address:
                inputs["url"] = address
            inputs.pop("limit", None)
        if capability.tool == "process" and capability.operation == "graph":
            if port:
                inputs["port"] = port
            elif pid is not None:
                inputs["pid"] = pid
            else:
                needle = process_query_from_intent(intent)
                if needle:
                    inputs["query"] = needle
        if capability.operation == "connections":
            inputs["state"] = connection_state_from_intent(intent)
            # A named host turns a ranking into a yes/no question about that host.
            if host:
                inputs["host"] = host
        if (capability.tool == "application" and app and capability.operation != "list"
                and not inputs.get("name")):
            inputs["name"] = app
        if capability.tool == "application" and capability.operation != "list" and not inputs.get("name"):
            continue
        if capability.tool == "filesystem":
            name = filename or quoted
            if name and capability.operation != "write":
                inputs["name"] = name
            if root:
                inputs["root"] = root
            if "image" in intent.casefold():
                inputs["glob"] = "images"
            if capability.operation == "write":
                spec = extract_file_write(intent)
                if not spec:
                    continue
                inputs["name"] = spec["name"]
                inputs["content"] = spec["content"]
                inputs["overwrite"] = True
            if capability.operation == "delete":
                spec = extract_file_delete(intent)
                if not spec:
                    continue
                inputs["name"] = spec["name"]
            if capability.operation == "serve":
                inputs["port"] = 8000
                inputs["open_browser"] = any(
                    word in intent.casefold() for word in ("chrome", "browser", "safari", "firefox")
                )
            if capability.operation == "find" and not inputs.get("name") and inputs.get("glob") != "images":
                continue
            if capability.operation in {"open", "read", "metadata", "size", "hash", "permissions", "disk_usage"} and not inputs.get("name") and capability.operation != "disk_usage":
                if capability.operation in {"open", "read"}:
                    continue
        if capability.tool == "git" and root:
            inputs["root"] = root
        if capability.tool in {"service", "package"} and capability.operation not in {"list", "outdated"}:
            label = filename or quoted or app
            if not label:
                continue
            inputs["name"] = label
        if capability.tool == "docker" and capability.operation in {"logs", "stats", "start", "stop", "rm", "rmi", "pull"}:
            label = docker_name or quoted or filename or app
            if not label:
                continue
            inputs["name"] = label
        if capability.tool == "docker" and capability.operation == "inspect":
            label = docker_name or quoted or filename or app
            if label:
                inputs["name"] = label
        if capability.tool == "ollama" and capability.operation in {"model_info", "pull", "rm", "stop"}:
            label = quoted or filename or app
            if not label:
                continue
            inputs["name"] = label
        if capability.tool == "git" and capability.operation == "add":
            label = filename or quoted
            if not label:
                continue
            inputs["name"] = label
        if capability.tool == "git" and capability.operation == "commit":
            quotes = _quoted_spans(intent)
            msg = quotes[0] if quotes else None
            if not msg:
                continue
            inputs["message"] = msg
        if capability.tool == "security":
            target = filename or quoted
            if capability.operation not in {"gatekeeper"} and not target and pid is None:
                continue
            if target:
                inputs["path"] = target
            if pid is not None:
                inputs["pid"] = pid
        if capability.operation == "resolve":
            if not host:
                continue
            inputs["host"] = host
        if capability.operation in {"open_files", "tree", "inspect", "process_signature"} and pid is not None:
            inputs["pid"] = pid
        if capability.operation == "open_files" and pid is None:
            continue
        if capability.operation == "find" and capability.tool == "process":
            name = app or re.search(r"(?i)process (?:named|called) ([\w.+-]+)", intent)
            if not name:
                continue
            inputs["query"] = name if isinstance(name, str) else name.group(1)
        steps.append({
            "tool": capability.tool,
            "operation": capability.operation,
            "inputs": inputs,
            "purpose": capability.purpose,
            "score": score,
        })
        if len(steps) >= 3:
            break
    if include_host_mutate:
        mutate_steps = [
            item for item in steps
            if (item["tool"], item["operation"]) in HOST_MUTATE_KEYS
        ]
        if mutate_steps:
            return mutate_steps[:1]
    if any(item["tool"] == "docker" and item["operation"] == "ps" for item in steps):
        steps = [item for item in steps if not (item["tool"] == "docker" and item["operation"] == "containers")]
    if any(item["operation"] == "listing" for item in steps):
        steps = [item for item in steps if item["operation"] != "cwd"]
    return steps


def native_inputs_json(inputs: dict[str, Any]) -> str:
    return json.dumps(inputs, separators=(",", ":"), sort_keys=True)
