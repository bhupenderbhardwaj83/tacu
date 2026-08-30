"""Machine readiness, model checks, and user workspace configuration."""

from __future__ import annotations

import ctypes
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .core import DEFAULT_BACKUP_MODEL, DEFAULT_MODEL, TacuError, app_home

MIN_RAM_GB = 16
RECOMMENDED_RAM_GB = 32
# First install (models / Docker image may still download): keep headroom.
MIN_DISK_GB_FULL = 40
# Stack already present (Ollama + Docker Desktop + required Gemma): lighter floor.
MIN_DISK_GB_READY = 20
# Back-compat alias used by older call sites; prefer required_disk_gb().
MIN_DISK_GB = MIN_DISK_GB_FULL
SEARXNG_IMAGE = "searxng/searxng:latest"
SEARXNG_CONTAINER = "tacu-searxng"
SEARXNG_PREFERRED_PORT = 8080
SEARXNG_PORT_SPAN = 20
DEFAULT_SEARXNG_URL = f"http://127.0.0.1:{SEARXNG_PREFERRED_PORT}"
SEARXNG_SETTINGS = """use_default_settings: true
server:
  limiter: false
  bind_address: "0.0.0.0"
  secret_key: "{secret}"
search:
  formats:
    - html
    - json
"""
DEFAULT_CONTEXT_TURNS = 5
MAX_CONTEXT_TURNS = 100
OLLAMA_PINNED_VERSION = "0.32.14"
OLLAMA_MLX_MIN_VERSION = (0, 32, 14)
PRIMARY_MODEL = DEFAULT_MODEL
PRIMARY_MODEL_GENERIC = "gemma4:12b"
BACKUP_MODEL = DEFAULT_BACKUP_MODEL


def is_apple_silicon() -> bool:
    return sys.platform == "darwin" and platform.machine().lower() in {"arm64", "aarch64"}


def required_models() -> tuple[str, ...]:
    """Primary Gemma plus the coding backup. Setup installs only one (Gemma) unless one is already present."""

    return preferred_models()


def preferred_models() -> tuple[str, str]:
    return (default_chat_model(), BACKUP_MODEL)


def chosen_chat_model(installed: set[str] | None = None) -> str | None:
    """Prefer Gemma when both exist; otherwise whichever of the two is already installed."""

    models = installed if installed is not None else ollama_models()
    primary, backup = preferred_models()
    if primary in models:
        return primary
    if backup in models:
        return backup
    return None


def default_chat_model() -> str:
    """Primary chat model for this machine. Install it during setup if it is missing."""

    return PRIMARY_MODEL if is_apple_silicon() else PRIMARY_MODEL_GENERIC


# Kept for tests/imports that still reference the constant name.
REQUIRED_MODELS = required_models()


@dataclass(frozen=True)
class Readiness:
    os: str
    architecture: str
    python: str
    ram_gb: float | None
    disk_free_gb: float
    disk_required_gb: int
    ram_ok: bool
    disk_ok: bool
    ollama_installed: bool
    ollama_mlx_ok: bool
    ollama_version: str | None
    docker_installed: bool
    searxng_image: bool
    searxng_running: bool
    required_models: dict[str, bool]
    workspace: str | None
    tacu_on_path: bool

    @property
    def prerequisites_ok(self) -> bool:
        return self.ram_ok and self.disk_ok

    @property
    def ready(self) -> bool:
        models_ok = any(self.required_models.values())
        mlx_ok = self.ollama_mlx_ok if is_apple_silicon() else True
        return (
            self.prerequisites_ok
            and self.ollama_installed
            and mlx_ok
            and models_ok
            and self.docker_installed
            and self.searxng_image
            and self.searxng_running
            and bool(self.workspace)
            and self.tacu_on_path
        )

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["prerequisites_ok"] = self.prerequisites_ok
        result["ready"] = self.ready
        result["required_model_names"] = list(required_models())
        result["apple_silicon"] = is_apple_silicon()
        return result


def physical_memory_gb() -> float | None:
    try:
        if sys.platform == "darwin":
            try:
                value = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, stderr=subprocess.DEVNULL).strip()
                return round(int(value) / 1024**3, 1)
            except (OSError, ValueError, subprocess.SubprocessError):
                return round(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 1024**3, 1)
        if sys.platform.startswith("linux"):
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return round(int(line.split()[1]) * 1024 / 1024**3, 1)
        if os.name == "nt":
            class MemoryStatus(ctypes.Structure):
                _fields_ = [("length", ctypes.c_ulong), ("memory_load", ctypes.c_ulong),
                            ("total_physical", ctypes.c_ulonglong), ("available_physical", ctypes.c_ulonglong),
                            ("total_page_file", ctypes.c_ulonglong), ("available_page_file", ctypes.c_ulonglong),
                            ("total_virtual", ctypes.c_ulonglong), ("available_virtual", ctypes.c_ulonglong),
                            ("available_extended_virtual", ctypes.c_ulonglong)]
            status = MemoryStatus(); status.length = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return round(status.total_physical / 1024**3, 1)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def config_path() -> Path:
    return app_home() / "config.json"


def load_config() -> dict[str, Any]:
    try: return json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError): return {}


def save_config(content: dict[str, Any]) -> None:
    target = config_path()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".config.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(content, stream, indent=2)
            stream.write("\n")
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def configured_model() -> str | None:
    value = load_config().get("model")
    return value if isinstance(value, str) and value else None


def configured_context_turns() -> int:
    value = load_config().get("context_turns", DEFAULT_CONTEXT_TURNS)
    return value if isinstance(value, int) and 0 <= value <= MAX_CONTEXT_TURNS else DEFAULT_CONTEXT_TURNS


def save_context_turns(value: int) -> int:
    if not 0 <= value <= MAX_CONTEXT_TURNS:
        raise TacuError(f"Context turns must be between 0 and {MAX_CONTEXT_TURNS}.")
    content = load_config()
    content["context_turns"] = value
    save_config(content)
    return value


def clear_companion_preferences() -> None:
    content = load_config()
    content.pop("model", None)
    content.pop("context_turns", None)
    save_config(content)


def save_model(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?", name):
        raise TacuError(f"Invalid model name: {name}")
    content = load_config()
    content["model"] = name
    save_config(content)
    return name


def clear_model() -> None:
    content = load_config()
    content.pop("model", None)
    save_config(content)


def save_workspace(path: Path) -> Path:
    workspace = path.expanduser().resolve()
    if workspace == Path(workspace.anchor):
        raise TacuError("A drive or filesystem root cannot be a TACU project workspace.")
    protected = (("System", "Library", "usr", "bin", "sbin", "etc", "private/etc")
                 if os.name != "nt" else ("Windows", "Program Files", "Program Files (x86)"))
    root = Path(workspace.anchor)
    if any(workspace == root / item or (root / item) in workspace.parents for item in protected):
        raise TacuError(f"System directories cannot be used as a TACU project workspace: {workspace}")
    workspace.mkdir(parents=True, exist_ok=True)
    content = load_config()
    content["workspace"] = str(workspace)
    save_config(content)
    return workspace


def configured_workspace() -> Path | None:
    value = load_config().get("workspace")
    return Path(value) if isinstance(value, str) and value else None


def ollama_models() -> set[str]:
    if not shutil.which("ollama"): return set()
    try:
        completed = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError): return set()
    return {line.split()[0] for line in completed.stdout.splitlines()[1:] if line.split()}


def ollama_version_text() -> str | None:
    ollama = shutil.which("ollama")
    if not ollama:
        return None
    try:
        output = subprocess.run([ollama, "--version"], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"\b\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?\b", output)
    return f"Ollama {match.group(0)}" if match else (output.splitlines()[-1] if output else None)


def ollama_version_tuple() -> tuple[int, int, int] | None:
    text = ollama_version_text() or ""
    match = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def ollama_mlx_supported() -> bool:
    """Apple Silicon needs an MLX-capable Ollama (0.32.14+) or an already-listed :mlx model."""

    if not is_apple_silicon():
        return True
    if not shutil.which("ollama"):
        return False
    version = ollama_version_tuple()
    if version is not None and version >= OLLAMA_MLX_MIN_VERSION:
        return True
    return any("-mlx" in name.casefold() or name.casefold().endswith(":mlx") for name in ollama_models())


def ollama_needs_mlx_upgrade() -> bool:
    """True when this Apple Silicon Mac should be offered an Ollama MLX upgrade."""

    return is_apple_silicon() and not ollama_mlx_supported()


def _download_with_progress(url: str, destination: Path, label: str) -> None:
    last = [-1]

    def hook(block: int, block_size: int, total: int) -> None:
        if total <= 0:
            return
        percent = min(100, int(block * block_size * 100 / total))
        if percent == last[0]:
            return
        last[0] = percent
        print(f"\r  • {label} {percent}%", end="", flush=True)

    urllib.request.urlretrieve(url, destination, reporthook=hook)
    print()


def install_pinned_ollama_macos() -> tuple[bool, str]:
    """Install the pinned MLX-capable Ollama macOS app (default 0.32.14)."""

    if sys.platform != "darwin":
        return False, "Ollama DMG install is macOS-only"
    bin_dir = Path(os.environ.get("TACU_BIN_DIR") or (Path.home() / ".local" / "bin"))
    applications = Path.home() / "Applications"
    applications.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    url = (
        "https://github.com/ollama/ollama/releases/download/"
        f"v{OLLAMA_PINNED_VERSION}/Ollama.dmg"
    )
    try:
        with tempfile.TemporaryDirectory(prefix="tacu-ollama-") as scratch:
            dmg = Path(scratch) / "Ollama.dmg"
            mount = Path(scratch) / "mount"
            mount.mkdir()
            print(f"Downloading Ollama {OLLAMA_PINNED_VERSION} (MLX)...")
            _download_with_progress(url, dmg, f"Downloading Ollama {OLLAMA_PINNED_VERSION}")
            attach = subprocess.run(
                ["hdiutil", "attach", str(dmg), "-nobrowse", "-quiet", "-mountpoint", str(mount)],
                check=False,
            )
            if attach.returncode != 0:
                return False, "could not mount the Ollama installer disk image"
            try:
                app_source = mount / "Ollama.app"
                if not app_source.is_dir():
                    return False, "Ollama.app was not inside the disk image"
                subprocess.run(["ditto", str(app_source), str(applications / "Ollama.app")], check=True)
            finally:
                subprocess.run(["hdiutil", "detach", str(mount), "-quiet"], check=False)
        ollama_bin = applications / "Ollama.app" / "Contents" / "Resources" / "ollama"
        if ollama_bin.is_file():
            target = bin_dir / "ollama"
            if target.exists() or target.is_symlink():
                target.unlink()
            target.symlink_to(ollama_bin)
        subprocess.run(["open", "-a", "Ollama"], check=False)
        for _ in range(45):
            if ollama_models() or ollama_version_tuple():
                break
            time.sleep(1)
        version = ollama_version_text() or f"Ollama {OLLAMA_PINNED_VERSION}"
        if ollama_mlx_supported():
            return True, f"installed {version} (MLX ready)"
        return True, f"installed {version}; start Ollama.app if models are not listed yet"
    except (OSError, subprocess.SubprocessError, urllib.error.URLError) as error:
        return False, str(error)


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        completed = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=12, check=False,
        )
        return completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def searxng_image_present() -> bool:
    return _docker_ok(["image", "inspect", SEARXNG_IMAGE], timeout=20)


def searxng_settings_path() -> Path:
    """Local limiter-off + JSON search settings mounted into tacu-searxng."""

    path = app_home() / "searxng" / "settings.yml"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    current = path.read_text(encoding="utf-8") if path.is_file() else ""
    if (
        "secret_key:" in current
        and "ultrasecretkey" not in current
        and "formats:" in current
        and "json" in current
    ):
        return path
    path.write_text(SEARXNG_SETTINGS.format(secret=secrets.token_hex(32)), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)
    return path


def save_searxng_url(url: str) -> str:
    cleaned = url.rstrip("/")
    content = load_config()
    content["searxng_url"] = cleaned
    save_config(content)
    return cleaned


def configured_searxng_url() -> str | None:
    value = load_config().get("searxng_url")
    return value.rstrip("/") if isinstance(value, str) and value.strip() else None


def searxng_url() -> str:
    """Where `ti web` talks to SearXNG: env, saved URL, published container port, then :8080."""

    env = (os.environ.get("TACU_SEARXNG_URL") or "").strip()
    if env:
        return env.rstrip("/")
    saved = configured_searxng_url()
    if saved:
        return saved
    published = searxng_published_url()
    if published:
        return published
    return DEFAULT_SEARXNG_URL


def host_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def next_free_host_port(start: int = SEARXNG_PREFERRED_PORT, *, limit: int = SEARXNG_PORT_SPAN) -> int:
    for port in range(start, start + max(1, limit)):
        if host_port_free(port):
            return port
    raise TacuError(
        f"No free loopback port in {start}–{start + max(1, limit) - 1} for {SEARXNG_CONTAINER}."
    )


def _docker_ok(args: list[str], *, timeout: int = 12) -> bool:
    if not shutil.which("docker"):
        return False
    try:
        completed = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False,
        )
        return completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _docker_text(args: list[str], *, timeout: int = 12) -> str | None:
    if not shutil.which("docker"):
        return None
    try:
        completed = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def searxng_published_port() -> int | None:
    """Host port published from tacu-searxng:8080, or None if the container has no mapping."""

    raw = _docker_text(["inspect", "-f", "{{json .NetworkSettings.Ports}}", SEARXNG_CONTAINER])
    if not raw or raw in {"null", "<no value>"}:
        return None
    try:
        ports = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(ports, dict):
        return None
    bindings = ports.get("8080/tcp")
    if not isinstance(bindings, list):
        return None
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        host = str(binding.get("HostPort") or "").strip()
        if host.isdigit():
            return int(host)
    return None


def searxng_published_url() -> str | None:
    port = searxng_published_port()
    return f"http://127.0.0.1:{port}" if port else None


def heavy_stack_installed(installed_models: set[str] | None = None) -> bool:
    """True when Ollama, Docker, and at least one preferred chat model are already present."""

    models = installed_models if installed_models is not None else ollama_models()
    chat_ok = chosen_chat_model(models) is not None
    return bool(shutil.which("ollama")) and docker_available() and chat_ok


def required_disk_gb(installed_models: set[str] | None = None) -> int:
    return MIN_DISK_GB_READY if heavy_stack_installed(installed_models) else MIN_DISK_GB_FULL


def readiness(path: Path | None = None) -> Readiness:
    check_path = (path or configured_workspace() or Path.cwd()).expanduser()
    disk_path = check_path
    while not disk_path.exists() and disk_path != disk_path.parent:
        disk_path = disk_path.parent
    ram = physical_memory_gb()
    disk = round(shutil.disk_usage(disk_path).free / 1024**3, 1)
    ollama = shutil.which("ollama")
    version = ollama_version_text() if ollama else None
    installed = ollama_models()
    need = required_disk_gb(installed)
    docker_ok = docker_available()
    image_ok = searxng_image_present() if docker_ok else False
    container_ok = searxng_container_running() if docker_ok else False
    return Readiness(
        platform.system(),
        platform.machine(),
        platform.python_version(),
        ram,
        disk,
        need,
        ram is not None and ram >= MIN_RAM_GB,
        disk >= need,
        bool(ollama),
        ollama_mlx_supported(),
        version,
        docker_ok,
        image_ok,
        container_ok,
        {model: model in installed for model in required_models()},
        str(configured_workspace()) if configured_workspace() else None,
        bool(shutil.which("ticu")),
    )


def pull_models() -> list[tuple[str, bool, str]]:
    """Install one chat model: Gemma, unless Gemma or the backup is already present."""

    installed = ollama_models()
    primary, backup = preferred_models()
    if primary in installed:
        return [(primary, True, "already installed")]
    if backup in installed:
        return [(backup, True, "already installed · using as chat model (Gemma not pulled)")]
    completed = subprocess.run(["ollama", "pull", primary], check=False)
    return [(
        primary,
        completed.returncode == 0,
        "installed" if completed.returncode == 0 else "installation failed",
    )]


def ensure_searxng_image() -> tuple[bool, str]:
    """Pull searxng/searxng:latest when Docker is available and the image is missing."""

    if not docker_available():
        return False, "Docker Desktop is not running or docker is not on PATH"
    if searxng_image_present():
        return True, "already present"
    completed = subprocess.run(["docker", "pull", SEARXNG_IMAGE], check=False)
    if completed.returncode == 0 and searxng_image_present():
        return True, "pulled"
    return False, "docker pull failed"


def searxng_container_running() -> bool:
    if not docker_available():
        return False
    state = _docker_text(["inspect", "-f", "{{.State.Running}}", SEARXNG_CONTAINER])
    return (state or "").casefold() == "true"


def searxng_container_exists() -> bool:
    return _docker_text(["inspect", "-f", "{{.Id}}", SEARXNG_CONTAINER]) is not None


def searxng_http_ready(url: str | None = None) -> bool:
    target = (url or searxng_url()).rstrip("/") + "/"
    try:
        urllib.request.urlopen(target, timeout=3)
        return True
    except (OSError, TimeoutError, urllib.error.URLError):
        return False


def _searxng_wait_attempts(default: int = 30) -> int:
    raw = (os.environ.get("TACU_SEARXNG_WAIT") or "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


def _wait_searxng_http(url: str, *, attempts: int | None = None) -> bool:
    remaining = _searxng_wait_attempts() if attempts is None else attempts
    if remaining <= 0:
        return searxng_http_ready(url)
    for _ in range(remaining):
        if searxng_http_ready(url):
            return True
        time.sleep(1)
    return False


def _remove_searxng_container() -> None:
    subprocess.run(
        ["docker", "rm", "-f", SEARXNG_CONTAINER],
        capture_output=True, check=False,
    )


def _run_searxng_container(port: int) -> tuple[bool, str]:
    settings = searxng_settings_path()
    created = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", SEARXNG_CONTAINER,
            "--restart", "unless-stopped",
            "-p", f"127.0.0.1:{port}:8080",
            "-v", f"{settings.resolve()}:/etc/searxng/settings.yml:ro",
            SEARXNG_IMAGE,
        ],
        capture_output=True, text=True, check=False,
    )
    if created.returncode == 0 and searxng_container_running():
        return True, ""
    detail = (created.stderr or created.stdout or "docker run for SearXNG failed").strip().splitlines()
    return False, detail[-1] if detail else "docker run for SearXNG failed"


def _remember_searxng(url: str, message: str) -> tuple[bool, str]:
    save_searxng_url(url)
    return True, message


def ensure_searxng_container() -> tuple[bool, str]:
    """Run TACU's own tacu-searxng on 127.0.0.1:8080, or the next free port."""

    image_ok, image_msg = ensure_searxng_image()
    if not image_ok:
        return False, image_msg

    if searxng_container_running():
        published = searxng_published_url()
        if published:
            _wait_searxng_http(published, attempts=8)
            return _remember_searxng(published, f"{SEARXNG_CONTAINER} already running at {published}")
        _remove_searxng_container()
    elif searxng_container_exists():
        started = subprocess.run(["docker", "start", SEARXNG_CONTAINER], check=False)
        if started.returncode == 0 and searxng_container_running():
            published = searxng_published_url()
            if published:
                _wait_searxng_http(published, attempts=8)
                return _remember_searxng(published, f"started {SEARXNG_CONTAINER} at {published}")
        _remove_searxng_container()

    try:
        port = next_free_host_port()
    except TacuError as error:
        return False, str(error)
    url = f"http://127.0.0.1:{port}"
    started, detail = _run_searxng_container(port)
    if not started:
        return False, detail
    _wait_searxng_http(url)
    return _remember_searxng(url, f"started {SEARXNG_CONTAINER} at {url}")


def status_lines(report: Readiness) -> list[tuple[bool, str]]:
    ram_text = "unknown" if report.ram_gb is None else f"{report.ram_gb:.1f} GB"
    disk_note = (
        f"{report.disk_required_gb} GB minimum"
        + (" · stack already present" if report.disk_required_gb == MIN_DISK_GB_READY else " · first install / downloads")
    )
    lines = [
        (report.ram_ok, f"Memory: {ram_text} (16 GB minimum; 32 GB preferred)"),
        (report.disk_ok, f"Free disk space: {report.disk_free_gb:.1f} GB ({disk_note})"),
        (report.ollama_installed, f"Ollama: {report.ollama_version or 'not installed'}"),
    ]
    if is_apple_silicon():
        lines.append((
            report.ollama_mlx_ok,
            f"Ollama MLX (Apple Silicon): {'ready' if report.ollama_mlx_ok else f'not ready — need Ollama {OLLAMA_PINNED_VERSION}+'}",
        ))
    chosen = chosen_chat_model({model for model, present in report.required_models.items() if present})
    primary = default_chat_model()
    if chosen:
        lines.append((True, f"AI chat model: {chosen}"))
    else:
        lines.append((False, f"AI chat model: not installed (setup pulls {primary} only)"))
    lines.append((report.docker_installed, f"Docker Desktop: {'ready' if report.docker_installed else 'not running / not installed'}"))
    lines.append((
        report.searxng_image,
        f"Docker image {SEARXNG_IMAGE}: {'ready' if report.searxng_image else 'missing (needed for ti web)'}",
    ))
    lines.append((
        report.searxng_running,
        f"SearXNG ({SEARXNG_CONTAINER} at {searxng_url()}): "
        f"{'running' if report.searxng_running else 'not running (needed for ti web)'}",
    ))
    lines.append((bool(report.workspace), f"Workspace: {report.workspace or 'not selected'}"))
    lines.append((report.tacu_on_path, f"Command from any directory: {'ready' if report.tacu_on_path else 'ticu not found on PATH'}"))
    return lines
