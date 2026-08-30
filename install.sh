#!/bin/sh
# Guided TACU installer for macOS and Linux. It never modifies system Python.
set -eu

MIN_RAM_GB=16
MIN_DISK_GB_FULL=40
MIN_DISK_GB_READY=20
SEARXNG_IMAGE="searxng/searxng:latest"
SEARXNG_CONTAINER="tacu-searxng"
FORCE=0
DRY_RUN=0
SKIP_OLLAMA=0
SKIP_MODELS=0
SKIP_DOCKER=0
WORKSPACE=""

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$SOURCE_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$SOURCE_DIR/.env"
  set +a
fi

SKIP_OLLAMA=${SKIP_OLLAMA:-0}
SKIP_MODELS=${SKIP_MODELS:-0}
SKIP_DOCKER=${SKIP_DOCKER:-0}
OLLAMA_PINNED_VERSION=${TACU_OLLAMA_VERSION:-0.32.14}

usage() {
  cat <<'EOF'
TACU guided installer

Usage: ./install.sh [options]
  --workspace PATH  Create or select this project workspace
  --use-current     Use the current directory as the workspace
  --skip-ollama     Do not install Ollama
  --skip-models     Do not download the required AI models
  --skip-docker     Do not verify/pull Docker / start SearXNG
  --force           Continue below the recommended hardware minimum
  --dry-run         Show what would happen without changing anything
  -h, --help        Show this help

Optional: copy .env.example to .env and edit before running. Defaults work
without a .env file (Gemma as the chat model, Ollama 0.32.14).
Python: uses any 3.11+ already installed; otherwise installs 3.14.7.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --workspace) [ "$#" -ge 2 ] || { echo "Missing path after --workspace" >&2; exit 2; }; WORKSPACE=$2; shift 2 ;;
    --use-current) WORKSPACE=$(pwd); shift ;;
    --skip-ollama) SKIP_OLLAMA=1; shift ;;
    --skip-models) SKIP_MODELS=1; shift ;;
    --skip-docker) SKIP_DOCKER=1; shift ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

INSTALL_HOME=${TACU_INSTALL_HOME:-"$HOME/.local/share/tacu/runtime"}
BIN_DIR=${TACU_BIN_DIR:-"$HOME/.local/bin"}

step() { printf '\n[%s/7] %s\n' "$1" "$2"; }
ok() { printf '  ✓ %s\n' "$1"; }
info() { printf '  • %s\n' "$1"; }
fail() { printf '  ✗ %s\n' "$1" >&2; exit 1; }
run() { if [ "$DRY_RUN" -eq 1 ]; then printf '  dry-run: '; printf '%s ' "$@"; printf '\n'; else "$@"; fi; }

wait_for() {
  # wait_for "label" attempts sleep_seconds -- command...
  label=$1
  max=$2
  delay=$3
  shift 3
  attempt=0
  printf '  • %s' "$label"
  while [ "$attempt" -lt "$max" ]; do
    if "$@" >/dev/null 2>&1; then
      printf '\r  ✓ %s\n' "$label"
      return 0
    fi
    attempt=$((attempt + 1))
    printf '.'
    sleep "$delay"
  done
  printf '\n'
  return 1
}

PYTHON_MIN=3.11
PYTHON_BOOTSTRAP=${TACU_PYTHON_VERSION:-3.14.7}

version_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    n = split(a, A, "."); m = split(b, B, ".");
    max = (n > m ? n : m); if (max < 3) max = 3;
    for (i = 1; i <= max; i++) {
      ai = (i <= n ? A[i] + 0 : 0);
      bi = (i <= m ? B[i] + 0 : 0);
      if (ai > bi) exit 0;
      if (ai < bi) exit 1;
    }
    exit 0;
  }'
}

ollama_numeric_version() {
  ollama --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1
}

python_version_of() {
  "$1" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || true
}

python_is_supported() {
  bin=$1
  [ -n "$bin" ] || return 1
  if [ ! -x "$bin" ]; then
    bin=$(command -v "$bin" 2>/dev/null) || return 1
  fi
  ver=$(python_version_of "$bin")
  [ -n "$ver" ] || return 1
  version_ge "$ver" "$PYTHON_MIN" || return 1
  "$bin" -c 'import venv' 2>/dev/null || return 1
  return 0
}

find_supported_python() {
  if [ -n "${TACU_PYTHON:-}" ] && python_is_supported "$TACU_PYTHON"; then
    command -v "$TACU_PYTHON" 2>/dev/null || printf '%s\n' "$TACU_PYTHON"
    return 0
  fi
  for cmd in python3.14 python3.13 python3.12 python3.11 python3 python; do
    resolved=$(command -v "$cmd" 2>/dev/null) || continue
    if [ "$(uname -s)" = Darwin ] && { [ "$resolved" = /usr/bin/python3 ] || [ "$resolved" = /usr/bin/python ]; }; then
      xcode-select -p >/dev/null 2>&1 || continue
    fi
    if python_is_supported "$resolved"; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done
  for resolved in \
      "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14" \
      "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13" \
      "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12" \
      "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11" \
      "$INSTALL_HOME/python-${PYTHON_BOOTSTRAP}/bin/python3.14" \
      "$INSTALL_HOME/python-${PYTHON_BOOTSTRAP}/bin/python3" \
      "/opt/homebrew/bin/python3.14" \
      "/usr/local/bin/python3.14"
  do
    if python_is_supported "$resolved"; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done
  return 1
}

install_python_bootstrap() {
  info "Python $PYTHON_MIN+ was not found. Installing Python $PYTHON_BOOTSTRAP from python.org..."
  if [ "$OS" = macOS ]; then
    command -v curl >/dev/null 2>&1 || fail "curl is required to download Python $PYTHON_BOOTSTRAP."
    PKG=$(mktemp -t tacu-python).pkg
    curl -fL --progress-bar "https://www.python.org/ftp/python/${PYTHON_BOOTSTRAP}/python-${PYTHON_BOOTSTRAP}-macos11.pkg" -o "$PKG"
    info "Installing the official Python $PYTHON_BOOTSTRAP package (administrator password may be required)..."
    if command -v sudo >/dev/null 2>&1; then
      sudo installer -pkg "$PKG" -target / || true
    else
      installer -pkg "$PKG" -target / || true
    fi
    rm -f "$PKG"
    export PATH="/Library/Frameworks/Python.framework/Versions/3.14/bin:/usr/local/bin:$PATH"
    if ! find_supported_python >/dev/null 2>&1 && command -v brew >/dev/null 2>&1; then
      info "python.org package was not on PATH yet; installing python@3.14 via Homebrew..."
      brew install python@3.14
      export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
    fi
  else
    PREFIX="$INSTALL_HOME/python-${PYTHON_BOOTSTRAP}"
    mkdir -p "$INSTALL_HOME"
    if ! command -v make >/dev/null 2>&1 || { ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; }; then
      if command -v apt-get >/dev/null 2>&1; then
        info "Installing compilers needed to build Python $PYTHON_BOOTSTRAP..."
        sudo apt-get update
        sudo apt-get install -y build-essential zlib1g-dev libssl-dev libffi-dev libbz2-dev \
          libreadline-dev libsqlite3-dev libncursesw5-dev xz-utils tk-dev
      else
        fail "A C compiler (gcc/make) is required to install Python $PYTHON_BOOTSTRAP on Linux."
      fi
    fi
    command -v curl >/dev/null 2>&1 || fail "curl is required to download Python $PYTHON_BOOTSTRAP."
    SRC=$(mktemp -d -t tacu-python)
    curl -fL --progress-bar "https://www.python.org/ftp/python/${PYTHON_BOOTSTRAP}/Python-${PYTHON_BOOTSTRAP}.tgz" -o "$SRC/Python.tgz"
    tar -xzf "$SRC/Python.tgz" -C "$SRC"
    info "Building Python $PYTHON_BOOTSTRAP into $PREFIX (this can take several minutes)..."
    (
      cd "$SRC/Python-${PYTHON_BOOTSTRAP}"
      ./configure --prefix="$PREFIX" --with-ensurepip=install
      make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
      make install
    )
    rm -rf "$SRC"
    export PATH="$PREFIX/bin:$PATH"
  fi
}

ARCH=$(uname -m)
case $(uname -s) in
  Darwin)
    OS=macOS
    RAM_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
    RAM_GB=$((RAM_BYTES / 1024 / 1024 / 1024))
    ;;
  Linux)
    OS=Linux
    RAM_KB=$(awk '/MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)
    RAM_GB=$((RAM_KB / 1024 / 1024))
    ;;
  *) fail "This installer supports macOS and Linux. On Windows, run install.ps1." ;;
esac

# Primary model: MLX-tuned Gemma on Apple Silicon; otherwise gemma4:12b.
if [ "$OS" = macOS ] && { [ "$ARCH" = arm64 ] || [ "$ARCH" = aarch64 ]; }; then
  REQUIRED_MODEL=${TACU_MODEL:-gemma4:12b-mlx}
  APPLE_SILICON=1
else
  REQUIRED_MODEL=${TACU_MODEL:-gemma4:12b}
  APPLE_SILICON=0
fi
BACKUP_MODEL=${TACU_BACKUP_MODEL:-qwen2.5-coder:7b}

docker_ready() {
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1
}

model_listed() {
  command -v ollama >/dev/null 2>&1 || return 1
  ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Fx "$1" >/dev/null 2>&1
}

model_ready() {
  model_listed "$REQUIRED_MODEL" || model_listed "$BACKUP_MODEL"
}

mlx_model_listed() {
  command -v ollama >/dev/null 2>&1 || return 1
  ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Ei -- '-mlx|:mlx' >/dev/null 2>&1
}

ollama_mlx_ready() {
  [ "$APPLE_SILICON" -eq 1 ] || return 0
  command -v ollama >/dev/null 2>&1 || return 1
  ver=$(ollama_numeric_version)
  if [ -n "$ver" ] && version_ge "$ver" "$OLLAMA_PINNED_VERSION"; then
    return 0
  fi
  mlx_model_listed
}

pull_one_model() {
  name=$1
  if model_listed "$name"; then
    ok "$name is already ready"
    return 0
  fi
  info "Downloading $name (progress from Ollama below)..."
  ollama pull "$name"
  model_listed "$name" || fail "The AI model $name could not be installed."
  ok "$name is ready"
}

install_ollama_macos_pinned() {
  command -v curl >/dev/null 2>&1 || fail "curl is required to download Ollama $OLLAMA_PINNED_VERSION."
  OLLAMA_DMG=$(mktemp -t ollama).dmg
  OLLAMA_MOUNT=$(mktemp -d -t ollama-mount)
  mkdir -p "$HOME/Applications"
  info "Downloading Ollama $OLLAMA_PINNED_VERSION (MLX) from GitHub..."
  curl -fL --progress-bar "https://github.com/ollama/ollama/releases/download/v${OLLAMA_PINNED_VERSION}/Ollama.dmg" -o "$OLLAMA_DMG"
  hdiutil attach "$OLLAMA_DMG" -nobrowse -quiet -mountpoint "$OLLAMA_MOUNT"
  ditto "$OLLAMA_MOUNT/Ollama.app" "$HOME/Applications/Ollama.app"
  hdiutil detach "$OLLAMA_MOUNT" -quiet
  rm -f "$OLLAMA_DMG"; rmdir "$OLLAMA_MOUNT"
  ln -sf "$HOME/Applications/Ollama.app/Contents/Resources/ollama" "$BIN_DIR/ollama"
  open -a Ollama >/dev/null 2>&1 || open "$HOME/Applications/Ollama.app" >/dev/null 2>&1 || true
}

heavy_stack_ready() {
  command -v ollama >/dev/null 2>&1 || return 1
  docker_ready || return 1
  model_ready || return 1
}

identity() {
  if printf '%s' "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" | grep -qi 'utf-\?8'; then
    printf '\n'
    printf '\033[1;36m╭──────────────╮        ♥\033[0m\n'
    printf '\033[1;36m│  >_          │\033[0m\n'
    printf '\033[1;36m│   ⌒     ⌒    │     t a c u\033[0m\n'
    printf '\033[1;36m│      ◡       │     Terminal Ally & Companion Unit\033[0m\n'
    printf '\033[1;36m╰──────────╮   │\033[0m\n'
    printf '\033[1;36m           ╰───╯\033[0m\n'
  else
    printf '\n'
    printf '\033[1;36m+--------------+        <3\033[0m\n'
    printf '\033[1;36m|  >_          |\033[0m\n'
    printf '\033[1;36m|   ~     ~    |     t a c u\033[0m\n'
    printf '\033[1;36m|      u       |     Terminal Ally & Companion Unit\033[0m\n'
    printf '\033[1;36m+----------+   |\033[0m\n'
    printf '\033[1;36m           +---+\033[0m\n'
  fi
  printf '\n'
}

identity
if [ -f "$SOURCE_DIR/.env" ]; then
  ok "Loaded settings from $SOURCE_DIR/.env"
elif [ -f "$SOURCE_DIR/.env.example" ]; then
  info "Using built-in defaults. Optional: cp .env.example .env, edit, then rerun ./install.sh"
fi
# macOS reports free space including "purgeable" bytes (caches, local snapshots,
# evictable iCloud files) that the system reclaims on demand; df counts none of it.
# Ask for the same figure System Settings and Finder show, so the installer never
# contradicts the OS. Requires the Command Line Tools; falls back to df silently.
macos_purgeable_aware_kb() {
  [ "$OS" = macOS ] || return 1
  xcode-select -p >/dev/null 2>&1 || return 1
  command -v swift >/dev/null 2>&1 || return 1
  swift - <<'SWIFT' 2>/dev/null
import Foundation
let home = URL(fileURLWithPath: NSHomeDirectory())
if let values = try? home.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]),
   let capacity = values.volumeAvailableCapacityForImportantUsage {
  print(capacity / 1024)
}
SWIFT
}

step 1 "Checking this computer"
DISK_KB=$(df -Pk "$HOME" | awk 'NR==2 {print $4}')
DISK_SOURCE=df
if PURGEABLE_KB=$(macos_purgeable_aware_kb) &&
   [ -n "$PURGEABLE_KB" ] &&
   [ "$PURGEABLE_KB" -gt "$DISK_KB" ] 2>/dev/null; then
  DF_GB=$((DISK_KB / 1024 / 1024))
  DISK_KB=$PURGEABLE_KB
  DISK_SOURCE=macos
fi
DISK_GB=$((DISK_KB / 1024 / 1024))
if heavy_stack_ready; then
  MIN_DISK_GB=$MIN_DISK_GB_READY
  DISK_REASON="20 GB minimum · Ollama, Docker, and required models already present"
else
  MIN_DISK_GB=$MIN_DISK_GB_FULL
  DISK_REASON="40 GB minimum · first install / remaining downloads"
fi
info "Operating system: $OS ($ARCH)"
if [ "$RAM_GB" -ge "$MIN_RAM_GB" ]; then
  ok "Memory: ${RAM_GB} GB (16 GB minimum; 32 GB preferred)"
else
  info "Memory: ${RAM_GB} GB; TACU needs at least 16 GB"
  [ "$FORCE" -eq 1 ] || fail "Prerequisite check stopped installation. Add --force only if you accept reduced reliability."
fi
if [ "$DISK_GB" -ge "$MIN_DISK_GB" ]; then
  if [ "$DISK_SOURCE" = macos ]; then
    ok "Free disk space: ${DISK_GB} GB ($DISK_REASON; df alone reports ${DF_GB} GB, the rest is purgeable)"
  else
    ok "Free disk space: ${DISK_GB} GB ($DISK_REASON)"
  fi
else
  info "Free disk: ${DISK_GB} GB; TACU needs at least ${MIN_DISK_GB} GB ($DISK_REASON)"
  if [ "$OS" = macOS ] && [ "$DISK_SOURCE" = df ]; then
    info "If Finder or System Settings shows more free space, that extra is purgeable and df cannot see it. Free it with: tmutil thinlocalsnapshots / 10000000000 4"
  fi
  [ "$FORCE" -eq 1 ] || fail "Prerequisite check stopped installation. Add --force only if you have another storage plan."
fi
PYTHON=""
if FOUND=$(find_supported_python); then
  PYTHON=$FOUND
  ok "Python $(python_version_of "$PYTHON") at $PYTHON (3.11+ is supported)"
elif [ "$DRY_RUN" -eq 1 ]; then
  info "Would install Python $PYTHON_BOOTSTRAP from python.org (no supported Python is on PATH)"
  PYTHON=python3
else
  install_python_bootstrap
  if FOUND=$(find_supported_python); then
    PYTHON=$FOUND
    ok "Python $(python_version_of "$PYTHON") at $PYTHON"
  else
    fail "Python $PYTHON_MIN+ is required. Install Python $PYTHON_BOOTSTRAP from https://www.python.org/downloads/ then rerun this installer."
  fi
fi
ok "Prerequisites are ready"

step 2 "Installing Terminal Ally & Companion Unit"
TI_COMMAND=$(command -v ti 2>/dev/null || true)
if [ -z "$TI_COMMAND" ] && { [ -e "$BIN_DIR/ti" ] || [ -L "$BIN_DIR/ti" ]; }; then TI_COMMAND="$BIN_DIR/ti"; fi
TI_ALIAS_AVAILABLE=0
if [ -z "$TI_COMMAND" ] || [ "$TI_COMMAND" = "$BIN_DIR/ti" ]; then TI_ALIAS_AVAILABLE=1; fi
if [ "$DRY_RUN" -eq 0 ]; then
  mkdir -p "$INSTALL_HOME" "$BIN_DIR"
  "$PYTHON" -m venv "$INSTALL_HOME/venv"
  "$INSTALL_HOME/venv/bin/python" -m pip install --quiet --no-cache-dir --disable-pip-version-check --no-deps --force-reinstall "$SOURCE_DIR"
  ln -sf "$INSTALL_HOME/venv/bin/ticu" "$BIN_DIR/ticu"
  if [ -z "$TI_COMMAND" ] || [ "$TI_COMMAND" = "$BIN_DIR/ti" ]; then
    ln -sf "$INSTALL_HOME/venv/bin/ticu" "$BIN_DIR/ti"
    ok "Installed the conflict-checked short command: ti"
  else
    info "Kept the existing ti command at $TI_COMMAND; use ticu on this computer"
  fi
  ok "Installed TACU in its own private application environment"
else
  info "Would create an isolated runtime at $INSTALL_HOME/venv"
  info "Would expose the command at $BIN_DIR/ticu"
  if [ -z "$TI_COMMAND" ] || [ "$TI_COMMAND" = "$BIN_DIR/ti" ]; then info "Would create or refresh the available short command: ti";
  else info "Would preserve the existing ti command at $TI_COMMAND"; fi
fi
case ":$PATH:" in
  *":$BIN_DIR:"*) ok "The ticu command is already on PATH" ;;
  *)
    SHELL_NAME=$(basename "${SHELL:-sh}")
    if [ -n "${TACU_SHELL_PROFILE:-}" ]; then PROFILE=$TACU_SHELL_PROFILE;
    elif [ "$SHELL_NAME" = zsh ]; then PROFILE="$HOME/.zprofile"; else PROFILE="$HOME/.profile"; fi
    if [ "$DRY_RUN" -eq 0 ]; then
      touch "$PROFILE"
      grep -F "$BIN_DIR" "$PROFILE" >/dev/null 2>&1 || printf '\n# TACU command\nexport PATH="%s:$PATH"\n' "$BIN_DIR" >> "$PROFILE"
    fi
    export PATH="$BIN_DIR:$PATH"
    ok "Configured ticu to work from every directory (effective in new terminals)"
    ;;
esac

# zsh expands ?, * and brackets before TACU can join natural question words.
if [ "$(basename "$(printenv SHELL 2>/dev/null || echo sh)")" = zsh ]; then
  if [ -n "$(printenv TACU_SHELL_RC 2>/dev/null || true)" ]; then
    TACU_ZSH_RC=$(printenv TACU_SHELL_RC)
  else
    TACU_ZSH_RC="$HOME/.zshrc"
  fi
  if [ "$DRY_RUN" -eq 0 ]; then
    touch "$TACU_ZSH_RC"
    grep -F "# TACU natural questions" "$TACU_ZSH_RC" >/dev/null 2>&1 || {
      printf '
# TACU natural questions: preserve ?, *, and brackets for the CLI
' >> "$TACU_ZSH_RC"
      printf "alias ticu='noglob ticu'
" >> "$TACU_ZSH_RC"
      if [ "$TI_ALIAS_AVAILABLE" -eq 1 ]; then printf "alias ti='noglob ti'
" >> "$TACU_ZSH_RC"; fi
    }
    grep -F "export TACU_SHELL_INTEGRATION=1" "$TACU_ZSH_RC" >/dev/null 2>&1 || \
      printf "export TACU_SHELL_INTEGRATION=1\n" >> "$TACU_ZSH_RC"
    grep -F "# TACU completion and ghost prompts" "$TACU_ZSH_RC" >/dev/null 2>&1 || \
      printf '\n# TACU completion and ghost prompts\neval "$(command ticu shell-init zsh)"\n' >> "$TACU_ZSH_RC"
    ok "Configured zsh punctuation, tab completion, and TACU ghost prompts"
    info "For this already-open terminal, run: source $TACU_ZSH_RC"
  else
    info "Would configure zsh punctuation, tab completion, and TACU ghost prompts"
  fi
fi
if [ "$(basename "$(printenv SHELL 2>/dev/null || echo sh)")" = bash ]; then
  TACU_BASH_RC=${TACU_SHELL_RC:-"$HOME/.bashrc"}
  if [ "$DRY_RUN" -eq 0 ]; then
    touch "$TACU_BASH_RC"
    grep -F "# TACU tab completion" "$TACU_BASH_RC" >/dev/null 2>&1 || \
      printf '\n# TACU tab completion\neval "$(command ticu shell-init bash)"\n' >> "$TACU_BASH_RC"
    ok "Configured bash tab completion"
  else
    info "Would configure bash tab completion"
  fi
fi

step 3 "Setting up Ollama (MLX on Apple Silicon)"
if [ "$SKIP_OLLAMA" -eq 1 ]; then
  info "Skipped Ollama installation"
elif [ "$DRY_RUN" -eq 1 ]; then
  info "Would install Ollama $OLLAMA_PINNED_VERSION (MLX) on Apple Silicon if needed"
elif command -v ollama >/dev/null 2>&1; then
  OLLAMA_VERSION=$(ollama_numeric_version)
  [ -n "$OLLAMA_VERSION" ] || OLLAMA_VERSION=installed
  ok "Ollama is already installed (version $OLLAMA_VERSION)"
  if [ "$APPLE_SILICON" -eq 1 ] && ! ollama_mlx_ready; then
    UPGRADE=0
    if [ -t 0 ]; then
      printf '  Ollama %s is not MLX-ready (need %s+ for %s). Upgrade now? [Y/n] ' "$OLLAMA_VERSION" "$OLLAMA_PINNED_VERSION" "$REQUIRED_MODEL"
      read ANSWER || ANSWER=Y
      case "$ANSWER" in n|N|no|NO) UPGRADE=0 ;; *) UPGRADE=1 ;; esac
    elif [ "${TACU_UPGRADE_OLLAMA:-0}" = 1 ]; then
      UPGRADE=1
    else
      info "Non-interactive: Ollama is below $OLLAMA_PINNED_VERSION. Set TACU_UPGRADE_OLLAMA=1 or rerun on a TTY."
    fi
    if [ "$UPGRADE" -eq 1 ]; then
      install_ollama_macos_pinned
      ok "Ollama $OLLAMA_PINNED_VERSION installed"
    elif [ "$FORCE" -eq 0 ]; then
      fail "Ollama MLX is required for $REQUIRED_MODEL. Confirm the upgrade, or rerun with --force."
    fi
  fi
  if [ "$APPLE_SILICON" -eq 1 ]; then
    if ollama list >/dev/null 2>&1; then
      ok "Ollama API is reachable"
    else
      info "Starting Ollama so MLX models can load..."
      open -a Ollama >/dev/null 2>&1 || open "$HOME/Applications/Ollama.app" >/dev/null 2>&1 || true
      wait_for "Waiting for Ollama API" 45 1 ollama list || {
        [ "$FORCE" -eq 1 ] || fail "Ollama did not start. Open Ollama.app, then rerun ./install.sh"
      }
    fi
    ollama_mlx_ready && ok "Ollama MLX path ready on Apple Silicon (arm64)"
  fi
elif [ "$OS" = Linux ]; then
  command -v curl >/dev/null 2>&1 || fail "curl is required to download Ollama."
  OLLAMA_SCRIPT=$(mktemp)
  info "Downloading the official Ollama Linux installer..."
  curl -fsSL https://ollama.com/install.sh -o "$OLLAMA_SCRIPT"
  sh "$OLLAMA_SCRIPT"
  rm -f "$OLLAMA_SCRIPT"
  ok "Ollama installed"
else
  install_ollama_macos_pinned
  ok "Ollama $OLLAMA_PINNED_VERSION installed and starting"
  if [ "$APPLE_SILICON" -eq 1 ]; then
    wait_for "Waiting for Ollama API" 45 1 ollama list || true
    ollama list >/dev/null 2>&1 && ok "Ollama MLX path ready on Apple Silicon (arm64)"
  fi
fi

step 4 "Setting up AI chat model ($REQUIRED_MODEL)"
CHOSEN_MODEL=$REQUIRED_MODEL
if [ "$SKIP_MODELS" -eq 1 ]; then
  info "Skipped model downloads"
elif [ "$DRY_RUN" -eq 1 ]; then
  info "Would use $REQUIRED_MODEL or $BACKUP_MODEL if already installed; otherwise download $REQUIRED_MODEL only"
elif ! command -v ollama >/dev/null 2>&1; then
  fail "Ollama is unavailable. Finish its installation, then run: ticu setup"
else
  if ! ollama list >/dev/null 2>&1; then
    if [ "$OS" = Linux ]; then nohup ollama serve >"$INSTALL_HOME/ollama.log" 2>&1 & else open -a Ollama >/dev/null 2>&1 || true; fi
    wait_for "Waiting for Ollama API" 45 1 ollama list || true
  fi
  ollama list >/dev/null 2>&1 || fail "Ollama did not start. Start Ollama, then run: ticu setup"
  if model_listed "$REQUIRED_MODEL"; then
    CHOSEN_MODEL=$REQUIRED_MODEL
    ok "$REQUIRED_MODEL is already ready"
  elif model_listed "$BACKUP_MODEL"; then
    CHOSEN_MODEL=$BACKUP_MODEL
    ok "$BACKUP_MODEL is already ready · using it as the chat model (not pulling $REQUIRED_MODEL)"
  else
    pull_one_model "$REQUIRED_MODEL"
    CHOSEN_MODEL=$REQUIRED_MODEL
  fi
fi

step 5 "Setting up Docker Desktop + SearXNG"
if [ "$SKIP_DOCKER" -eq 1 ]; then
  info "Skipped Docker / SearXNG checks"
elif [ "$DRY_RUN" -eq 1 ]; then
  info "Would verify Docker Desktop is running"
  info "Would pull $SEARXNG_IMAGE if missing"
  info "Would start $SEARXNG_CONTAINER on 127.0.0.1:8080 (or the next free port)"
elif ! command -v docker >/dev/null 2>&1; then
  if [ "$OS" = macOS ] && command -v brew >/dev/null 2>&1; then
    info "Installing Docker Desktop via Homebrew (this can take several minutes)..."
    brew install --cask docker || true
    open -a Docker >/dev/null 2>&1 || true
    info "Finish Docker Desktop first-run setup if prompted, then rerun ./install.sh"
  fi
  if ! command -v docker >/dev/null 2>&1; then
    [ "$FORCE" -eq 1 ] || fail "Docker Desktop is required for ti web. Install it from https://www.docker.com/products/docker-desktop/ then rerun ./install.sh"
    info "Docker missing; continuing because --force was set"
  fi
fi
if [ "$SKIP_DOCKER" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && command -v docker >/dev/null 2>&1; then
  if docker_ready; then
    ok "Docker Desktop is running"
  else
    if [ "$OS" = macOS ]; then open -a Docker >/dev/null 2>&1 || true; fi
    wait_for "Waiting for Docker Desktop" 60 2 docker_ready || {
      [ "$FORCE" -eq 1 ] || fail "Docker Desktop is installed but not running. Start it, then rerun ./install.sh"
      info "Docker not ready; continuing because --force was set"
    }
  fi
  if docker_ready; then
    if docker image inspect "$SEARXNG_IMAGE" >/dev/null 2>&1; then
      ok "$SEARXNG_IMAGE is already present"
    else
      info "Pulling $SEARXNG_IMAGE (required for ti web; progress from Docker below)..."
      docker pull "$SEARXNG_IMAGE"
      ok "$SEARXNG_IMAGE is ready"
    fi
    info "Starting $SEARXNG_CONTAINER (127.0.0.1:8080, or the next free port)..."
    if [ -x "$INSTALL_HOME/venv/bin/python" ]; then
      if MSG=$("$INSTALL_HOME/venv/bin/python" -c "from tacu.configuration import ensure_searxng_container; ok, msg = ensure_searxng_container(); print(msg); raise SystemExit(0 if ok else 1)"); then
        ok "$MSG"
      else
        [ "$FORCE" -eq 1 ] || fail "Could not start $SEARXNG_CONTAINER. $MSG"
        info "SearXNG not ready; continuing because --force was set"
      fi
    else
      [ "$FORCE" -eq 1 ] || fail "TACU Python is missing; rerun ./install.sh"
    fi
  fi
fi

step 6 "Preparing your project workspace"
if [ -z "$WORKSPACE" ]; then
  DEFAULT_WORKSPACE="$HOME/TACU-Workspace"
  if [ -t 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    printf '  Create the recommended workspace at %s? [Y/n] ' "$DEFAULT_WORKSPACE"
    read ANSWER
    case "$ANSWER" in n|N|no|NO) WORKSPACE=$(pwd) ;; *) WORKSPACE=$DEFAULT_WORKSPACE ;; esac
  else WORKSPACE=$DEFAULT_WORKSPACE; fi
fi
if [ "$DRY_RUN" -eq 0 ]; then
  mkdir -p "$WORKSPACE"
  "$BIN_DIR/ticu" workspace create "$WORKSPACE" --no-enter
else info "Would create/select workspace: $WORKSPACE"; fi

step 7 "Verifying TACU"
if [ "$DRY_RUN" -eq 0 ]; then
  "$BIN_DIR/ticu" --version
  info "Open a new terminal, then run: ticu doctor"
  info "Start anywhere with: ticu (or the short command: ti)"
  info "Move into focused work with: ticu workspace enter"
  info "Chat model: $CHOSEN_MODEL · keep-alive 15m · timeout 15 min"
  info "Backup $BACKUP_MODEL is used if it is already installed; setup does not pull both."
  info "Web stack: $SEARXNG_CONTAINER (127.0.0.1:8080, or the next free port)"
else
  info "Dry run complete; no files or settings were changed."
fi
printf '\nTACU installation complete.\n'
