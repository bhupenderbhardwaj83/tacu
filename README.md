<p align="center">
  <img src="assets/brand/tacu-logo.png" width="180" alt="TACU terminal companion logo">
</p>

<p align="center">
  <a href="https://github.com/bhupenderbhardwaj83/tacu/releases/latest"><img
    src="https://img.shields.io/github/v/release/bhupenderbhardwaj83/tacu?label=version&color=blue"
    alt="Latest TACU release"></a>
  <a href="https://github.com/bhupenderbhardwaj83/tacu/blob/main/LICENSE"><img
    src="https://img.shields.io/github/license/bhupenderbhardwaj83/tacu?color=blue"
    alt="MIT licensed"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Requires Python 3.11 or newer">
</p>

# TACU

**Terminal Ally & Companion Unit** is a local-first AI harness that turns terminal output, host telemetry, security evidence, and large files into focused, actionable answers.

Model inference and retained data stay local by default. Network access occurs only for explicit features such as installation downloads and `ti web`, which gives the terminal access to current information from the internet. TACU uses deterministic native tools first and a local Ollama model when interpretation is needed.

**Platform status:** macOS and Linux are the primary supported platforms. Windows support is experimental until its installation and functional release gates are certified. TACU requires Python 3.11+, has a standard-library-only core, and is MIT licensed.

[![CI](https://github.com/bhupenderbhardwaj83/tacu/actions/workflows/ci.yml/badge.svg)](https://github.com/bhupenderbhardwaj83/tacu/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-62D6A8)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-FF6B6B.svg)](LICENSE)

```text
╭──────────────╮        ♥
│  >_          │
│   ⌒     ⌒    │     t a c u
│      ◡       │     Terminal Ally & Companion Unit
╰──────────╮   │
           ╰───╯
```

TACU is available as two interchangeable commands: `ticu` and the shorter `ti`.

---

## Why it exists

Terminal tools are powerful and verbose. Commands such as `ifconfig`, `docker inspect`, `nmap`, and `whois` can answer a focused question with pages of unrelated output. Large PCAPs, Burp exports, registry hives, and CSV files create the same problem at a different scale.

TACU was built for power users who live in a shell and need:

- the **exact fact from verbose command or tool output**, such as a primary IP, top CPU process, listening-port owner, outbound connection, or DNS record;
- a **bounded, reviewed action**, such as creating a script, editing a program, or confirming a destructive operation;
- a **question over a file too large for a prompt**, including JSON, CSV, HTML, PCAP, Burp, registry-hive, and log data;
- **locally retained prompt and response history** that can be reviewed, copied, or saved for later reuse;
- **quick language, host, and current-web answers** directly from the terminal without inventing a shell pipeline first.

Deterministic native tools answer when they can. A local model is used only when the fact is not already in a parser.

## Who it is for

- **Security Analysts** and operators who already use a terminal
- **DevOps and Cloud Engineers** who already use a terminal
- **Developers** who want a local coding companion with a hard workspace and policy gate
- **DFIR Analysts** who cannot (or will not) paste captures into a hosted chatbot
- **Penetration Testers** who want a local AI assistant that can run scripts and commands
- **Network and System Engineers** and operators who already use a terminal
- **Anyone who works in a terminal** and wants a local AI assistant with explicit safety boundaries.

It is **not** a replacement for `bash`, Wireshark, or a full IDE. It is the local AI layer that turns those tools into short, grounded, copyable answers.

---

## Install (macOS / Linux)

You need **Python 3.11+**. If none is installed (or the only copy is older than 3.11), `./install.sh` downloads **Python 3.14.7** from python.org. An already-supported interpreter is left alone. TACU still never modifies system Python packages — it creates its own venv.

```sh
git clone https://github.com/bhupenderbhardwaj83/tacu.git
cd tacu
chmod +x install.sh
./install.sh
```

That is the whole path. Copy `.env.example` to `.env` first only if you want to change defaults; otherwise the script uses:

- **Python:** any **3.11+** already on the machine; otherwise **3.14.7** from python.org
- **Chat model:** `gemma4:12b-mlx` on Apple Silicon (`gemma4:12b` elsewhere). Setup pulls **only this one**. If Gemma or `qwen2.5-coder:7b` is already installed, that copy is used and nothing else is pulled.
- **Ollama:** MLX-capable **0.32.14** on Apple Silicon (prompts to upgrade if your build is older)
- **Timeout / keep-alive:** 15 minutes
- **SearXNG:** TACU's own container `tacu-searxng` on `127.0.0.1:8080` (next free port if 8080 is taken)
- **Docker Desktop:** installed/started when needed

The script:

1. Checks RAM and disk (with a progress wait if Ollama or Docker is still starting)
2. Installs TACU in `~/.local/share/tacu/runtime/venv`
3. Puts `ticu` and `ti` on your PATH (`~/.local/bin`)
4. Sets up Ollama (MLX on Apple Silicon) and one chat model (Gemma, or an already-installed backup)
5. Starts Docker Desktop + the SearXNG container
6. Creates a workspace
7. Prints `ticu doctor` as the next step

Open a **new terminal**, then:

```sh
ticu doctor
ticu help
ti
```

**Windows (experimental):** run `.\install.ps1` from PowerShell in the cloned folder. Windows should not be considered release-certified until its installation and functional pre-release reports pass on a Windows host.

### Lighter install

```sh
./install.sh --skip-models          # TACU now; pull the model later with ticu setup
./install.sh --skip-ollama --skip-models   # native tools only (no model)
./install.sh --skip-docker          # skip SearXNG / ti web
./install.sh --dry-run              # show the plan, change nothing
./install.sh --use-current          # this directory is the workspace
```

Optional overrides without editing the script:

```sh
cp .env.example .env   # then edit TACU_MODEL, TACU_BACKUP_MODEL, TACU_OLLAMA_VERSION, …
./install.sh
```

`.env` is gitignored. No `.env` file is required; the installer uses those same defaults on its own.

Hardware floor: **16 GB RAM** (32 GB preferred), **40 GB** free disk on first install, **20 GB** if Ollama + Docker + the models are already present. Use `--force` only if you accept a weaker setup.

---

## Which command?

| You want… | Use |
|---|---|
| A host fact, file CRUD, search, tests — native tools | `ti auto …` |
| To **see** the plan and approve every step (shell fallback allowed) | `ti do …` |
| Language, explanation, “how do I…” | `ti ask …` |
| You already know the argv | `ti run -q QUESTION -- command` or `ti inspect -- command` |
| A huge file (CSV / PCAP / Burp / hive) | `ti data load FILE` then `ti data ask NAME …` |
| Local web search | `ti web QUERY` (starts TACU's `tacu-searxng` on `127.0.0.1:8080`, or the next free port) |

`ti auto` refuses invented shell commands. `ti do` is the same planner with review, and may fall back to a looser plan. Both pause on deletes, writes outside policy, and host mutations.

```sh
ti auto which process is consuming most CPU
ti do please generate a shell script that scans open TCP ports and save it as sc.sh
ti ask explain split-horizon DNS
ifconfig | ti ask which interface has my LAN address?
```

---

## 15 TACU Use Cases!

1. **Instant Host & Telemetry Diagnostics** — Distill system telemetry (LAN/public IP, active interfaces, CPU/RAM process hogs, listening port owners, outbound TCP connections) into exact facts without regex or `ps`/`netstat` archaeology.
   `ti auto what is my primary IP` · `ti auto what is my public IP` · `ti auto what is listening on port 443` · `ti auto top outbound TCP connections`

2. **No-Noise Infrastructure & Container Inspection** — Query Docker containers, images, port maps, and active local Ollama models without parsing 400-line JSON blobs or terminal clutter.
   `ti run -q "what image is this container using?" -- docker inspect ID` · `ti auto list active local AI models`

3. **Repo-Aware Code Search & Structure Mapping** — Search codebase patterns and generate visual ASCII project maps while automatically ignoring `node_modules`, `.git`, and vendor noise.
   `ti auto search this repo for TODO` · `ti tools map . --depth 3`

4. **Safe Workspace File Engineering** — Create and edit project source files with hard policy gates that block accidental modifications to OS-critical paths (`/System`, `/etc`, `/usr`).
   `ti auto create app.py with a flask server` · `ti auto update database connection string`

5. **Review-First Script Generation (`ti do`)** — Generate shell scripts and automate multi-step tasks with a mandatory human-in-the-loop plan review before any script touches your shell.
   `ti do generate a port scanner script and save as scan.sh`

6. **Destructive Action Safety Gates** — Perform file removals, process terminations, and host modifications with automatic confirmation gates to prevent accidental data wiping or runaway execution.
   `ti auto remove program.py` · `ti auto kill process on port 8080`

7. **Juicy-information discovery, then a filtered question** — Extract secrets and identifiers locally with no model. Ask only after the harness has filtered to the value or kind you named; the model never sees the full dump.
   `ti juicy dump.csv -o findings.csv` → `ti data load findings.csv --name secrets` → `ti data ask secrets is ada@example.com in the data`
   `ti juicy ./exports --ask is mobile number 9713442354 in the data`

8. **Big Data & Packet Capture Q&A (`ti data`)** — Ingest massive CSVs, PCAPs, Burp XMLs, and SQLite DBs into a local indexed store and ask natural language questions without blowing LLM context limits.
   `ti data load traffic.pcap --name dns` → `ti data ask dns show all queries for example.com`

9. **Terminal Pipe Augmentation** — Pipe noisy output from legacy CLI tools (`ifconfig`, `docker`, `nmap`, `git`) directly into local AI to extract specific answers instantly(provided command should complete before 120 seonds, 2min. Alternatively, move the long running command output to a file and then ask ti auto on that file).
   `ifconfig | ti ask which interface has my LAN address?` · `docker inspect ID | ti run -q show open ports`

10. **Local Privacy-Preserving Web Research** — Conduct live web searches and pull page snippets locally via SearXNG without cloud telemetry, ad trackers, or third-party data collection.
    `ti web current macOS security advisories` · `ti web --snippets python 3.14 release features`

11. **Git Repository & Change Auditing** — Summarize git status, recent commits, uncommitted diffs, and branch states using natural language instead of memorizing complex git flag combinations.
    `ti auto summarize uncommitted git changes` · `ti ask explain the last 3 git commits`

12. **Persistent Turn History & Session Browsing** — Retain up to 100 recent terminal turns locally, browse past interactions, and search prior answers without losing context when scrollback clears.
    `ti review` · `ti review search dns` · `ticu`

13. **Instant Clipboard & Clip Notes Management** — Copy latest AI answers, extract line ranges, or manage scratchpad notes (`ti clip`) for seamless reuse across terminal sessions.
    `ti copy` · `ti copy last` · `ti clip list` · `ti copy 42:L10-L15`

14. **Structured Multi-Format Artifact Export** — Export diagnostic findings, generated scripts, and AI responses into Markdown, JSON, or plain text for documentation and team tickets.
    `ti save 42 --format md` · `ti save 42 --format json`

15. **Offline-Capable Local Model Control** — Switch local coding models, adjust context windows, set keep-alive timeouts, and run core/model workflows without a cloud model. Explicit network features such as `ti web` remain available when current internet facts are needed.
    `ti config update --model qwen2.5-coder:7b` · `ticu doctor`

---

## Endpoint forensics

One question, correlated answer. TACU ties each outbound connection to the process that
owns it, that process to its executable, and the executable to its location and signing
authority — then reports only what more than one signal agrees on.

```sh
ti auto am i compromised                      # full sweep, correlated and scored
ti auto is anything calling home              # outbound, with the owning process
ti auto is something reading my ssh keys      # who holds credential files open
ti auto what starts automatically at login    # persistence entries
ti auto am i connected to example.com         # a verdict about that host
```

```text
2 findings, none high severity.
[REVIEW] com.docker (pid 92894) reading ~/.docker/config.json
    - has docker registry credentials open
Checked: 41 external connections, 0 exposed listeners, 37 startup entries, 2 credential readers.
Not inspected: root-owned cron and system daemons require sudo
```

A signed binary in a normal location is not raised. An unsigned binary running from `/tmp`
that also holds an outbound socket and a launch agent is. Checks that need root are named
as not inspected rather than skipped silently — an answer that hides its own blind spots is
worse than no answer.

Everything runs as native tools, so `ti do` shows the same plan for review and `ti auto`
still refuses invented shell.

---

## Everyday loop

```sh
ticu                          # interactive prompt
ti help                       # mind-map of commands
ti auto --dry-run INTENT      # plan only
ti copy                       # latest answer → clipboard (same as ti copy last)
ti review                     # browse retained turns (max 100)
ticu doctor                   # model, Docker, workspace, PATH
```

After an answer: `[c] copy` `[s] md` `[j] json` `[t] txt`. Turn ids are yellow.

Long output pauses after 20 lines (Enter = one line, Space = a page, `q` = stop). `TACU_NO_PAGER=1` prints everything.

---

## Resources: CPU and memory

**TACU the CLI is small.** The heavy process on your machine is almost always **Ollama + the chat model**, not `ti`.

A 12B Gemma build can sit at **~16 GB RAM** while loaded. That is expected. Activity Monitor “Python” at ~100% for hours is usually:

- Ollama generating, or
- a leftover `python -m http.server` from `filesystem.serve`, or
- a `ti data` / planner call that has not finished

Idle behaviour:

- Ollama **keep-alive defaults to 15 minutes** (`TACU_KEEP_ALIVE`). After you stop asking, the model can unload. Set `TACU_KEEP_ALIVE=0` to unload immediately, or `30m` if you prefer a longer warm window.
- Chat and command **timeout defaults to 15 minutes** (`--timeout` / `TACU_TIMEOUT=900`).
- Context window defaults to 8K tokens (`TACU_NUM_CTX`). Reply length defaults to 1024 tokens (`TACU_NUM_PREDICT`) so Gemma 4 can finish hidden thinking and still write the answer.
- Syntax highlighting skips dumps larger than 200 KB so inspect/pcap print does not burn a core.
- zsh ghost suggestions reuse the previous scan while a line is being edited, instead of rescanning history on every redraw.

Prefer a smaller coding model when you do not need Gemma 12B:

```sh
ti config update --model qwen2.5-coder:7b
# or
ti config update --model qwen2.5-coder:1.5b --context-turns 2
```

---

## Safety (short)

- **Local only.** Default provider is Ollama on loopback.
- **No sudo store.** TACU does not keep an admin password or a root session.
- **Workspace writes.** Create/edit/delete of source files stay inside the selected workspace. OS-critical paths (`/System`, `/usr`, `/etc`, …) cannot be mutated.
- **Policy gate.** Deletes, secret-bearing argv, package/process/container changes, and outbound writes pause for review. `ti auto` will not invent `bash -c`.
- **Web fetch.** SearXNG is loopback-only. Page reads are GET, no cookies, public addresses only.
- **Your data** lives under `~/.local/share/tacu/` (history, clipboard, artifacts). That directory is gitignored and is not part of this repository.

See [SECURITY.md](SECURITY.md).

---

## Web research

```sh
ti web current macOS security updates
ti web --snippets ransomware trends
ti web health
```

Requires Docker image `searxng/searxng:latest`. TACU starts its own `tacu-searxng` container on `http://127.0.0.1:8080`, or the next free port if 8080 is already in use (`./install.sh` and `ti web` start it).

---

## Data files too big for a prompt

```sh
ti data load capture.pcap --name dns
ti data ask dns show me all transactions for domain example.com
ti data list
```

Readers: CSV/TSV, JSON/NDJSON, XLSX, PCAP/PCAPNG, SQLite, registry hive, Burp XML/JSON, text `.bak`.

---

## Documentation index

| Doc | What |
|---|---|
| This README | Install, why, commands, use cases |
| `ti help` / `ti help TOPIC` | In-CLI reference (`ask`, `auto`, `run`, `juicy`, `data`, `web`, …) |
| [SECURITY.md](SECURITY.md) | Trust boundary and private vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, tests, and contribution expectations |
| [CHANGELOG.md](CHANGELOG.md) | Release history and notable changes |

License: [MIT](LICENSE).
