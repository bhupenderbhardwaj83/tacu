# Changelog

All notable TACU changes are documented here. TACU follows [semantic versioning](https://semver.org/).

## [0.3.5] - 2026-09-06

### Added

- A request's checkable claims are extracted and verified against the workspace, so "done"
  is decided by looking rather than by the last exit code. Asking for an index file and
  receiving a Flask app is now reported as unmet, with a CHECK summary listing what holds
  and what does not.
- Setting up an environment or installing a dependency is carried out instead of being
  handed back as a shell script. A tool the user names outranks both the lockfile and any
  preference, and a request whose ecosystem cannot be established proposes nothing rather
  than guessing.
- `diagnose.toolchain` reports which interpreters and package managers are actually present
  and which one this project would use.

### Changed

- A task carrying acceptance criteria gets a larger turn budget. Extra turns are safe
  because an attempt is never repeated.
- Installs call the environment's own `python -m pip`, so a machine with `pip3` and no
  `pip` behaves the same as any other.

## [0.3.4] - 2026-09-06

### Fixed

- A failed command was retried unchanged until the turn budget ran out. The correction for
  a non-zero exit re-derived the same plan from the same words, and because it returned
  something the model was never asked to replan. The loop now refuses to repeat an attempt
  it has already made, and a replan that only repeats earlier work stops instead of looping.

### Added

- The harness reads the failure before deciding what to do. A missing Python module becomes
  create-an-environment, install, and retry inside it; a missing node module becomes an
  install with the project's own package manager; an unexecutable script is run through a
  shell; a bare `pip` becomes `python -m pip`. An unrecognised failure proposes nothing
  rather than guessing.
- Dependency work uses the environment's own binaries and never shell activation, which
  cannot affect a subprocess. Import names are mapped to distribution names, so a missing
  `cv2` installs `opencv-python`.
- The project's lockfile decides the package manager: `package-lock.json` means npm even
  where pnpm is installed, `uv.lock` means uv. `uv` and `pnpm` are preferred only where
  nothing is pinned and they are actually present.

## [0.3.3] - 2026-09-06

### Fixed

- A dataset test asserted POSIX permission bits, which Windows does not have. Guarded the
  same way the other permission assertion already was.

### Changed

- CI gates on macOS and Linux and reports Windows without blocking, matching the support
  level the README states. Windows has failed since the first release for reasons rooted
  in POSIX assumptions across the suite; that work is tracked separately.

## [0.3.2] - 2026-09-06

### Added

- `process.graph` correlates every process with its lineage, its runtime and the ports it
  holds, so questions like "what is running on port 8080", "which process is running my
  python http server", "is vite running" and "what servers are running" now have answers
  that name the PID and how to stop it. `ti help processes` documents it.
- Runtime and role are derived from the command line and from what a process holds — a
  listening socket is what makes something a server — rather than from a list of known
  applications, so an unfamiliar tool is described as accurately as a familiar one.

### Changed

- Versioning: patch releases now carry new capabilities too. A minor bump is reserved for
  a major step rather than every feature.

## [0.3.1] - 2026-09-05

### Fixed

- A question naming a process by number failed with "find requires query". PIDs are now
  read from the wording people actually use ("process with id 92894", "details of process
  92932"), and such a question routes to `inspect`, which takes a PID. `find` also accepts
  a PID rather than dead-ending, and its error now says which operation to use.
- Inspecting one process answered with the top-CPU ranking. It now reports that process:
  command, PID, owner, parent, CPU, memory, and executable.
- "list running processes" and "what processes are running" matched nothing.

## [0.3.0] - 2026-09-05

### Added

- `ti version --history` lists every released version with its notes and marks the one
  installed. The changelog now travels inside the wheel, so this answers the same from an
  install as from a checkout.

### Changed

- `ti tools list` uses the same entry format as the rest of the help — name, shape,
  runnable example, then risk level and the full purpose — instead of its own table.

## [0.2.2] - 2026-09-05

### Changed

- Native tools in `ti tools --help` now follow the same entry format as every other
  help section: name, shape, runnable example, then what it is for. The shape and the
  description come from each tool's own contract, so they cannot drift from it, and a
  test asserts every registered tool has all four parts.

## [0.2.1] - 2026-09-05

### Fixed

- Certificate attribution probed only 12 endpoints while a browsing machine holds tens
  open, so a connected CDN-fronted site could be reported as not connected. Coverage now
  matches a real machine and the endpoints sharing the resolved prefix are checked first.
- A negative answer said "checked N of M" when all M were probed and only N replied.

### Changed

- `ti tools --help` lists every native tool, grouped, with the count. The list is derived
  from the registry, so a new tool can never be missing from it.

## [0.2.0] - 2026-09-05

### Added

- `ti help forensics`, and a forensics tool covering `sweep`, `outbound`, `listening`,
  `persistence`, and `secret_access`.
- Optional elevated forensic checks behind a reviewed `ti do` plan: a fixed read-only
  command list run with `sudo -n`, with no password ever prompted for, read, or stored.
- Connections to a named host are matched by DNS address, reverse DNS, or the TLS
  certificate the endpoint serves, so a site behind a CDN or WAF is still attributed,
  and the answer says which evidence was used.

### Fixed

- lsof rows were sliced at header column widths, but lsof right-aligns PID and USER, so a
  wide pid or long username silently corrupted both. Every process attribution built on
  lsof was affected, including port ownership.
- A question naming a host returned a destination-port ranking instead of a verdict.

### Changed

- The version now lives only in `src/tacu/__init__.py`; `pyproject.toml` declares it dynamic.

## [0.1.0] - 2026-08-30

First public release.

### Added

- Local-first terminal companion with deterministic native recipes and guarded AI planning.
- Structured tools for workspace files, system facts, processes, networks, Git, Docker, and Ollama.
- Large-file workflows for CSV, JSONL, XLSX, PCAP, Burp, registry-hive, SQLite, and text data.
- Local juicy-information extraction and filtered AI questions.
- Correlated endpoint forensics: outbound connections tied to the owning process, its
  location and signature; exposed listeners; persistence entries; and processes holding
  credential files open, with the checks that need root reported rather than hidden.
- Named-host connection answers, so "am I connected to example.com" is a verdict about
  that host rather than a ranking of destination ports.
- Retained history, secured raw evidence, clipboard tray, backups, and workspace controls.
- Local SearXNG-powered `ti web` research with cited answers.
- Date, time, day, and timezone answered deterministically from the machine's own clock,
  with the same clock grounding the model for `ti ask` and `ti web`.
- Guided installers for macOS, Linux, and experimental Windows support.

[0.3.5]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.3.5
[0.3.4]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.3.4
[0.3.3]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.3.3
[0.3.2]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.3.2
[0.3.1]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.3.1
[0.3.0]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.3.0
[0.2.2]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.2.2
[0.2.1]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.2.1
[0.2.0]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.2.0
[0.1.0]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.1.0
