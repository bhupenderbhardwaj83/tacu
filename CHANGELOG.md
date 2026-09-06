# Changelog

All notable TACU changes are documented here. TACU follows [semantic versioning](https://semver.org/).

## [0.3.9] - 2026-09-06

### Changed

- Looking at your own machine no longer needs a review step. `ti do` now runs a plan
  whose every step is read-only without asking for approval, so "is docker installed",
  "what is in this folder" and "how much disk space is free" read the same under
  `ti ask`, `ti auto` and `ti do`. Anything the policy will not run unattended —
  including sensitive paths — is still reviewed exactly as before.
- A question phrased in the user's own words now reaches the same tool as the catalog's
  own phrasing. "what files are in this directory" no longer needs to be said as
  "list directory". This applies only to read-only capabilities, only when nothing
  else matched, and only when two of the question's nouns point the same way, so
  "list the widget inventory" still means nothing to TACU.

### Fixed

- "is docker installed" was answered by the container catalog and then sent back for
  replanning twice before giving the same answer. A question about whether something is
  installed, where it lives, or which version it is, is a question about the application
  bundle, and is now routed and judged as one.
- A single application was described three times over, once per lookup, with the three
  records appearing to contradict each other. One question about one application now
  produces one statement, and it leads with what was asked: the version for a version
  question, the date for an install-date question, yes or no for "is it installed".
- A misspelt name reached a dead end. "is flacon installed" now answers with the closest
  installed name.
- "what is the version of Google Chrome" also reported an unrelated Google product,
  matched through a vendor hint in its bundle id. A weak vendor match is now only
  considered when nothing better answers.
- "what operating system version am i running" was answered with the version of the first
  bundle in /Applications, because "system version" was read as an application name.
- A disk question was answered with a pasted `df` table and a question about uptime was
  answered with the platform string. Both now lead with the number that was asked for.
- Answers sometimes contained words in Devanagari or another script the question never
  used — drift from the local multilingual model. The harness now detects a script the
  question did not use and asks for the answer again, and the answer writer is told to
  reply in the language it was asked in.

## [0.3.8] - 2026-09-06

### Fixed

- An application was reported as missing while it sat in /Applications, because the whole
  phrase had to appear in the bundle name: CrowdStrike ships `Falcon.app`, so "which version
  of crowdstrike falcon" found nothing. Matching now works on the words that carry meaning
  and ranks the closest bundle first, while a two-letter fragment matches nothing.
- "show all the applications" answered with the first 40 of 79. A listing no longer stops
  short, and asking for "all" asks for all.
- "is burp suite installed" and "which version of X" reached no tool at all; both now
  route with the name they contain.
- A replan was told only that something was unmet, so it produced another file with the
  same gap and spent the whole turn budget doing it. The planner is now told which claim
  failed and what was looked for, and a claim that survives one retry is reported instead
  of being retried again.

## [0.3.7] - 2026-09-06

### Added

- A request that asks for more than one thing is planned as more than one step.
  "read app.py then open safari" reads and then opens; "open google chrome and launch
  apple.com" stays a single action, because "and" alone does not make two instructions.
  A chain whose parts cannot all be placed is left to the planner rather than half done.

### Fixed

- A domain has the shape of a filename, so `apple.com` was looked for on disk and
  "open the apple.com main website in google chrome" became a hunt for files that never
  existed. Addresses are no longer read as paths, while real paths are unaffected.
- `ti auto` refused a launch without saying what to do. It now names the target and the
  command that runs it.
- A filename is no longer mistaken for an application name, so "run program.py" is still
  a script rather than something to launch.
- A chained plan kept only its host action, dropping the other steps.

## [0.3.6] - 2026-09-06

### Added

- `application.open` takes a web address, so "open google chrome and launch apple.com" is
  one reviewed step. Addresses must be http or https and are passed as separate arguments,
  never through a shell. The application is matched against what is installed, so "google
  chrome" finds Google Chrome without any list of application names.
- A request's behaviour is checked where it leaves a mark: a page asked to collect input
  and greet the user is verified for both, not merely for existing.
- An install is confirmed by importing the package, and a command that would run a server
  is reported rather than waited on, since a process that never returns cannot be waited for.

### Fixed

- An operation that required review could never run: approval was inferred from the policy
  level, so `application.open` refused even after the step was shown and executed. Seeing a
  step and choosing to run it now counts as the review.
- Host actions were ranked ahead of better matches regardless of score, so "launch
  apple.com" was answered by `docker start`. The whole field is now ranked by score.
- The duplicate `application.open` capability was removed.

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

[0.3.8]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.3.8
[0.3.7]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.3.7
[0.3.6]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.3.6
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
