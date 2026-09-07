# Changelog

All notable TACU changes are documented here. TACU follows [semantic versioning](https://semver.org/).

## [0.4.2] - 2026-09-07

### Fixed

- A definitive ask now gets the whole answer. "How many files are there, show their
  names" reported the count correctly and then listed twenty of thirty-one, stopping
  mid-list with nothing on screen saying the answer was partial — the count was right
  and the list was short, which is the worst of both.
- The cause was not the model or the token budget: evidence with more than 24 lines
  was cut to its first 24 before the model ever saw it. A 34-line `ls -la` is 2,633
  characters against a 20,000-character budget and was still sampled. Everything that
  fits the budget is now sent whole.
- When input genuinely exceeds the budget, both ends are kept and the gap is stated —
  `[TACU omitted N middle line(s) of M]`. Previously input between 25 and 48 lines
  lost its tail entirely, with no marker at all.
- A reply cut off at the token limit is now retried with a wider budget instead of
  being handed over as though it were finished. Only a reply with *empty* content was
  retried before, so a half-written list was streamed out and presented as complete.
  If the widest attempt still runs out, the answer says it is incomplete.
- The reply ceiling rises from 4096 to 8192 tokens. Naming 77 files needs more room
  than 4096 leaves once a model has spent some of it thinking; at 4096 it returned
  nothing at all. The ceiling only costs anything on the retry path.
- The answer writer was told to use at most 60 words for host facts, with no exception
  for being asked to list things. Listing, naming, showing and counting are now exempt,
  and it is told never to stop a list partway or state a count it does not then list.

## [0.4.1] - 2026-09-07

### Fixed

- Piped input was ignored by `ti auto`, `ti do` and `ti code`. Those verbs return
  before the block that reads stdin, so `nmap … | ti auto which ports are open`
  threw away the scan it was handed and reported this machine's own listening
  ports — a confident answer about the wrong computer. All four verbs now read
  what was piped in.
- `ti ask` discarded piped evidence too, by a different route: a host-shaped
  question promoted itself to a host inspection and dropped the supplied data on
  the way, which is where the "10 listening ports … depth limit" answer came from.
  It no longer promotes when something was piped in.
- Piping means "here is the data", so asking the host about itself can only be
  wrong. Only a request that changes something — writing a file, stopping a
  container, launching an application — still plans; everything else is answered
  from the input.
- "which database ports are open in this **output**" tried to launch an application
  called "output". Words for the text in front of you — output, results, log, scan,
  report, response, listing and the rest — are no longer read as application names.
- An empty pipe (`ti ask … < /dev/null`) was treated as evidence, which answered
  every host question with "nothing here". Nothing piped in is nothing piped in.

## [0.4.0] - 2026-09-06

### Added

- `ti code` (aliases `script`, `build`) plans long-horizon coding and scripting work
  with a larger local model. A 12B planner returns a good four-step plan about half
  the time; the rest is truncated JSON and timeouts. `ti code` uses
  `qwen3.8:27b-mlx` with the reply, context and step budgets that model needs, and
  runs under exactly the same policy gates as `ti auto`.
- It **refuses** rather than falling back when that model is not installed, and says
  which command fixes it. Planning a long task with the small model is the failure
  the verb exists to avoid, so substituting it silently would make the verb a lie.
  `TACU_CODING_MODEL` points it at a different model; `--keep-models` skips unloading.
- Other loaded models are unloaded first. Ollama evicts under memory pressure on its
  own, but a long keep-alive means it holds a model nothing is asking for until the
  timer expires, and a 27B planner with a large KV cache wants that memory now.
  Nothing reloads them here: the next ordinary question loads what it needs.
- `ollama settings` reports every Ollama setting in force — each environment variable
  and whether it is set, what TACU sends with every request, and **which of the two
  actually applies**. `OLLAMA_KEEP_ALIVE=60m` is overridden by the `keep_alive` TACU
  sends per request, so the environment value never reaches the server; the answer
  now says so instead of reporting a number that does not apply. `ollama version` too.
- Git grew from 10 operations to 32: `pull`, `fetch`, `clone`, `checkout`, `merge`,
  `reset`, `revert`, `restore`, `stash`, `stash_pop` and `tag`, alongside `show`,
  `blame`, `config`, `tags`, `stashes`, `describe`, `shortlog`, `reflog`, `files`,
  `diff_staged` and `ahead_behind`. Daily Git was simply absent.
- Docker grew from 13 to 27: `info`, `version`, `disk_usage`, `top`, `port`,
  `history`, `events` and `compose_ps` for reading; `restart`, `kill`, `pause`,
  `unpause`, `prune` and `exec` for changing, all reviewed.

### Fixed

- A capability was penalised 80 points for not containing its tool's name, which
  cancelled its own phrase match. "who wrote this file", "stash my changes" and
  "what is my keepalive" all scored below the bar and reached no tool, which is what
  sent people back to the native commands these tools exist to replace. A phrase
  match is now evidence in itself, for Git, Docker and Ollama alike.
- "restart the container" was answered by `docker.start`, because the operation name
  was matched as a substring and "restart" contains "start".
- Every host mutation was given a score floor, so they all tied and "checkout the
  main branch" could be answered by `process.kill`. They are scored on their merits.
- The reviewed-mutation gate did not recognise Git or Docker state changes, so `ti do`
  could not reach pull, stash, checkout, merge, restart, prune or exec at all.

## [0.3.13] - 2026-09-06

### Fixed

- TACU was typing Hindi into the command line. A single mangled Devanagari entry
  in `~/.zsh_history` matched the prefix `ti auto ` and the ghost suggester offered
  its remainder as completion text, so accepting a ghost inserted characters the
  user never typed and could not read. Ghost suggestions drawn from history are now
  ASCII only, from both the TACU log and the shell history. This was never a
  keyboard or input-source problem: the text came from TACU.

## [0.3.12] - 2026-09-06

### Fixed

- A build request was read as a request to launch an application. "start that flask
  application after creating a virtual environment" became
  `application(open, name=that flask application after creating a virtual environment)`,
  which `ti auto` refused, `ti ask` refused with the same words, and `ti do` planned
  and then rejected as needing review — three verbs, three dead ends, on an ordinary
  task. An application name is now a few words with no verbs or prepositions in them,
  and a request that mentions creating, installing or a virtual environment is work to
  do rather than something already on the machine.
- `ti do` could not run `application.open` at all. The read-only fast path added in
  0.3.9 treated the step as needing no review because the policy calls it safe, which
  skipped the review the tool itself asks for and left the operation impossible. Only
  a step whose capability is declared read-risk now skips review.
- A build request was answered with a host fact. "create a venv and start the app"
  returned the current working directory, because host read tools outscored everything
  else and the planner was never offered anything that could build. Those tools are now
  withheld from a build request, and writing a file and running a command are offered
  instead — `write_file` scored zero on a request to create a file.
- "installing required dependencies" installed nothing: `\binstall\b` did not match
  "installing", and the phrase names no package. The project is read instead — a
  requirements file is installed with `-r`, and failing that the framework named in the
  request is what gets installed, so "for flask application" installs flask.
- A file inside the workspace was reported as outside it. A venv's `bin/python` is a
  symlink to the interpreter that built it, so resolving it landed in `/opt` and the
  project's own binary needed permission. The written path is now judged as well as the
  resolved one; traversal out of the workspace is still refused.
- Several commands written as one string — `python3 -m venv venv && ./venv/bin/pip
  install -r requirements.txt` — were handed to a shell as a single argument, which the
  shell read as a file name and exited 127, stopping the plan on a command that never
  ran. A compound command becomes one step per command, each still argv-safe.
- "ensure index.html is the default page" carried no checkable claim, because only
  create/make/write counted as asking for something. The run then reported success
  having produced nothing. Ensure, set up, start, serve and run now count, so an
  unmet claim is reported and replanned instead of passing silently.

## [0.3.11] - 2026-09-06

### Added

- Pushing a version tag now publishes a GitHub release. `.github/workflows/release.yml`
  takes the notes from this file's section for that version, refuses to publish when
  the section is missing or when the tag disagrees with `src/tacu/__init__.py`, and
  creates the release from the tag. Nothing publishes from a branch, so a release
  stays a deliberate act: `git push origin v0.3.11`.
- The README carries a version badge that reads the latest published release, so it
  cannot drift from the real version the way a hand-written number does.

- `ti migrate` packages this whole working copy as one zip beside it, so the same
  TACU can be rebuilt on another computer. The archive is named
  `tacu_HHMM_IST_DD_MMM_YYYY_your-description.zip` and lands one directory above
  the checkout, never inside the copy it is packaging.
- What travels is everything in the tree, including what `.gitignore` hides:
  `not_required/`, `pre_release_tests/`, local notes, captures and `.git` itself.
  That is the point — a fresh clone gives you the tracked files and nothing else.
- What stays behind is only what the other machine rebuilds for itself: `.venv`,
  `node_modules`, `__pycache__`, `build`, `dist`, `*.egg-info` and the other
  caches. A macOS virtualenv would not work on Linux anyway.
- `--dry-run` shows what would travel and how large it is, largest folders first.
  When one folder is more than half the archive it is named, with the `--exclude`
  line that would drop it, so carrying it is a decision rather than a default.
- `--exclude PATTERN` (repeatable) leaves out paths, and `-o` writes elsewhere.
  Credential files (`.env`, `*.pem`, keys) are listed before anything is written,
  and the zip is created owner-only, because a working copy carries them in the
  clear and the archive usually lands in a synced folder.

## [0.3.10] - 2026-09-06

### Changed

- Juicy reports are named for the project and the run:
  `_Juicy_<Project>_DD_MMM_YYYY_HHMM_IST`. Every file written by one scan carries
  the same stamp, including the master summary and the rotation report, and a
  resumed scan keeps the stamp of the run it is continuing. The time is Indian
  Standard Time regardless of the machine's own timezone.
- A directory that is itself an application is now one project. An ASP.NET app
  was being split into `Areas`, `Views`, `Scripts` and the root, producing four
  reports for one codebase. A folder that holds several repositories still
  reports one project per repository.
- Credential detection no longer works from exact field names. A candidate is an
  alias at a word boundary, an assignment, and a value — and the value is then
  classified before anything is reported. `pw`, `pwd`, `pass`, `passphrase`,
  `db_password`, `SmtpPassword` and `<password>` are all found; `bypass`,
  `compass` and `passenger_count` are not.
- Confidence is now an additive score rather than a fixed level per pattern:
  the alias, the assignment, the value's randomness, the surrounding words and
  the file's location each move it. A username beside a password is reported as
  the login it is.

### Fixed

- `password = os.getenv("DB_PASSWORD")` was reported as a hard-coded password,
  and so were `config.password`, `get_secret()`, `"${DB_PASSWORD}"`, `changeme`
  and `REPLACE_ME`. A value is now classified as a literal, an environment read,
  a reference, a call or a placeholder, and only a literal can be a secret.
- Any first line containing a comma was read as a CSV header, so a Python
  docstring turned every following line of that file into a credential. A header
  now has to look like one, and the rows below it have to agree on how many
  columns there are. Scanning TACU's own source fell from 4,087 findings to 221,
  with none of the remaining ones a credential false positive.
- An assignment could run past the end of its line, so `if executable ==
  "uname":` took the next line's `return` as a username. `==` is also no longer
  read as an assignment.
- A negative word anywhere in the surrounding window silenced a real finding: a
  `maxTokens` on the following line hid the password above it. Only the
  candidate's own line can disqualify it.
- `example.com` on the same line as a credential suppressed it, because the word
  "example" was read as documentation wording.
- Dotted identifiers were reported as hostnames — `os.path.join`, `item.value`
  and `System.Environment.GetEnvironmentVariable`. A hostname now needs a real
  public suffix, and a name that is immediately called is a function.
- `ESTABLISHED` in netstat output was reported as a SWIFT bank code.
- ASP.NET view and handler files (`.cshtml`, `.aspx`, `.ascx`, `.asax`,
  `.razor`) were not scanned at all.

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
