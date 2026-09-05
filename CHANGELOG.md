# Changelog

All notable TACU changes are documented here. TACU follows [semantic versioning](https://semver.org/).

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

[0.2.0]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.2.0
[0.1.0]: https://github.com/bhupenderbhardwaj83/tacu/releases/tag/v0.1.0
