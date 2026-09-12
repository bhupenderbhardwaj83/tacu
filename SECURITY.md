# Security

TACU is a **local** terminal companion. The default model provider is Ollama on loopback. There is no cloud fallback.

## Supported versions

Security fixes are provided for the latest published TACU release. If a report affects an older version, include that version and operating system so the impact can be assessed.

## What this repository must never contain

- API keys, `.env` files, private keys, `credentials.json`
- Live captures: PCAP, Burp XML, hive dumps, customer CSV
- Runtime databases: `history.db`, `clipboard.db`, artifact folders
- Optional local catalogs such as `utils/wireshark_filters.csv` (not required to run)

User data belongs in `~/.local/share/tacu/` (or `%LOCALAPPDATA%\tacu` on Windows), not in git.

## Trust boundary

| Surface | Policy |
|---|---|
| Workspace writes | Relative paths inside the selected workspace |
| OS-critical paths | Cannot create, edit, or delete |
| `ti auto` | Shortlist tools only — no invented `bash -c` / `python -c` |
| `ti do` | Same planner; every step is execute / edit / abort |
| Host mutations | Kill, brew, service, docker start/stop require `ti do` |
| Secrets in argv | Redacted in audit; operations that look like exfil are blocked or prompted |
| `ti web` fetch | HTTP(S), no credentials in URL, public addresses only, GET, no cookies |
| `email` | Static: nothing in the message is executed, rendered, fetched or connected to. `parse_message(raw)` has no transport parameter; `enrich(iocs: strings, …)` cannot receive the message or attachment bytes — both held by tests. HTML tag-stripped, never rendered. Attachments hashed and magic-typed in memory; archives inventoried from the central directory, never extracted; nothing written to disk. URLs defanged in all output. Reputation lookups are about the mail's addresses and domains, from third parties, never to them |
| `recon` | GET-only; DNS-to-socket pinning; private, loopback and link-local targets refused before any request; every contacted service listed in the answer; not offered to the `ti ask` lookup loop (checked at build, not by convention); cookie values never recorded; reputation keys sent as headers only, stored 0600, never on argv or in the audit log |

TACU does not store an administrator password or maintain a sudo keepalive.

Elevated forensic checks keep that promise. TACU never prompts for, reads, or stores a
password: you authenticate to `sudo` yourself, and TACU then runs a fixed, read-only,
never-model-authored list of commands with `sudo -n`. Without a valid credential it prints
what it would have run and stops. Elevation is available only through a reviewed `ti do`
plan, so the exact commands are shown before anything runs.

## Reporting

Do **not** open a public issue for a suspected vulnerability.

Use [GitHub private vulnerability reporting](https://github.com/bhupenderbhardwaj83/tacu/security/advisories/new) to report vulnerabilities in TACU itself. Include the affected version, operating system, reproduction steps, impact, and any suggested mitigation. GitHub repository administrators must enable private vulnerability reporting before public launch.

Never attach real captures, credentials, private keys, customer data, or unredacted runtime databases. Replace sensitive evidence with the smallest synthetic reproduction possible.

You should receive an acknowledgement within five business days. Please allow a reasonable remediation period before public disclosure.
