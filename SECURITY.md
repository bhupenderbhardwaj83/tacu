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

TACU does not store an administrator password or maintain a sudo keepalive.

## Reporting

Do **not** open a public issue for a suspected vulnerability.

Use [GitHub private vulnerability reporting](https://github.com/bhupenderbhardwaj83/tacu/security/advisories/new) to report vulnerabilities in TACU itself. Include the affected version, operating system, reproduction steps, impact, and any suggested mitigation. GitHub repository administrators must enable private vulnerability reporting before public launch.

Never attach real captures, credentials, private keys, customer data, or unredacted runtime databases. Replace sensitive evidence with the smallest synthetic reproduction possible.

You should receive an acknowledgement within five business days. Please allow a reasonable remediation period before public disclosure.
