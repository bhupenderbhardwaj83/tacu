# Contributing to TACU

Thank you for helping improve TACU. Contributions should preserve its local-first architecture, deterministic-tool preference, workspace boundaries, and explicit safety gates.

## Before starting

- Search existing issues before opening a duplicate.
- Use a focused issue for behavior changes or substantial features.
- Never attach real credentials, captures, customer data, runtime databases, or private terminal history.
- Report suspected vulnerabilities through the private process in [SECURITY.md](SECURITY.md), not through a public issue.

## Development setup

TACU requires Python 3.11 or newer and has a standard-library-only core.

```sh
git clone https://github.com/bhupenderbhardwaj83/tacu.git
cd tacu
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps -e .
python -m unittest discover -s tests
```

On Windows, activate the environment with `.venv\Scripts\Activate.ps1`.

## Pull requests

- Keep each pull request focused on one coherent change.
- Add or update tests for changed behavior.
- Update README, help text, and the changelog when user-visible behavior changes.
- Preserve `ti auto` capability validation and confirmation gates.
- Keep file operations inside the selected workspace unless the documented policy explicitly allows otherwise.
- Do not add mandatory runtime dependencies without discussing the architecture first.
- Confirm `python -m unittest discover -s tests` passes before requesting review.

## Commit messages

Use a short imperative subject that describes the outcome, for example:

```text
Improve CSV header detection
Add Linux installer regression coverage
Clarify web evidence boundaries
```

By contributing, you agree that your contribution is licensed under the repository's MIT License.
