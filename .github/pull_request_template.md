## What changed

Describe the user-visible outcome and why it belongs in TACU.

## Validation

- [ ] Added or updated tests for changed behavior.
- [ ] Ran `python -m unittest discover -s tests` successfully.
- [ ] Updated README/help/changelog where user-visible behavior changed.
- [ ] Used only synthetic or redacted test evidence.

## Local-first and safety review

- [ ] Model inference and retained data remain local by default.
- [ ] Any network access is explicit and documented.
- [ ] Workspace boundaries and destructive-action gates remain intact.
- [ ] No credentials, runtime databases, captures, reports, or administrator-only files are included.
