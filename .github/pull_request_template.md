# Summary

<!-- What does this PR do and why? -->

## Checklist

- [ ] `ruff check .` passes
- [ ] `ruff format .` applied
- [ ] `pytest` passes
- [ ] New/changed logic has tests that **mock the network** (no live requests)
- [ ] Any new source is free and needs no account/API key
- [ ] Change stays within scope: scanning the operator's *own* identity (see SECURITY.md)
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (for user-facing changes)
