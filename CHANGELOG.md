# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- A failed source check (network error, rate limiting, or a missing tool) is now
  reported as `info` — never as a false `clear`. Previously, e.g. a rate-limited
  GitHub search could wrongly report your email as private.
- holehe results no longer count its output legend (`[+] Email used`) as a fake
  registered site.

### Added
- Full type hints + `py.typed`; the package is now type-checked with mypy in CI.
- Tests for the CLI, the renderer, and every check's failure path (32 tests total).

## [0.1.0] — 2026-07-18

### Added
- Initial release: personal OSINT self-exposure scanner.
- Free, no-account source checks: Gravatar, Hudson Rock (infostealer logs), GitHub
  email/commit exposure, holehe (email → registered sites), Sherlock (username →
  accounts).
- Data-broker opt-out link generation (25 people-search sites) and Google/DuckDuckGo
  search-dork generation.
- `rich`-powered terminal report, with a plain-text fallback and a `--json` mode.
- Test suite (offline, mocked) and CI across Linux/macOS/Windows on Python 3.9–3.13.

[Unreleased]: https://github.com/GreenHarvestDev/exposed/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/GreenHarvestDev/exposed/releases/tag/v0.1.0
