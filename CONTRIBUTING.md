# Contributing to exposed

Thanks for helping out. This project has one rule above all: **keep it readable and
tested.** Someone should be able to open any file and understand it without wading
through cleverness or dead code.

## Project layout

```
exposed/
  scan.py      # all scanning logic — pure functions + one check_* per source.
               # Uses ONLY the standard library. No presentation code here.
  render.py    # terminal presentation (rich). No logic here.
  cli.py       # argument parsing + wiring. Thin.
  brokers.json # the generic data-broker list (templated URLs, no PII)
tests/
  test_scan.py # offline, mocked, deterministic
scripts/
  make_screenshot.py  # regenerates assets/demo.svg from a fixed demo dataset
```

Guiding split: **`scan.py` decides *what's true*, `render.py` decides *how it looks*.**
Keep them separate — it's what lets people build their own UI on top of `--json`.

## Dev setup

```bash
git clone https://github.com/GreenHarvestDev/exposed.git
cd exposed
pip install -e ".[dev]"      # editable install + pytest & ruff
```

## Before you open a PR

Run these locally — CI runs the same and will block otherwise:

```bash
ruff check .          # lint
ruff format .         # auto-format
pytest                # tests must pass
```

## Adding a new source check

1. Write a `check_<source>(...)` function in `scan.py` that appends **finding dicts**
   with this exact shape:
   ```python
   {"source": str, "severity": "high|medium|low|info|clear",
    "title": str, "detail": str, "action": str, "url": str}
   ```
2. Call it from `run_scan()`.
3. Add a test in `tests/test_scan.py` that **mocks the network** (`monkeypatch` on
   `scan.http_get`) — no test may hit the internet.
4. Keep it free and no-account. `exposed` deliberately uses only sources that need
   no API key or signup.

## Scope & ethics

`exposed` is a **defensive** tool: it scans the *operator's own* identity. PRs that
turn it into a tool for profiling other people will be declined. See
[SECURITY.md](SECURITY.md).

## Commit style

Small, focused commits with a clear subject line. Explain the *why* in the body if
it isn't obvious.
