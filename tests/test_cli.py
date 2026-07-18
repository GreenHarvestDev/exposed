"""Tests for the CLI wiring (no network — run_scan is stubbed)."""

import json

from exposed import cli

FAKE_RESULT = {
    "scanned_at": "2026-07-18T00:00:00+00:00",
    "identity_summary": {
        "name": "Jane Public",
        "emails": ["j@x.com"],
        "usernames": ["janep"],
        "location": "Portland, OR",
        "configured": True,
    },
    "stats": {"high": 1, "clear": 1},
    "findings": [
        {"source": "HudsonRock", "severity": "high", "title": "hit", "detail": "d", "action": "a"},
        {"source": "Gravatar", "severity": "clear", "title": "ok", "detail": "", "action": ""},
    ],
    "brokers": [{"name": "X"}],
    "dorks": [{"engine": "Google", "label": "Exact name", "url": "https://g"}],
}


def _write_identity(tmp_path):
    p = tmp_path / "exposed_identity.json"
    p.write_text(json.dumps({"full_name": "Jane Public", "emails": ["j@x.com"]}), encoding="utf-8")
    return p


def test_missing_identity_returns_2(tmp_path, capsys):
    rc = cli.main(["--identity", str(tmp_path / "nope.json")])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_invalid_json_returns_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert cli.main(["--identity", str(bad)]) == 2


def test_successful_run_writes_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: FAKE_RESULT)
    identity = _write_identity(tmp_path)
    out = tmp_path / "report.json"
    rc = cli.main(["--identity", str(identity), "--out", str(out), "--no-color"])
    assert rc == 0
    assert out.exists()
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["stats"]["high"] == 1
    # human-readable summary mentions the finding
    assert "hit" in capsys.readouterr().out


def test_json_mode_emits_full_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: FAKE_RESULT)
    identity = _write_identity(tmp_path)
    rc = cli.main(["--identity", str(identity), "--out", str(tmp_path / "r.json"), "--json"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["identity_summary"]["name"] == "Jane Public"
