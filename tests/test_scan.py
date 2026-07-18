"""Unit tests for exposed.scan.

Network (`http_get`) and external tools (`subprocess`, `shutil.which`) are mocked,
so these tests are fast, offline, and deterministic while still exercising the
real parsing/logic in each check.
"""

import json
import types

import pytest

from exposed import scan

# ── pure helpers ──────────────────────────────────────────────────────────────


def test_name_parts_full_name():
    assert scan.name_parts({"full_name": "Jane Q. Public"}) == ("Jane", "Public", "Jane Q. Public")


def test_name_parts_falls_back_to_username():
    assert scan.name_parts({"usernames": ["janep"]}) == ("janep", "", "janep")


def test_name_parts_empty():
    assert scan.name_parts({}) == ("", "", "")


def test_get_cities_prefers_list():
    assert scan.get_cities({"cities": ["Portland", ""], "city": "Salem"}) == ["Portland"]


def test_get_cities_single_fallback():
    assert scan.get_cities({"city": "Salem"}) == ["Salem"]
    assert scan.get_cities({}) == []


def test_fill_tokens_substitutes_and_url_encodes():
    url = "https://x.com/?name={name}&city={city}"
    out = scan.fill_tokens(
        url, "Jane", "Public", "San Jose", "CA", "j@x.com", "5551234", "Jane Public"
    )
    assert "Jane%20Public" in out  # {name} url-encoded
    assert "San%20Jose" in out  # {city} url-encoded
    assert "{name}" not in out and "{city}" not in out


def test_load_json_missing_returns_default(tmp_path):
    assert scan.load_json(tmp_path / "nope.json", {"d": 1}) == {"d": 1}


def test_load_json_reads_file(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"a": 2}), encoding="utf-8")
    assert scan.load_json(p, {}) == {"a": 2}


# ── dork + broker builders ────────────────────────────────────────────────────


def test_build_dorks_includes_exact_name_and_email():
    identity = {
        "full_name": "Jane Public",
        "emails": ["j@x.com"],
        "cities": ["Portland"],
        "state": "OR",
    }
    dorks = scan.build_dorks(identity, "Jane", "Public", "Jane Public")
    labels = {d["label"] for d in dorks}
    assert "Exact name" in labels
    assert any(lbl.startswith("Email:") for lbl in labels)
    assert all(d["url"].startswith("http") for d in dorks)


def test_build_brokers_fills_tokens_from_packaged_data():
    identity = {"full_name": "Jane Public", "cities": ["Portland"], "state": "OR"}
    brokers = scan.build_brokers(identity, "Jane", "Public", "Jane Public")
    assert brokers, "packaged brokers.json should yield entries"
    for b in brokers:
        assert "{first}" not in b["search_url"] and "{last}" not in b["search_url"]
        assert b.get("optout_url") is not None


# ── individual checks (mocked network) ────────────────────────────────────────


def _patch_http(monkeypatch, handler):
    """handler(url) -> (status, body)"""
    monkeypatch.setattr(scan, "http_get", lambda url, headers=None, timeout=15: handler(url))


def test_check_gravatar_clear(monkeypatch):
    _patch_http(monkeypatch, lambda url: (404, ""))
    findings = []
    scan.check_gravatar("j@x.com", findings)
    assert findings[0]["severity"] == "clear"


def test_check_gravatar_found_with_linked_accounts(monkeypatch):
    def handler(url):
        if url.endswith(".json"):
            body = json.dumps(
                {
                    "entry": [
                        {"displayName": "Jane", "accounts": [{"url": "https://twitter.com/jane"}]}
                    ]
                }
            )
            return 200, body
        return 200, "img"

    _patch_http(monkeypatch, handler)
    findings = []
    scan.check_gravatar("j@x.com", findings)
    assert findings[0]["severity"] == "medium"
    assert "twitter.com/jane" in findings[0]["detail"]


def test_check_hudsonrock_hit_is_high(monkeypatch):
    body = json.dumps({"stealers": [{"credentials": [{"url": "netflix.com"}]}]})
    _patch_http(monkeypatch, lambda url: (200, body))
    findings = []
    scan.check_hudsonrock("j@x.com", findings)
    assert findings[0]["severity"] == "high"
    assert "netflix.com" in findings[0]["detail"]


def test_check_hudsonrock_clear(monkeypatch):
    _patch_http(monkeypatch, lambda url: (200, json.dumps({"stealers": []})))
    findings = []
    scan.check_hudsonrock("j@x.com", findings)
    assert findings[0]["severity"] == "clear"


def test_check_github_exposed(monkeypatch):
    def handler(url):
        if "search/users" in url:
            return 200, json.dumps({"items": [{"login": "janep"}]})
        if "search/commits" in url:
            return 200, json.dumps({"total_count": 42})
        return 0, ""

    _patch_http(monkeypatch, handler)
    findings = []
    scan.check_github("j@x.com", findings)
    assert findings[0]["severity"] == "medium"
    assert "janep" in findings[0]["detail"]


def test_check_github_clear(monkeypatch):
    def handler(url):
        if "search/users" in url:
            return 200, json.dumps({"items": []})
        return 200, json.dumps({"total_count": 0})

    _patch_http(monkeypatch, handler)
    findings = []
    scan.check_github("j@x.com", findings)
    assert findings[0]["severity"] == "clear"


def _fake_run_factory(stdout="", returncode=0):
    def fake_run(cmd, **kwargs):
        return types.SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)

    return fake_run


def test_check_holehe_found(monkeypatch):
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        _fake_run_factory("[+] twitter.com\n[+] spotify.com\n[-] nope.com\n"),
    )
    findings = []
    scan.check_holehe("j@x.com", findings)
    assert findings[0]["severity"] == "medium"
    assert "twitter.com" in findings[0]["detail"]
    assert "spotify.com" in findings[0]["detail"]
    assert "nope.com" not in findings[0]["detail"]


def test_check_holehe_clear(monkeypatch):
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)
    monkeypatch.setattr(scan.subprocess, "run", _fake_run_factory(""))
    findings = []
    scan.check_holehe("j@x.com", findings)
    assert findings[0]["severity"] == "clear"


def test_check_sherlock_found(monkeypatch, tmp_path):
    def fake_run(cmd, **kwargs):
        # emulate sherlock writing its results file
        (tmp_path / "janep.txt").write_text(
            "https://github.com/janep\nhttps://reddit.com/u/janep\n", encoding="utf-8"
        )
        return types.SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(scan.shutil, "which", lambda name: None)
    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    findings = []
    scan.check_sherlock("janep", findings, tmp_path)
    assert findings[0]["severity"] == "medium"
    assert findings[0]["sites"] == ["https://github.com/janep", "https://reddit.com/u/janep"]


# ── end-to-end orchestration (fully mocked) ───────────────────────────────────


@pytest.fixture
def mocked_world(monkeypatch):
    def handler(url):
        if "gravatar" in url:
            return 404, ""
        if "hudsonrock" in url and "email" in url:
            return 200, json.dumps({"stealers": [{"credentials": [{"url": "bank.com"}]}]})
        if "search/users" in url:
            return 200, json.dumps({"items": []})
        if "search/commits" in url:
            return 200, json.dumps({"total_count": 0})
        return 200, "{}"

    monkeypatch.setattr(scan, "http_get", lambda url, headers=None, timeout=15: handler(url))
    monkeypatch.setattr(scan.shutil, "which", lambda name: None)
    monkeypatch.setattr(scan.subprocess, "run", _fake_run_factory(""))


def test_run_scan_schema_and_sorting(mocked_world):
    identity = {
        "full_name": "Jane Public",
        "emails": ["j@x.com"],
        "usernames": ["janep"],
        "cities": ["Portland"],
        "state": "OR",
    }
    result = scan.run_scan(identity, do_sherlock=False)

    assert set(result) == {
        "scanned_at",
        "identity_summary",
        "stats",
        "findings",
        "brokers",
        "dorks",
    }
    assert result["identity_summary"]["configured"] is True

    # a high-severity stealer hit must be present and sorted first
    assert result["stats"].get("high", 0) >= 1
    order = {"high": 0, "medium": 1, "low": 2, "info": 3, "clear": 4}
    sev_values = [order[f["severity"]] for f in result["findings"]]
    assert sev_values == sorted(sev_values), "findings must be sorted by severity"

    assert result["brokers"], "brokers should be populated"
    assert result["dorks"], "dorks should be populated"


def test_run_scan_unconfigured_identity_is_empty(mocked_world):
    result = scan.run_scan({}, do_sherlock=False)
    assert result["identity_summary"]["configured"] is False
    assert result["findings"] == []
