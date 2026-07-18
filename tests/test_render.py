"""Smoke test for the rich renderer — asserts it produces output without error."""

import io

from rich.console import Console

from exposed.render import render

RESULT = {
    "identity_summary": {
        "name": "Jane Public",
        "emails": ["j@x.com"],
        "usernames": ["janep"],
        "location": "Portland, OR",
        "configured": True,
    },
    "stats": {"high": 1, "clear": 1},
    "findings": [
        {
            "source": "HudsonRock",
            "severity": "high",
            "title": "stealer hit",
            "detail": "bad",
            "action": "rotate passwords",
        },
        {"source": "Gravatar", "severity": "clear", "title": "clean", "detail": "", "action": ""},
    ],
    "brokers": [{"name": "X"}] * 25,
    "dorks": [{"engine": "Google", "label": "Exact name", "url": "https://g"}] * 5,
}


def test_render_produces_output():
    console = Console(file=io.StringIO(), force_terminal=True, width=90, legacy_windows=False)
    render(RESULT, console)
    out = console.file.getvalue()
    assert "exposed" in out
    assert "stealer hit" in out
    assert "rotate passwords" in out
    # the "next: remove yourself" footer with the broker count should render
    assert "25" in out


def test_render_handles_empty_scan():
    console = Console(file=io.StringIO(), force_terminal=True, width=90, legacy_windows=False)
    empty = {
        "identity_summary": {
            "name": "(not set)",
            "emails": [],
            "usernames": [],
            "location": "",
            "configured": False,
        },
        "stats": {},
        "findings": [],
        "brokers": [],
        "dorks": [],
    }
    render(empty, console)  # must not raise
    assert console.file.getvalue()  # produced something
