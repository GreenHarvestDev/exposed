"""Generate the README hero image (assets/demo.svg) from a realistic demo report.

Uses a fixed, fictional dataset (no real scan, no network) so the image is
stable and reproducible. Run:  python scripts/make_screenshot.py
"""

import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rich.console import Console  # noqa: E402

from exposed.render import render  # noqa: E402

DEMO = {
    "identity_summary": {
        "name": "Jane Q. Public",
        "emails": ["jane@example.com"],
        "usernames": ["janepublic"],
        "location": "Portland, OR",
        "configured": True,
    },
    "stats": {"high": 1, "medium": 3, "low": 1, "clear": 4},
    "findings": [
        {
            "source": "HudsonRock",
            "severity": "high",
            "title": "jane@example.com found in infostealer data (2 records)",
            "detail": "A device tied to this email was infected by info-stealing "
            "malware; saved logins were harvested. Exposed domains: "
            "netflix.com, paypal.com, coinbase.com.",
            "action": "Assume those passwords are compromised — rotate them, enable 2FA, "
            "and run a malware scan on your devices.",
        },
        {
            "source": "holehe",
            "severity": "medium",
            "title": "jane@example.com is registered on 11 sites",
            "detail": "These sites confirm an account exists for this email: twitter, "
            "spotify, adobe, pinterest, wordpress, imgur, patreon, and more.",
            "action": "Delete accounts you don't use; remove your address/phone from the rest.",
        },
        {
            "source": "Sherlock",
            "severity": "medium",
            "title": "'janepublic' found on 14 sites",
            "detail": "Accounts under this handle reveal your interests, activity, and "
            "often your real name and photo across GitHub, Reddit, Instagram…",
            "action": "Lock down profiles and stop reusing this handle for anything sensitive.",
        },
        {
            "source": "GitHub",
            "severity": "medium",
            "title": "jane@example.com is exposed on GitHub",
            "detail": "GitHub account: janepublic. 340 public commits publish this email "
            "in their metadata.",
            "action": "Enable 'Keep my email private' and set commits to the noreply address.",
        },
        {
            "source": "Gravatar",
            "severity": "low",
            "title": "Public Gravatar tied to jane@example.com",
            "detail": "A public avatar confirms the address is real and leaks a photo.",
            "action": "Edit or delete the profile at gravatar.com.",
        },
        {"source": "HudsonRock", "severity": "clear", "title": "clean", "detail": "", "action": ""},
        {"source": "s2", "severity": "clear", "title": "clean", "detail": "", "action": ""},
        {"source": "s3", "severity": "clear", "title": "clean", "detail": "", "action": ""},
        {"source": "s4", "severity": "clear", "title": "clean", "detail": "", "action": ""},
    ],
    "brokers": [None] * 25,
    "dorks": [None] * 12,
}


def main():
    out = ROOT / "assets" / "demo.svg"
    out.parent.mkdir(exist_ok=True)
    # Render into an in-memory buffer so we never touch the real (legacy) console.
    console = Console(
        record=True, width=92, file=io.StringIO(), force_terminal=True, legacy_windows=False
    )
    render(DEMO, console)
    console.save_svg(str(out), title="exposed")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
