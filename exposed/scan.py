"""
exposed — personal OSINT self-exposure scan.

Scans FREE, no-account, no-API-key public sources to show what of YOUR
personal information is exposed online, so you can go remove it.

Sources (all no-signup):
  - Gravatar    : is your email tied to a public profile (name/photo/linked accounts)?
  - HudsonRock  : does your email/username appear in infostealer-malware logs?
  - GitHub      : is your email leaking through public commits / linked to a user?
  - holehe      : which sites have an account registered to your email?
  - Sherlock    : which sites have an account under your username?
  - Data brokers: resolved deep-links to find + opt out of each people-search site.
  - Search dorks: pre-built Google/DuckDuckGo queries to eyeball remaining exposure.

Nothing is hardcoded — identity is read from a JSON file you control.

Severity contract used throughout:
  high/medium/low : something exposed, worth acting on.
  clear           : the source was reached and found nothing.
  info            : the check could NOT be completed (unreachable, rate-limited,
                    tool missing). NEVER reported as "clear" — a failed check must
                    not be mistaken for a clean result.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

DATA_DIR = Path(__file__).resolve().parent
BROKERS_FILE = DATA_DIR / "brokers.json"

UA = "Mozilla/5.0 (exposed OSINT self-scan; personal privacy audit)"
socket.setdefaulttimeout(15)


class Finding(TypedDict, total=False):
    """One line item in a scan report."""

    source: str
    severity: str  # high | medium | low | info | clear
    title: str
    detail: str
    action: str
    url: str
    sites: list[str]


Identity = dict[str, Any]
ScanResult = dict[str, Any]


def http_get(url: str, headers: dict[str, str] | None = None, timeout: int = 15) -> tuple[int, str]:
    """Return (status_code, text). Never raises. status_code is 0 on network error."""
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception as e:
        return 0, f"[error: {e}]"


def http_failed(status: int) -> bool:
    """True when a non-200 status means the check could NOT be completed
    (vs. a legitimate 'nothing found'). 0=network error, 403/429=blocked/rate-limited,
    5xx=server error. A 404 is intentionally NOT a failure — some checks use it to
    mean 'no record'."""
    return status == 0 or status in (403, 429) or status >= 500


def load_json(path: str | Path, default: Any) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def name_parts(identity: Identity) -> tuple[str, str, str]:
    full = (identity.get("full_name") or "").strip()
    if full:
        bits = full.split()
        return bits[0], bits[-1], full
    for u in identity.get("usernames", []):
        if u:
            return u, "", u
    return "", "", ""


def fill_tokens(
    url: str,
    first: str,
    last: str,
    city: str,
    state: str,
    email: str,
    phone: str,
    full: str,
) -> str:
    slug = re.sub(r"\s+", "-", full.strip().lower()) if full else ""
    return (
        url.replace("{first}", urllib.parse.quote(first))
        .replace("{last}", urllib.parse.quote(last))
        .replace("{name}", urllib.parse.quote(full))
        .replace("{name_slug}", urllib.parse.quote(slug))
        .replace("{city}", urllib.parse.quote(city))
        .replace("{state}", urllib.parse.quote(state))
        .replace("{email}", urllib.parse.quote(email))
        .replace("{phone}", urllib.parse.quote(phone))
    )


def _info(source: str, title: str, detail: str, action: str = "") -> Finding:
    """Build a 'check could not be completed' finding — never a false 'clear'."""
    return {
        "source": source,
        "severity": "info",
        "title": title,
        "detail": detail,
        "action": action,
        "url": "",
    }


# ── Individual checks ────────────────────────────────────────────────────────


def check_gravatar(email: str, findings: list[Finding]) -> None:
    h = hashlib.md5(email.strip().lower().encode(), usedforsecurity=False).hexdigest()
    status, _ = http_get(f"https://www.gravatar.com/avatar/{h}?d=404&s=80")
    if http_failed(status):
        findings.append(
            _info(
                "Gravatar",
                f"Gravatar check unavailable for {email}",
                f"Couldn't reach Gravatar (status {status}); this is not a clean result.",
                "Re-run the scan later.",
            )
        )
        return
    if status != 200:  # 404 -> no public avatar
        findings.append(
            {
                "source": "Gravatar",
                "severity": "clear",
                "title": f"No public Gravatar for {email}",
                "detail": "Your email isn't tied to a public Gravatar avatar/profile.",
                "action": "",
                "url": "",
            }
        )
        return
    pstatus, pbody = http_get(f"https://www.gravatar.com/{h}.json")
    detail = "A public Gravatar avatar is linked to this email (leaks a photo + confirms the address is real)."
    linked: list[str] = []
    if pstatus == 200:
        with contextlib.suppress(Exception):
            prof = json.loads(pbody)["entry"][0]
            for a in prof.get("accounts", []):
                if a.get("url"):
                    linked.append(a["url"])
            dn = prof.get("displayName") or prof.get("name", {}).get("formatted")
            if dn:
                detail += f" Public display name: {dn}."
    if linked:
        detail += " Linked accounts exposed: " + ", ".join(linked[:8])
    findings.append(
        {
            "source": "Gravatar",
            "severity": "medium" if linked else "low",
            "title": f"Public Gravatar tied to {email}",
            "detail": detail,
            "action": "Edit or delete the profile at gravatar.com so it doesn't confirm the address or leak linked accounts.",
            "url": "https://gravatar.com/profile",
        }
    )


def check_hudsonrock(email: str, findings: list[Finding]) -> None:
    url = (
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        "search-by-email?email=" + urllib.parse.quote(email)
    )
    status, body = http_get(url, timeout=20)
    if status != 200:
        findings.append(
            _info(
                "HudsonRock",
                f"Stealer-log check unavailable for {email}",
                f"Couldn't reach the free infostealer database (status {status}).",
                "Re-run the scan later.",
            )
        )
        return
    try:
        data = json.loads(body)
    except Exception:
        findings.append(
            _info(
                "HudsonRock",
                f"Stealer-log check unreadable for {email}",
                "The infostealer database returned an unexpected response.",
                "Re-run the scan later.",
            )
        )
        return
    stealers = data.get("stealers") or []
    if not stealers:
        findings.append(
            {
                "source": "HudsonRock",
                "severity": "clear",
                "title": f"{email} not seen in infostealer logs",
                "detail": "This email did not appear in Hudson Rock's free stealer-malware dataset.",
                "action": "",
                "url": "",
            }
        )
        return
    n = len(stealers)
    domains: set[str] = set()
    for s in stealers:
        for c in s.get("credentials") or []:
            if c.get("url"):
                domains.add(c["url"])
    detail = (
        (
            "A device tied to this email was infected by info-stealing malware; saved "
            "logins were harvested. Exposed login domains include: " + ", ".join(list(domains)[:10])
        )
        if domains
        else "A device tied to this email appears in stealer-malware logs."
    )
    findings.append(
        {
            "source": "HudsonRock",
            "severity": "high",
            "title": f"{email} found in infostealer data ({n} infection record(s))",
            "detail": detail,
            "action": "Assume passwords typed on that device are compromised: rotate them, enable 2FA, and run a malware scan.",
            "url": "https://www.hudsonrock.com/free-tools",
        }
    )


def check_github(email: str, findings: list[Finding]) -> None:
    u_status, u_body = http_get(
        "https://api.github.com/search/users?q=" + urllib.parse.quote(f"{email} in:email"),
        headers={"Accept": "application/vnd.github+json"},
    )
    c_status, c_body = http_get(
        "https://api.github.com/search/commits?q=" + urllib.parse.quote(f"author-email:{email}"),
        headers={"Accept": "application/vnd.github.cloak-preview+json"},
    )

    # If neither call succeeded, the check FAILED — do not report a clean result.
    # (Unauthenticated GitHub search is rate-limited to ~10 req/min.)
    if u_status != 200 and c_status != 200:
        findings.append(
            _info(
                "GitHub",
                f"GitHub check incomplete for {email}",
                f"GitHub search did not respond (status {u_status}/{c_status}) — likely rate "
                "limiting. This is NOT a confirmation that your email is private.",
                "Wait a minute and re-run the scan.",
            )
        )
        return

    users: list[str] = []
    if u_status == 200:
        with contextlib.suppress(Exception):
            for it in json.loads(u_body).get("items", []):
                if it.get("login"):
                    users.append(it["login"])
    commit_ct = 0
    if c_status == 200:
        with contextlib.suppress(Exception):
            commit_ct = json.loads(c_body).get("total_count", 0)

    if users or commit_ct:
        parts = []
        if users:
            parts.append("GitHub account(s): " + ", ".join(users[:5]))
        if commit_ct:
            parts.append(f"{commit_ct} public commit(s) publish this email in their metadata")
        findings.append(
            {
                "source": "GitHub",
                "severity": "medium",
                "title": f"{email} is exposed on GitHub",
                "detail": ". ".join(parts) + ".",
                "action": "Enable 'Keep my email private' in GitHub settings and set commit email to the noreply address; scrub old commit history if needed.",
                "url": "https://github.com/settings/emails",
            }
        )
    else:
        findings.append(
            {
                "source": "GitHub",
                "severity": "clear",
                "title": f"{email} not found leaking on GitHub",
                "detail": "No public GitHub user or commit metadata surfaced this email.",
                "action": "",
                "url": "",
            }
        )


def check_sherlock(username: str, findings: list[Finding], tmp_dir: str | Path) -> None:
    exe = shutil.which("sherlock")
    tmp = Path(tmp_dir)
    tmp.mkdir(parents=True, exist_ok=True)
    out = tmp / f"{username}.txt"
    if out.exists():
        with contextlib.suppress(Exception):
            out.unlink()
    base = [exe] if exe else [sys.executable, "-m", "sherlock_project"]
    cmd = [*base, username, "--timeout", "8", "--print-found", "--no-color", "--folder", str(tmp)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=240, encoding="utf-8", errors="replace"
        )
    except Exception as e:
        findings.append(
            _info(
                "Sherlock",
                f"Username sweep skipped for '{username}'",
                f"Sherlock did not run ({e}).",
                "Install it with: pip install 'exposed[full]'",
            )
        )
        return
    sites: list[str] = []
    if out.exists():
        for raw in out.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("http"):
                sites.append(line)
    if sites:
        findings.append(
            {
                "source": "Sherlock",
                "severity": "medium",
                "title": f"'{username}' found on {len(sites)} site(s)",
                "detail": "Accounts under this username reveal your interests, activity, and often real name/photo: "
                + ", ".join(sites[:25])
                + ("…" if len(sites) > 25 else ""),
                "action": "Review each: delete unused accounts, lock down profiles, and stop reusing this handle for anything sensitive.",
                "url": "",
                "sites": sites,
            }
        )
    elif proc.returncode not in (0, None):
        findings.append(
            _info(
                "Sherlock",
                f"Username sweep incomplete for '{username}'",
                f"Sherlock exited with status {proc.returncode} and produced no results — "
                "this is not a clean result.",
                "Re-run the scan.",
            )
        )
    else:
        findings.append(
            {
                "source": "Sherlock",
                "severity": "clear",
                "title": f"No accounts surfaced for '{username}'",
                "detail": "Sherlock found no public accounts under this exact username.",
                "action": "",
                "url": "",
            }
        )


def check_holehe(email: str, findings: list[Finding]) -> None:
    """holehe: which sites have an account registered to this email (no login needed)."""
    exe = shutil.which("holehe")
    base = [exe] if exe else [sys.executable, "-m", "holehe.core"]
    cmd = [*base, "--only-used", "--no-color", email]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=150, encoding="utf-8", errors="replace"
        )
        out = (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        findings.append(
            _info(
                "holehe",
                f"Account-registration sweep skipped for {email}",
                f"holehe did not run ({e}).",
                "Install it with: pip install 'exposed[full]'",
            )
        )
        return
    # holehe marks a hit as "[+] domain.tld". Its legend also prints "[+] Email used",
    # so keep only domain-like tokens (a dot, no spaces) to exclude legend/status text.
    sites = sorted(
        {
            tok
            for line in out.splitlines()
            if (s := line.strip()).startswith("[+]") and (tok := s[3:].strip())
            if " " not in tok and "." in tok
        }
    )
    if sites:
        findings.append(
            {
                "source": "holehe",
                "severity": "medium",
                "title": f"{email} is registered on {len(sites)} site(s)",
                "detail": "These sites confirm an account exists for this email (each one stores your data): "
                + ", ".join(sites),
                "action": "Delete accounts you don't use; for the rest, remove your address/phone from the profile and turn on 2FA.",
                "url": "",
                "sites": sites,
            }
        )
    elif r.returncode not in (0, None) and "[-]" not in out:
        # nonzero exit and not even a single negative line => it didn't really run
        findings.append(
            _info(
                "holehe",
                f"Account-registration sweep incomplete for {email}",
                f"holehe exited with status {r.returncode} without usable output.",
                "Re-run the scan.",
            )
        )
    else:
        findings.append(
            {
                "source": "holehe",
                "severity": "clear",
                "title": f"No account registrations surfaced for {email}",
                "detail": "holehe found no sites confirming an account for this email.",
                "action": "",
                "url": "",
            }
        )


def check_hudson_username(username: str, findings: list[Finding]) -> None:
    url = (
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        "search-by-username?username=" + urllib.parse.quote(username)
    )
    status, body = http_get(url, timeout=20)
    if status != 200:
        return  # supplementary check — stays silent on failure, never claims "clear"
    try:
        stealers = json.loads(body).get("stealers") or []
    except Exception:
        return
    if stealers:
        findings.append(
            {
                "source": "HudsonRock",
                "severity": "high",
                "title": f"Username '{username}' found in infostealer logs ({len(stealers)} record(s))",
                "detail": "This handle appears in stealer-malware logs, meaning a device that used it was infected and its saved logins were harvested.",
                "action": "Rotate every password tied to this handle, enable 2FA, and run a malware scan on your devices.",
                "url": "https://www.hudsonrock.com/free-tools",
            }
        )


# ── Dork + broker link builders ──────────────────────────────────────────────


def get_cities(identity: Identity) -> list[str]:
    c = identity.get("cities")
    if isinstance(c, list) and c:
        return [x for x in c if x]
    one = identity.get("city")
    return [one] if one else []


def build_dorks(identity: Identity, first: str, last: str, full: str) -> list[dict[str, str]]:
    dorks: list[dict[str, str]] = []
    cities = get_cities(identity)
    state = identity.get("state", "")

    def g(q: str, label: str) -> None:
        dorks.append(
            {
                "engine": "Google",
                "label": label,
                "url": "https://www.google.com/search?q=" + urllib.parse.quote(q),
            }
        )

    def d(q: str, label: str) -> None:
        dorks.append(
            {
                "engine": "DuckDuckGo",
                "label": label,
                "url": "https://duckduckgo.com/?q=" + urllib.parse.quote(q),
            }
        )

    if full:
        g(f'"{full}"', "Exact name")
        for city in cities:
            g(f'"{full}" "{city}" "{state}"', f"Name + {city}")
        g(f'"{full}" (email OR phone OR address)', "Name + contact terms")
        g(f'"{full}" (arrest OR lawsuit OR court OR mugshot)', "Name + records")
        g(f'"{full}" site:linkedin.com OR site:facebook.com', "Name on social")
    for a in identity.get("aliases", []):
        if a and full:
            g(f'"{a}" "{last}"', f"Alias: {a}")
    for e in identity.get("emails", []):
        if e:
            g(f'"{e}"', f"Email: {e}")
    for p in identity.get("phones", []):
        if p:
            g(f'"{p}"', f"Phone: {p}")
    for r in identity.get("relatives", []):
        if r and full:
            g(f'"{full}" "{r}"', f"Relative link: {r}")
    for u in identity.get("usernames", []):
        if u:
            d(f'"{u}"', f"Handle: {u}")
    return dorks


def build_brokers(identity: Identity, first: str, last: str, full: str) -> list[dict[str, Any]]:
    brokers = load_json(BROKERS_FILE, {}).get("brokers", [])
    cities = get_cities(identity)
    city = cities[0] if cities else ""
    state = identity.get("state", "")
    email = (identity.get("emails") or [""])[0]
    phone = (identity.get("phones") or [""])[0]
    out: list[dict[str, Any]] = []
    for b in brokers:
        b = dict(b)
        b["search_url"] = fill_tokens(
            b.get("search_url", ""), first, last, city, state, email, phone, full
        )
        b["optout_url"] = fill_tokens(
            b.get("optout_url", ""), first, last, city, state, email, phone, full
        )
        out.append(b)
    return out


def run_scan(
    identity: Identity,
    *,
    do_sherlock: bool = True,
    tmp_dir: str | Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> ScanResult:
    """Run the full scan and return the result dict.

    identity   : dict loaded from the user's identity JSON.
    do_sherlock: run the slow username sweep.
    tmp_dir    : working dir for Sherlock output (default: ./.exposed_tmp).
    progress   : optional callable(str) for status messages.
    """

    def say(msg: str) -> None:
        if progress:
            progress(msg)

    tmp_dir = tmp_dir or (Path.cwd() / ".exposed_tmp")
    first, last, full = name_parts(identity)
    emails = [e for e in identity.get("emails", []) if e]
    usernames = [u for u in identity.get("usernames", []) if u]

    findings: list[Finding] = []
    for email in emails:
        say(f"Gravatar    {email}")
        check_gravatar(email, findings)
        say(f"HudsonRock  {email}")
        check_hudsonrock(email, findings)
        say(f"GitHub      {email}")
        check_github(email, findings)
        say(f"holehe      {email}")
        check_holehe(email, findings)
    for u in usernames:
        say(f"HudsonRock  @{u}")
        check_hudson_username(u, findings)
    if do_sherlock:
        for u in usernames:
            say(f"Sherlock    @{u} (up to ~4 min)")
            check_sherlock(u, findings, tmp_dir)

    dorks = build_dorks(identity, first, last, full)
    brokers = build_brokers(identity, first, last, full)

    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3, "clear": 4}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 9))
    stats: dict[str, int] = {}
    for f in findings:
        stats[f["severity"]] = stats.get(f["severity"], 0) + 1

    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "identity_summary": {
            "name": full or "(not set)",
            "emails": emails,
            "usernames": usernames,
            "location": (", ".join(get_cities(identity)) + f", {identity.get('state', '')}").strip(
                ", "
            ),
            "configured": bool(full and emails),
        },
        "stats": stats,
        "findings": findings,
        "brokers": brokers,
        "dorks": dorks,
    }
