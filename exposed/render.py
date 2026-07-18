"""Beautiful terminal rendering for scan results, powered by `rich`."""

from rich.box import HEAVY, ROUNDED
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# severity -> (label, badge style, accent style, icon)
SEV = {
    "high": ("HIGH", "bold white on red3", "red3", "●"),
    "medium": ("MEDIUM", "bold black on gold1", "gold1", "●"),
    "low": ("LOW", "bold black on deep_sky_blue1", "deep_sky_blue1", "●"),
    "info": ("INFO", "bold black on grey62", "grey62", "○"),
    "clear": ("CLEAR", "bold black on green3", "green3", "✓"),
}
SEV_ORDER = ["high", "medium", "low", "info", "clear"]


def _badge(sev):
    label, style, _, _ = SEV.get(sev, (sev.upper(), "white", "white", "•"))
    return Text(f" {label} ", style=style)


def _header(result):
    ident = result["identity_summary"]
    title = Text("  exposed  ", style="bold white on dark_magenta")
    subtitle = Text("your personal data, as the internet sees it", style="italic grey70")

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="grey58", justify="right")
    meta.add_column(style="bold white")
    meta.add_row("identity", ident.get("name") or "(not set)")
    if ident.get("emails"):
        meta.add_row("emails", ", ".join(ident["emails"]))
    if ident.get("usernames"):
        meta.add_row("usernames", ", ".join("@" + u for u in ident["usernames"]))
    if ident.get("location"):
        meta.add_row("location", ident["location"])

    return Panel(
        Group(subtitle, Text(""), meta),
        title=title,
        title_align="left",
        border_style="dark_magenta",
        box=HEAVY,
        padding=(1, 2),
    )


def _risk_bar(stats):
    bar = Text()
    for sev in SEV_ORDER:
        n = stats.get(sev, 0)
        label, style, accent, icon = SEV[sev]
        bar.append(f" {icon} {n} {label.lower()} ", style=f"bold {accent}")
        bar.append("  ")
    return Padding(bar, (0, 1))


def _finding(f):
    _, _, accent, _ = SEV.get(f["severity"], ("", "", "white", ""))
    head = Text()
    head.append_text(_badge(f["severity"]))
    head.append("  ")
    head.append(f["title"], style=f"bold {accent}")

    lines = [head]
    if f.get("detail"):
        lines.append(Padding(Text(f["detail"], style="grey74"), (0, 0, 0, 9)))
    if f.get("action"):
        act = Text()
        act.append("→ ", style="bold green3")
        act.append(f["action"], style="green3")
        lines.append(Padding(act, (0, 0, 0, 9)))
    return Group(*lines)


def render(result, console: Console):
    stats = result["stats"]
    findings = result["findings"]

    console.print()
    console.print(_header(result))
    console.print()
    console.print(_risk_bar(stats))
    console.print()

    # Actionable findings first (everything that isn't "clear"), then a clear roll-up.
    actionable = [f for f in findings if f["severity"] != "clear"]
    clear = [f for f in findings if f["severity"] == "clear"]

    for f in actionable:
        console.print(_finding(f))
        console.print()

    if clear:
        ok = Text()
        ok.append_text(_badge("clear"))
        ok.append(f"  {len(clear)} source(s) came back clean", style="green3")
        console.print(ok)
        console.print()

    footer = Table.grid(padding=(0, 3))
    footer.add_column(justify="left", style="bold white")
    footer.add_column(justify="left", style="grey70")
    footer.add_row(f"{len(result['brokers'])}", "data-broker opt-out links ready")
    footer.add_row(f"{len(result['dorks'])}", "search dorks generated")
    console.print(
        Panel(
            footer,
            title=Text(" next: remove yourself ", style="bold black on green3"),
            title_align="left",
            border_style="green3",
            box=ROUNDED,
            padding=(1, 2),
        )
    )
