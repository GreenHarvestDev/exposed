"""Command-line interface for `exposed`."""

import argparse
import json
import sys
from pathlib import Path

from .scan import load_json, run_scan

SEV_COLORS = {
    "high": "\033[91m", "medium": "\033[93m", "low": "\033[96m",
    "info": "\033[90m", "clear": "\033[92m",
}
RESET = "\033[0m"


def _c(text, sev, use_color):
    if not use_color:
        return text
    return f"{SEV_COLORS.get(sev, '')}{text}{RESET}"


def print_report(result, use_color=True):
    stats = result["stats"]
    ident = result["identity_summary"]
    print()
    print(f"  Scanned: {ident['name']}  |  {', '.join(ident['emails']) or '(no emails)'}")
    if ident["location"]:
        print(f"  Location: {ident['location']}")
    print()
    order = ["high", "medium", "low", "info", "clear"]
    for f in result["findings"]:
        tag = f["severity"].upper().ljust(6)
        print(_c(f"  [{tag}] {f['title']}", f["severity"], use_color))
        if f.get("detail"):
            print(f"          {f['detail']}")
        if f.get("action"):
            print(f"          → {f['action']}")
        print()
    summary = "  ".join(
        _c(f"{s}={stats.get(s, 0)}", s, use_color) for s in order
    )
    print(f"  {len(result['findings'])} findings   {summary}")
    print(f"  {len(result['brokers'])} data-broker opt-out targets ready")
    print(f"  {len(result['dorks'])} search dorks generated")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="exposed",
        description="Scan free public sources for your exposed personal data, "
                    "then get opt-out links to remove it.")
    ap.add_argument("--identity", "-i", default="exposed_identity.json",
                    help="Path to your identity JSON (default: ./exposed_identity.json)")
    ap.add_argument("--out", "-o", default="exposed_report.json",
                    help="Where to write the full JSON report (default: ./exposed_report.json)")
    ap.add_argument("--no-sherlock", action="store_true",
                    help="Skip the slow username sweep")
    ap.add_argument("--json", action="store_true",
                    help="Print the full report JSON to stdout instead of the readable summary")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = ap.parse_args(argv)

    identity_path = Path(args.identity)
    if not identity_path.exists():
        print(f"error: identity file not found: {identity_path}", file=sys.stderr)
        print("Copy exposed_identity.example.json to exposed_identity.json and fill it in.",
              file=sys.stderr)
        return 2
    identity = load_json(identity_path, None)
    if not identity:
        print(f"error: could not parse {identity_path} as JSON", file=sys.stderr)
        return 2

    use_color = not args.no_color and sys.stdout.isatty()
    result = run_scan(
        identity,
        do_sherlock=not args.no_sherlock,
        progress=lambda m: print(f"  [*] {m}", file=sys.stderr),
    )

    Path(args.out).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_report(result, use_color=use_color)
        print(f"\n  Full report saved → {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
