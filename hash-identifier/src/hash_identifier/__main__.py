#!/usr/bin/env python3
"""
hashid — command-line hash identifier.

Usage examples:
  hashid 5f4dcc3b5aa765d61d8327deb882cf99
  echo "$2b\$12\$..." | hashid -
  hashid --json <hash>
  hashid --top <hash>         # print only the top candidate name (scriptable)
  hashid --exit-code <hash>   # exits 0=high, 1=medium, 2=low, 3=unknown
"""

from __future__ import annotations

import argparse
import sys

from .core import identify
from .formatter import format_table, format_json


_EXIT_CONF = {"high": 0, "medium": 1, "low": 2}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hashid",
        description="Identify hash / encoding formats by prefix, length, and shape.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "hash",
        nargs="?",
        help="Hash string to identify. Pass '-' to read from stdin.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON (machine-readable).",
    )
    p.add_argument(
        "--top",
        action="store_true",
        help="Print only the top candidate name and exit.",
    )
    p.add_argument(
        "--exit-code",
        action="store_true",
        dest="exit_code",
        help="Exit 0=high, 1=medium, 2=low confidence (useful for shell scripting).",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        help="Disable rich color output (plain ASCII table).",
    )
    p.add_argument(
        "--version",
        action="version",
        version="hashid 1.0.0",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Read input
    if args.hash is None:
        if sys.stdin.isatty():
            parser.print_help()
            return 1
        raw = sys.stdin.read()
    elif args.hash == "-":
        raw = sys.stdin.read()
    else:
        raw = args.hash

    raw = raw.strip()
    if not raw:
        print("error: empty input", file=sys.stderr)
        return 3

# Remove the fmt._RICH = False hack
    candidates = identify(raw)
    
    if args.json:
        print(format_json(candidates, raw))
    elif args.top:
        print(candidates[0].name if candidates else "unknown")
    else:
        # Pass the flag directly to the formatter
        if args.no_color:
             # If you want pure ASCII fallback instead of rich's uncolored tables:
             import hash_identifier.formatter as fmt
             fmt._print_plain(candidates, raw)
        else:
             format_table(candidates, raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
