"""
formatter.py — render HashCandidate lists as rich terminal tables or JSON.
"""

from __future__ import annotations

import json as _json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HashCandidate

try:
    from rich.table import Table
    from rich.console import Console
    from rich.text import Text
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False


# ---------------------------------------------------------------------------
# Confidence styling
# ---------------------------------------------------------------------------

_CONF_STYLE = {
    "high":   ("bright_green",  "●"),
    "medium": ("yellow",        "◐"),
    "low":    ("dim white",     "○"),
}

_CONF_PLAIN = {
    "high":   "[HIGH  ]",
    "medium": "[MED   ]",
    "low":    "[LOW   ]",
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def format_table(candidates: list["HashCandidate"], input_str: str = "") -> None:
    """Print a rich-rendered table to stdout (falls back to plain text)."""
    if _RICH:
        _print_rich(candidates, input_str)
    else:
        _print_plain(candidates, input_str)


def format_json(candidates: list["HashCandidate"], input_str: str = "") -> str:
    """Return a JSON string representation of the results."""
    data = {
        "input_length": len(input_str),
        "candidates": [
            {
                "rank": i + 1,
                "name": c.name,
                "confidence": c.confidence,
                "reason": c.reason,
                "format_class": c.format_class,
                "bit_length": c.bit_length or None,
                "extra": c.extra or None,
            }
            for i, c in enumerate(candidates)
        ],
    }
    return _json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Rich renderer
# ---------------------------------------------------------------------------

def _print_rich(candidates: list["HashCandidate"], input_str: str, no_color: bool = False) -> None:
    # Tell rich to output plain text if no_color is True
    console = Console(color_system=None if no_color else "auto")
    

    # Header panel
    console.print()
    console.rule("[bold]Hash Identifier[/bold]", style="dim")
    if input_str:
        preview = input_str[:72] + ("…" if len(input_str) > 72 else "")
        console.print(f"  [dim]Input:[/dim]  [bold cyan]{preview}[/bold cyan]")
        console.print(f"  [dim]Length:[/dim] [bold]{len(input_str)}[/bold] chars")
    console.print()

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold",
        expand=False,
        padding=(0, 1),
    )
    table.add_column("#",          style="dim",        width=3,  justify="right")
    table.add_column("Hash / Format",                  min_width=30)
    table.add_column("Confidence",                     width=12)
    table.add_column("Format class",                   width=12)
    table.add_column("Reason",     style="dim",        min_width=30)

    for i, c in enumerate(candidates):
        style, dot = _CONF_STYLE.get(c.confidence, ("white", "?"))
        conf_text = Text(f"{dot} {c.confidence}", style=style)

        bits = f" [dim]({c.bit_length} bit)[/dim]" if c.bit_length else ""
        name_text = Text.from_markup(f"[bold]{c.name}[/bold]{bits}")

        table.add_row(
            str(i + 1),
            name_text,
            conf_text,
            c.format_class or "—",
            c.reason,
        )

    console.print(table)

    top = candidates[0] if candidates else None
    if top and top.confidence == "high":
        console.print(f"  [bold green]→ Most likely:[/bold green] [cyan]{top.name}[/cyan]")
    console.print()


# ---------------------------------------------------------------------------
# Plain-text fallback
# ---------------------------------------------------------------------------

def _print_plain(candidates: list["HashCandidate"], input_str: str) -> None:
    SEP = "-" * 72
    print()
    print("  Hash Identifier")
    print(SEP)
    if input_str:
        preview = input_str[:68] + ("…" if len(input_str) > 68 else "")
        print(f"  Input  : {preview}")
        print(f"  Length : {len(input_str)} chars")
    print(SEP)
    print(f"  {'#':<3} {'Confidence':<10} {'Format class':<14} Hash / Format")
    print(SEP)
    for i, c in enumerate(candidates):
        tag = _CONF_PLAIN.get(c.confidence, "[?????]")
        print(f"  {i+1:<3} {tag:<10} {(c.format_class or '—'):<14} {c.name}")
        print(f"      {'':10} {'':14} {c.reason}")
        print()
    print(SEP)
    print()
