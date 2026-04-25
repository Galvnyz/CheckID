#!/usr/bin/env python3
"""Compute rationale / impact / references population metrics for the registry.

Informational tool. **Always exits 0** — this is a metric, not a gate.
The hard release-gate for Critical/High enrichment lives in v3.2 (issue
#281); this script's job is to surface trends on every PR so progress
is visible without blocking routine work.

Usage:
    Snapshot:    python scripts/Compute-EnrichmentMetrics.py <registry>
    Comparison:  python scripts/Compute-EnrichmentMetrics.py <main> <head>

Options:
    --markdown PATH   Also write a sticky-comment-friendly markdown table.

The markdown output uses a stable HTML marker (`<!-- enrichment-metrics -->`)
so a CI step can update one comment in place rather than spam new ones.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

STICKY_MARKER = "<!-- enrichment-metrics -->"
ENRICHMENT_FIELDS = ("rationale", "impact", "references")


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _populated(check: dict, field: str) -> bool:
    val = check.get(field)
    if field == "references":
        return bool(val)  # truthy list
    return bool((val or "").strip())


def overall(registry: dict) -> dict[str, int]:
    out = {"total": 0, "rationale": 0, "impact": 0, "references": 0}
    for c in registry.get("checks", []):
        out["total"] += 1
        for f in ENRICHMENT_FIELDS:
            if _populated(c, f):
                out[f] += 1
    return out


def per_framework(registry: dict) -> dict[str, dict[str, int]]:
    by_fw: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "rationale": 0, "impact": 0, "references": 0}
    )
    for c in registry.get("checks", []):
        flags = {f: _populated(c, f) for f in ENRICHMENT_FIELDS}
        for fw in c.get("frameworks", {}):
            row = by_fw[fw]
            row["total"] += 1
            for f in ENRICHMENT_FIELDS:
                if flags[f]:
                    row[f] += 1
    return dict(by_fw)


def pct(numer: int, denom: int) -> float:
    return (numer / denom * 100.0) if denom else 0.0


def fmt_cell(numer: int, denom: int, delta_pp: float | None) -> str:
    """Render one table cell: 'X.X% (n/d)' plus optional ' (Δ+P.Pp)'."""
    p = pct(numer, denom)
    s = f"{p:.1f}% ({numer}/{denom})"
    if delta_pp is not None and abs(delta_pp) >= 0.05:
        sign = "+" if delta_pp > 0 else ""
        s += f" ({sign}{delta_pp:.1f}pp)"
    return s


def render_console(
    head_overall: dict,
    head_per_fw: dict,
    main_overall: dict | None = None,
    main_per_fw: dict | None = None,
) -> str:
    lines = []
    lines.append("Enrichment metrics (rationale / impact / references)")
    lines.append("")

    def row(label: str, numer_key_pairs: list[tuple[int, int]]) -> str:
        cells = []
        for n, d in numer_key_pairs:
            cells.append(f"{pct(n, d):>5.1f}% ({n}/{d})")
        return f"  {label:<24} " + "  ".join(cells)

    lines.append(f"{'':26}  rationale         impact            references")
    lines.append(row("(overall)", [
        (head_overall["rationale"], head_overall["total"]),
        (head_overall["impact"], head_overall["total"]),
        (head_overall["references"], head_overall["total"]),
    ]))

    for fw in sorted(head_per_fw):
        r = head_per_fw[fw]
        lines.append(row(fw, [
            (r["rationale"], r["total"]),
            (r["impact"], r["total"]),
            (r["references"], r["total"]),
        ]))

    if main_overall is not None:
        lines.append("")
        lines.append("(comparison vs main: see --markdown output for delta detail)")
    return "\n".join(lines)


def _delta_pp(head: dict, main: dict, field: str) -> float:
    return pct(head[field], head["total"]) - pct(main.get(field, 0), main.get("total", 0))


def render_markdown(
    head_overall: dict,
    head_per_fw: dict,
    main_overall: dict | None = None,
    main_per_fw: dict | None = None,
) -> str:
    has_main = main_overall is not None
    lines: list[str] = [STICKY_MARKER, "", "## Content enrichment population", ""]

    # Headline row
    if has_main:
        d_r = _delta_pp(head_overall, main_overall, "rationale")
        d_i = _delta_pp(head_overall, main_overall, "impact")
        d_f = _delta_pp(head_overall, main_overall, "references")
        lines.append(
            f"**Overall ({head_overall['total']} checks):** "
            f"rationale {fmt_cell(head_overall['rationale'], head_overall['total'], d_r)} • "
            f"impact {fmt_cell(head_overall['impact'], head_overall['total'], d_i)} • "
            f"references {fmt_cell(head_overall['references'], head_overall['total'], d_f)}"
        )
    else:
        lines.append(
            f"**Overall ({head_overall['total']} checks):** "
            f"rationale {fmt_cell(head_overall['rationale'], head_overall['total'], None)} • "
            f"impact {fmt_cell(head_overall['impact'], head_overall['total'], None)} • "
            f"references {fmt_cell(head_overall['references'], head_overall['total'], None)}"
        )
    lines.append("")

    lines.append("| Framework | n | rationale | impact | references |")
    lines.append("|---|---:|---:|---:|---:|")
    for fw in sorted(head_per_fw):
        head_row = head_per_fw[fw]
        main_row = (main_per_fw or {}).get(fw)
        d_r = _delta_pp(head_row, main_row, "rationale") if main_row else None
        d_i = _delta_pp(head_row, main_row, "impact") if main_row else None
        d_f = _delta_pp(head_row, main_row, "references") if main_row else None
        lines.append(
            f"| `{fw}` | {head_row['total']} | "
            f"{fmt_cell(head_row['rationale'], head_row['total'], d_r)} | "
            f"{fmt_cell(head_row['impact'], head_row['total'], d_i)} | "
            f"{fmt_cell(head_row['references'], head_row['total'], d_f)} |"
        )
    lines.append("")
    lines.append("_Informational only — does not gate the build. The hard release-gate for "
                 "Critical/High enrichment lives in #281 (v3.2.0)._")
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="+", type=Path, help="<head> for snapshot, or <main> <head> for comparison")
    p.add_argument("--markdown", type=Path, default=None)
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if len(args.paths) == 1:
        head = load(args.paths[0])
        main_reg = None
    elif len(args.paths) == 2:
        main_reg = load(args.paths[0])
        head = load(args.paths[1])
    else:
        print("::error::expected 1 (snapshot) or 2 (comparison) registry paths", file=sys.stderr)
        # Still exit 0 — script is non-blocking by contract.
        return 0

    head_overall = overall(head)
    head_per_fw = per_framework(head)
    main_overall = overall(main_reg) if main_reg is not None else None
    main_per_fw = per_framework(main_reg) if main_reg is not None else None

    print(render_console(head_overall, head_per_fw, main_overall, main_per_fw))

    if args.markdown is not None:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(
            render_markdown(head_overall, head_per_fw, main_overall, main_per_fw),
            encoding="utf-8",
        )
        print(f"\nMarkdown written to {args.markdown}", file=sys.stderr)

    return 0  # Always 0 — informational only.


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
