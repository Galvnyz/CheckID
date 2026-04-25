#!/usr/bin/env python3
"""Compare per-framework mapping counts between two registry snapshots.

Catches the v2.22.0 AZ-enrichment-class bug where a build path silently
dropped ~400 framework mappings across 26 AZ-* checks. CI does not have
to re-run the full build to detect such loss — it just compares the
committed registry on the PR head against the committed registry on
main.

Usage:
    python scripts/Compare-MappingCounts.py <main> <head> [options]

Options:
    --threshold-pct N    Fail when any framework drops more than N%. Default 2.0.
    --allow-drop FW      Whitelist a framework that may drop without failing.
                         Repeatable. Used for intentional removals.
    --markdown PATH      Write a sticky-comment-friendly markdown table to PATH.

Exit 0 — no regressions (or all regressions whitelisted).
Exit 1 — at least one un-whitelisted regression beyond the threshold.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

STICKY_MARKER = "<!-- mapping-count-delta -->"


def load_registry(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def count_mappings(registry: dict) -> dict[str, int]:
    """Return {framework_id: count_of_checks_with_that_mapping}."""
    counts: dict[str, int] = defaultdict(int)
    for check in registry.get("checks", []):
        for fw in check.get("frameworks", {}):
            counts[fw] += 1
    return dict(counts)


def compare(
    main_counts: dict[str, int],
    head_counts: dict[str, int],
    threshold_pct: float,
    allow_drops: set[str],
) -> tuple[list[dict], list[dict]]:
    """Return (regressions, all_rows). Each row has framework, main, head, delta, delta_pct, status."""
    all_frameworks = sorted(set(main_counts) | set(head_counts))
    rows: list[dict] = []
    regressions: list[dict] = []

    for fw in all_frameworks:
        m = main_counts.get(fw, 0)
        h = head_counts.get(fw, 0)
        if m == 0 and h == 0:
            continue
        delta = h - m
        delta_pct = (delta / m * 100.0) if m > 0 else float("inf")

        is_regression = (
            m > 0
            and delta < 0
            and abs(delta_pct) > threshold_pct
            and fw not in allow_drops
        )
        is_waived = (
            m > 0
            and delta < 0
            and abs(delta_pct) > threshold_pct
            and fw in allow_drops
        )

        if delta == 0:
            status = "OK"
        elif is_regression:
            status = "FAIL"
        elif is_waived:
            status = "WAIVED"
        elif delta < 0:
            status = "DROP"  # below threshold, informational
        elif m == 0:
            status = "ADDED"
        else:
            status = "GROWN"

        row = {
            "framework": fw,
            "main": m,
            "head": h,
            "delta": delta,
            "delta_pct": delta_pct,
            "status": status,
        }
        rows.append(row)
        if is_regression:
            regressions.append(row)

    return regressions, rows


def render_console(rows: list[dict], threshold_pct: float) -> str:
    if not rows:
        return "No frameworks with mappings in either snapshot."
    fw_w = max(len("Framework"), max(len(r["framework"]) for r in rows))
    out = []
    out.append(f"{'Framework':<{fw_w}}  {'main':>6}  {'head':>6}  {'diff':>6}  {'diff%':>8}  Status")
    out.append("-" * (fw_w + 42))
    for r in rows:
        pct = "    +inf" if r["delta_pct"] == float("inf") else f"{r['delta_pct']:+7.2f}%"
        out.append(
            f"{r['framework']:<{fw_w}}  {r['main']:>6}  {r['head']:>6}  "
            f"{r['delta']:>+6}  {pct:>8}  {r['status']}"
        )
    out.append("")
    out.append(f"(threshold: drops greater than {threshold_pct}% fail unless waived)")
    return "\n".join(out)


def render_markdown(
    rows: list[dict],
    regressions: list[dict],
    threshold_pct: float,
    allow_drops: set[str],
) -> str:
    lines: list[str] = [STICKY_MARKER, "", "## Framework mapping count delta", ""]

    if not rows:
        lines.append("_No mapping changes detected._")
        return "\n".join(lines) + "\n"

    lines.append("| Framework | main | this PR | Δ | Δ% | Status |")
    lines.append("|---|---:|---:|---:|---:|:--:|")
    icon = {
        "OK": "✓",
        "FAIL": "❌",
        "WAIVED": "⚠️",
        "DROP": "⚠️",
        "ADDED": "✨",
        "GROWN": "✓",
    }
    for r in rows:
        pct = "—" if r["delta_pct"] == float("inf") else f"{r['delta_pct']:+.2f}%"
        delta = f"{r['delta']:+d}" if r["delta"] != 0 else "0"
        lines.append(
            f"| `{r['framework']}` | {r['main']} | {r['head']} | "
            f"{delta} | {pct} | {icon.get(r['status'], '?')} {r['status']} |"
        )
    lines.append("")

    if regressions:
        names = ", ".join(f"`{r['framework']}`" for r in regressions)
        lines.append(
            f"**Result:** ❌ FAIL — regression in {names} exceeds the {threshold_pct}% threshold."
        )
        lines.append("")
        lines.append(
            f"Override by adding a label of the form `ALLOW_MAPPING_DROP=<framework>` to this PR."
        )
    elif allow_drops:
        waived = ", ".join(f"`{fw}`" for fw in sorted(allow_drops))
        lines.append(
            f"**Result:** ⚠️ PASS — drops in {waived} were waived via `ALLOW_MAPPING_DROP` label(s)."
        )
    else:
        lines.append("**Result:** ✓ PASS — no framework mapping regressions detected.")

    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("main", type=Path, help="path to main/baseline registry.json")
    p.add_argument("head", type=Path, help="path to head/PR registry.json")
    p.add_argument("--threshold-pct", type=float, default=2.0)
    p.add_argument("--allow-drop", action="append", default=[], metavar="FW")
    p.add_argument("--markdown", type=Path, default=None)
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    main_reg = load_registry(args.main)
    head_reg = load_registry(args.head)

    main_counts = count_mappings(main_reg)
    head_counts = count_mappings(head_reg)

    allow_drops = set(args.allow_drop)
    regressions, rows = compare(main_counts, head_counts, args.threshold_pct, allow_drops)

    print(render_console(rows, args.threshold_pct))

    if args.markdown is not None:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(
            render_markdown(rows, regressions, args.threshold_pct, allow_drops),
            encoding="utf-8",
        )
        print(f"\nMarkdown delta written to {args.markdown}", file=sys.stderr)

    if regressions:
        for r in regressions:
            print(
                f"::error::Framework '{r['framework']}' dropped {abs(r['delta'])} "
                f"mappings ({r['delta_pct']:+.2f}%, threshold {args.threshold_pct}%). "
                f"Add label 'ALLOW_MAPPING_DROP={r['framework']}' if intentional.",
                file=sys.stderr,
            )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
