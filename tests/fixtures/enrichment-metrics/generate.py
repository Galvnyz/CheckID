#!/usr/bin/env python3
"""Generate fixture registries for enrichment-metrics tests.

Run from repo root:
    python tests/fixtures/enrichment-metrics/generate.py

Outputs in tests/fixtures/enrichment-metrics/:
    sparse.json    — N=10 checks; 5 enriched (rationale + impact + 2 refs), 5 empty.
                     All mapped to fw-a; the 5 enriched also mapped to fw-b.
    enriched.json  — Same N=10 checks, but ALL have rationale + impact + 2 refs.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def make_check(idx: int, enriched: bool, in_fw_b: bool) -> dict:
    base: dict = {
        "checkId": f"TEST-{idx:03d}",
        "frameworks": {"fw-a": {"controlId": "X"}},
    }
    if in_fw_b:
        base["frameworks"]["fw-b"] = {"controlId": "Y"}
    if enriched:
        base["rationale"] = "Why this control matters."
        base["impact"] = "What an attacker sees on failure."
        base["references"] = [
            {"url": "https://learn.microsoft.com/example", "title": "Example doc 1"},
            {"url": "https://learn.microsoft.com/another", "title": "Example doc 2"},
        ]
    return base


def write(name: str, data: dict) -> None:
    out = HERE / f"{name}.json"
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")


def main() -> None:
    # sparse: 5 enriched, 5 empty; the 5 enriched are also in fw-b
    sparse_checks = [
        make_check(i, enriched=(i <= 5), in_fw_b=(i <= 5))
        for i in range(1, 11)
    ]
    write(
        "sparse",
        {
            "schemaVersion": "test-fixture",
            "checks": sparse_checks,
        },
    )

    # enriched: ALL 10 enriched; same fw-b membership pattern as sparse so deltas
    # cleanly attribute to enrichment changes only (not membership changes).
    enriched_checks = [
        make_check(i, enriched=True, in_fw_b=(i <= 5))
        for i in range(1, 11)
    ]
    write(
        "enriched",
        {
            "schemaVersion": "test-fixture",
            "checks": enriched_checks,
        },
    )


if __name__ == "__main__":
    main()
