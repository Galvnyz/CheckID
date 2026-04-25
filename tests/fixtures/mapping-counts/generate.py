#!/usr/bin/env python3
"""Generate fixture registries for mapping-count regression tests.

Run from repo root:
    python tests/fixtures/mapping-counts/generate.py

Outputs four files in tests/fixtures/mapping-counts/:
    baseline.json         — 100 checks, each mapped to {fw-a, fw-b, fw-c, fw-d, fw-e}
    drop-1pct.json        — 1 check loses fw-e (99/100, under 2% threshold)
    drop-5pct.json        — 5 checks lose fw-e (95/100, over 2% threshold)
    framework-added.json  — every check gains fw-f (100/100, additive change)
"""

from __future__ import annotations

import json
from pathlib import Path

N = 100
HERE = Path(__file__).resolve().parent


def base() -> dict:
    return {
        "schemaVersion": "test-fixture",
        "checks": [
            {
                "checkId": f"TEST-{i:03d}",
                "frameworks": {
                    "fw-a": {"controlId": "X"},
                    "fw-b": {"controlId": "X"},
                    "fw-c": {"controlId": "X"},
                    "fw-d": {"controlId": "X"},
                    "fw-e": {"controlId": "X"},
                },
            }
            for i in range(1, N + 1)
        ],
    }


def write(name: str, data: dict) -> None:
    out = HERE / f"{name}.json"
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")


def main() -> None:
    baseline = base()
    write("baseline", baseline)

    drop_1pct = base()
    drop_1pct["checks"][0]["frameworks"].pop("fw-e")
    write("drop-1pct", drop_1pct)

    drop_5pct = base()
    for i in range(5):
        drop_5pct["checks"][i]["frameworks"].pop("fw-e")
    write("drop-5pct", drop_5pct)

    framework_added = base()
    for c in framework_added["checks"]:
        c["frameworks"]["fw-f"] = {"controlId": "X"}
    write("framework-added", framework_added)


if __name__ == "__main__":
    main()
