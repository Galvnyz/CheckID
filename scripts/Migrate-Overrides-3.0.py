#!/usr/bin/env python3
"""One-shot migration script for v3.0.0: dissolve override files into source files.

Moves the contents of:
    data/framework-overrides.json
    data/effort-overrides.json
…into per-check inline fields on:
    data/scf-check-mapping.json    (M365 checks)
    data/az-assess-source-checks.json  (AZ-* checks)

After this script runs, Build-Registry.py reads `frameworkOverrides` and
`effortOverride` from the source files directly — no standalone override
files needed. The original files become safe to delete.

This script is committed for reproducibility (and audit trail) but only
needs to run once. Subsequent rebuilds do NOT need it; the data lives in
the source files now.

Usage (from repo root):
    python scripts/Migrate-Overrides-3.0.py

Run it once; verify the diff; commit.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA = REPO_ROOT / "data"


def load(path: Path) -> dict | list:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def write(path: Path, data: object) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def main() -> int:
    fw_path = DATA / "framework-overrides.json"
    eff_path = DATA / "effort-overrides.json"
    m365_path = DATA / "scf-check-mapping.json"
    az_path = DATA / "az-assess-source-checks.json"

    if not fw_path.exists() and not eff_path.exists():
        print("Migration appears already complete (override files missing). Nothing to do.")
        return 0

    fw_overrides = load(fw_path)["overrides"] if fw_path.exists() else {}
    eff_overrides = load(eff_path)["overrides"] if eff_path.exists() else {}
    m365 = load(m365_path)
    az = load(az_path)

    m365_by_id = {c["checkId"]: c for c in m365["checks"]}
    az_by_id = {c["checkId"]: c for c in az}

    # Migrate framework-overrides
    fw_m365 = 0
    fw_az = 0
    fw_orphan: list[str] = []
    for check_id, fw_map in fw_overrides.items():
        if check_id in m365_by_id:
            m365_by_id[check_id]["frameworkOverrides"] = fw_map
            fw_m365 += 1
        elif check_id in az_by_id:
            az_by_id[check_id]["frameworkOverrides"] = fw_map
            fw_az += 1
        else:
            fw_orphan.append(check_id)

    # Migrate effort-overrides
    eff_m365 = 0
    eff_orphan: list[str] = []
    for check_id, entry in eff_overrides.items():
        target = m365_by_id.get(check_id) or az_by_id.get(check_id)
        if not target:
            eff_orphan.append(check_id)
            continue

        # Strip the underscore on _rationale (no longer build-time-stripped;
        # it's a real field now). Keep all other fields verbatim.
        clean_entry = {
            ("rationale" if k == "_rationale" else k): v
            for k, v in entry.items()
        }
        target["effortOverride"] = clean_entry
        if target is m365_by_id.get(check_id):
            eff_m365 += 1

    if fw_orphan or eff_orphan:
        print("ERROR: Orphan override entries (check ID not found in any source file):")
        for o in fw_orphan:
            print(f"  framework-override: {o}")
        for o in eff_orphan:
            print(f"  effort-override: {o}")
        return 1

    write(m365_path, m365)
    write(az_path, az)

    print("Migration complete:")
    print(f"  Framework overrides: {fw_m365} inlined into scf-check-mapping.json, "
          f"{fw_az} into az-assess-source-checks.json")
    print(f"  Effort overrides:    {eff_m365} inlined into scf-check-mapping.json")
    print()
    print("Next steps (do these as part of the same commit):")
    print("  1. rm data/framework-overrides.json data/effort-overrides.json")
    print("  2. Update scripts/Build-Registry.py to read inline overrides")
    print("  3. Run: python scripts/Build-Registry.py")
    print("  4. Run: pwsh -Command 'Invoke-Pester ./tests/migration-3.0.Tests.ps1'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
