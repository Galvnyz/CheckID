#!/usr/bin/env python3
"""Consumer-side importer for CIS M365 v6 authored prose (#347 phase 2 / Path A).

Reads YOUR LICENSED COPY of CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.xlsx
and writes data/cis-m365-v6-authored.local.json — a gitignored artifact that
stays on your machine.

The CIS SecureSuite membership agreement permits members to use CIS Benchmark
content for internal use within the member organization. It does NOT permit
public redistribution. CheckID respects this by never carrying CIS-authored
prose in the public repository; instead, the structure (the cisAuthored block
in the schema) accepts the data when each consumer populates it locally.

Output file shape:

    {
      "schemaVersion": "1.0.0",
      "source": "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.xlsx",
      "license": "CC BY-NC-SA 4.0 + CIS SecureSuite member agreement (internal use only)",
      "_warning": "Do NOT commit. Do NOT redistribute publicly. See LICENSES/CIS-CONSUMER-SIDE.md.",
      "controls": {
        "1.1.1": {
          "description": "<verbatim>",
          "rationale": "<verbatim>",
          "impact": "<verbatim>",
          "remediation": "<verbatim>",
          "audit": "<verbatim>",
          "additionalInfo": "<verbatim>"
        },
        ...
      }
    }

scripts/Build-Registry.py merges this file into each check's
frameworks.cis-m365-v6.cisAuthored block when present; gracefully no-ops when
absent (the public CheckID flow).

Usage:
    python tools/import-cis-prose.py
    python tools/import-cis-prose.py --cis-dir path/to/SecFrame/CIS
    python tools/import-cis-prose.py --include description,rationale  # subset

Exit codes:
    0  success
    1  XLSX file not found
    2  XLSX missing expected columns
"""
import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

try:
    import openpyxl
except ImportError:
    raise SystemExit("ERROR: openpyxl is required. Run: pip install openpyxl")


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CIS_DIR = REPO_ROOT.parent / "SecFrame" / "CIS"
XLSX_NAME = "CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.xlsx"
OUTPUT_PATH = REPO_ROOT / "data" / "cis-m365-v6-authored.local.json"

SCHEMA_VERSION = "1.0.0"

# Map CIS spreadsheet column names → cisAuthored field names (matches
# data/registry.schema.json $defs.cisAuthoredProse).
COLUMN_MAP = OrderedDict([
    ("Description",           "description"),
    ("Rationale Statement",   "rationale"),
    ("Impact Statement",      "impact"),
    ("Remediation Procedure", "remediation"),
    ("Audit Procedure",       "audit"),
    ("Additional Information", "additionalInfo"),
])


def _opt_col(headers: tuple, name: str) -> int | None:
    for i, h in enumerate(headers):
        if h == name:
            return i
    return None


def _cell_text(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def import_prose(xlsx_path: Path, include_fields: set[str] | None) -> dict:
    """Extract per-recommendation CIS-authored prose from the XLSX.

    Returns {rec_id: {field: prose_text, ...}, ...}, omitting empty fields.
    """
    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    ws = wb["Combined Profiles"]
    rows = list(ws.iter_rows(values_only=True))
    headers = rows[0]

    rec_col = _opt_col(headers, "Recommendation #")
    if rec_col is None:
        print("ERROR: 'Recommendation #' column not found in 'Combined Profiles' sheet")
        sys.exit(2)

    # Resolve each requested column; skip silently if a column is missing
    # from this XLSX version (the spreadsheet shape evolves between releases).
    field_cols: list[tuple[int, str]] = []
    missing: list[str] = []
    for xlsx_name, json_field in COLUMN_MAP.items():
        if include_fields is not None and json_field not in include_fields:
            continue
        idx = _opt_col(headers, xlsx_name)
        if idx is not None:
            field_cols.append((idx, json_field))
        else:
            missing.append(xlsx_name)

    if missing:
        print(f"  NOTE: skipped columns not present in this XLSX: {', '.join(missing)}")

    if not field_cols:
        print("ERROR: no requested prose columns found in XLSX")
        sys.exit(2)

    controls: dict[str, dict] = {}
    for row in rows[1:]:
        if rec_col >= len(row):
            continue
        rec_raw = row[rec_col]
        if rec_raw is None:
            continue
        rec = str(rec_raw).strip()
        if not re.match(r'^\d+\.\d+', rec):
            continue
        if rec in controls:
            # Multi-row presence (some XLSX exports duplicate per profile);
            # keep the first non-empty value seen.
            continue
        entry: dict[str, str] = {}
        for idx, field in field_cols:
            text = _cell_text(row[idx]) if idx < len(row) else ""
            if text:
                entry[field] = text
        if entry:
            controls[rec] = entry

    return controls


def write_output(controls: dict, out_path: Path) -> None:
    payload = OrderedDict([
        ("schemaVersion", SCHEMA_VERSION),
        ("source", XLSX_NAME),
        ("license", "CC BY-NC-SA 4.0 + CIS SecureSuite member agreement (internal use only)"),
        ("_warning",
         "Do NOT commit. Do NOT redistribute publicly. CIS member terms permit "
         "internal use only. See LICENSES/CIS-CONSUMER-SIDE.md for the full posture."),
        ("controls", OrderedDict(sorted(controls.items(), key=lambda kv: [
            int(p) if p.isdigit() else p for p in kv[0].split(".")
        ]))),
    ])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    field_counts: dict[str, int] = {f: 0 for f in COLUMN_MAP.values()}
    for entry in controls.values():
        for field in entry:
            field_counts[field] = field_counts.get(field, 0) + 1
    print(f"  Written: {out_path.relative_to(REPO_ROOT)}")
    print(f"  {len(controls)} recommendations imported.")
    print(f"  Field population: {field_counts}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--cis-dir",
        type=Path,
        default=DEFAULT_CIS_DIR,
        help="Directory containing the CIS XLSX (default: %(default)s)",
    )
    parser.add_argument(
        "--include",
        type=str,
        default=None,
        help="Comma-separated subset of fields to import: "
             "description,rationale,impact,remediation,audit,additionalInfo. "
             "Default: all fields.",
    )
    args = parser.parse_args()

    xlsx_path = args.cis_dir / XLSX_NAME
    if not xlsx_path.exists():
        print(f"ERROR: file not found: {xlsx_path}")
        print(f"       Expected the CIS M365 Foundations v6 XLSX at this path.")
        print(f"       Override with --cis-dir if your copy is elsewhere.")
        sys.exit(1)

    include_fields: set[str] | None = None
    if args.include is not None:
        include_fields = {f.strip() for f in args.include.split(",") if f.strip()}
        valid = set(COLUMN_MAP.values())
        unknown = include_fields - valid
        if unknown:
            print(f"ERROR: --include has unknown fields: {', '.join(sorted(unknown))}")
            print(f"       Valid: {', '.join(sorted(valid))}")
            sys.exit(2)

    print(f"Reading: {xlsx_path.name}")
    print()
    print("=" * 72)
    print("  LICENSING NOTICE")
    print("=" * 72)
    print("  This script extracts CIS-authored prose from your licensed copy")
    print("  of the CIS M365 v6 Benchmark. The output file is gitignored and")
    print("  must NOT be committed or redistributed publicly. CIS SecureSuite")
    print("  member terms permit internal use only.")
    print("  See LICENSES/CIS-CONSUMER-SIDE.md.")
    print("=" * 72)
    print()

    controls = import_prose(xlsx_path, include_fields)
    write_output(controls, OUTPUT_PATH)
    print()
    print("Done. The output is gitignored. Re-run scripts/Build-Registry.py to")
    print("merge into your local registry build.")


if __name__ == "__main__":
    main()
