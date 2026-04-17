"""Build CIS M365 crosswalk data files for CheckID.

Reads CIS_M365_to_NIST_to_FedRAMP_Crosswalk.csv from the SecFrame/CIS directory
and produces:
  - data/cis-m365-crosswalk.json   authoritative CIS M365 -> NIST / FedRAMP mapping
  - data/framework-titles.json     updated with cis-m365-v6 section

Usage:
    python scripts/Build-CisM365Crosswalk.py
    python scripts/Build-CisM365Crosswalk.py --csv path/to/crosswalk.csv
"""

import argparse
import csv
import json
import re
from collections import OrderedDict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CSV = REPO_ROOT.parent / "SecFrame" / "CIS" / "CIS_M365_to_NIST_to_FedRAMP_Crosswalk.csv"
CROSSWALK_OUT = REPO_ROOT / "data" / "cis-m365-crosswalk.json"
TITLES_PATH = REPO_ROOT / "data" / "framework-titles.json"
SCHEMA_VERSION = "1.0.0"


def parse_nist_ids(raw: str) -> list[str]:
    """Split semicolon-separated NIST IDs, normalise whitespace and parens.

    Input:  "AC-2; AC-6(5); IA-5c; CM-7b"
    Output: ["AC-2", "AC-6(5)", "IA-5", "CM-7"]

    CIS sometimes references NIST sub-items using letter suffixes (IA-5c, CM-7b)
    which are not standard NIST control IDs. These are normalised to the parent
    control (letter stripped) and deduplicated.
    """
    ids: list[str] = []
    seen: set[str] = set()
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        # Normalise parenthetical suffix spacing: "AC-6 (5)" -> "AC-6(5)"
        part = re.sub(r'\s+\(', '(', part)
        # Normalise letter sub-item suffix: "IA-5c" -> "IA-5", "CM-7b" -> "CM-7"
        # Only strip when it's a bare letter (no parenthesis follows)
        part = re.sub(r'^([A-Z]+-\d+)[a-z]$', r'\1', part)
        if part not in seen:
            seen.add(part)
            ids.append(part)
    return ids


def strip_level_prefix(title: str) -> str:
    """Remove leading level tag from CIS titles.

    "(L1) Ensure Administrative accounts are cloud-only"
    -> "Ensure Administrative accounts are cloud-only"
    """
    return re.sub(r'^\(L\d\)\s*', '', title).strip()


def build_crosswalk(csv_path: Path) -> tuple[dict, dict]:
    """Parse the CSV and return (controls_dict, titles_dict).

    controls_dict: {cisId: {title, section, level, license, nist800_53, fedramp}}
    titles_dict:   {cisId: title_string}
    """
    controls: dict = {}
    titles: dict = {}

    with open(csv_path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cis_id = row["RecommendationId"].strip()
            if not cis_id:
                continue

            raw_title = row.get("Title", "").strip()
            title = strip_level_prefix(raw_title)
            section = row.get("Section", "").strip()
            level = row.get("Level", "").strip()
            license_ = row.get("License", "").strip()
            nist_raw = row.get("NIST80053", "").strip()
            nist_ids = parse_nist_ids(nist_raw) if nist_raw else []
            fedramp = {
                "high":     row.get("FedRAMP_High", "").strip().lower() == "yes",
                "moderate": row.get("FedRAMP_Moderate", "").strip().lower() == "yes",
                "low":      row.get("FedRAMP_Low", "").strip().lower() == "yes",
            }

            # Keep first occurrence if the same ID appears more than once
            if cis_id not in controls:
                controls[cis_id] = {
                    "title":     title,
                    "section":   section,
                    "level":     level,
                    "license":   license_,
                    "nist800_53": nist_ids,
                    "fedramp":   fedramp,
                }
                titles[cis_id] = title

    return controls, titles


def write_crosswalk(controls: dict, out_path: Path) -> None:
    payload = OrderedDict([
        ("schemaVersion", SCHEMA_VERSION),
        ("source", "CIS_M365_to_NIST_to_FedRAMP_Crosswalk.csv"),
        ("controls", controls),
    ])
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"  Written: {out_path.relative_to(REPO_ROOT)} ({len(controls)} controls)")


def update_framework_titles(titles: dict, titles_path: Path) -> None:
    existing = json.loads(titles_path.read_text(encoding="utf-8"))
    existing["cis-m365-v6"] = titles
    # Sort top-level keys for stable output
    ordered = OrderedDict(sorted(existing.items()))
    titles_path.write_text(
        json.dumps(ordered, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"  Updated: {titles_path.relative_to(REPO_ROOT)} (added cis-m365-v6: {len(titles)} titles)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--csv", type=Path, default=DEFAULT_CSV,
        help="Path to CIS_M365_to_NIST_to_FedRAMP_Crosswalk.csv (default: %(default)s)",
    )
    args = parser.parse_args()

    if not args.csv.exists():
        print(f"ERROR: CSV not found: {args.csv}")
        raise SystemExit(1)

    print(f"Reading: {args.csv.name}")
    controls, titles = build_crosswalk(args.csv)
    print(f"  Parsed {len(controls)} CIS M365 control entries")

    write_crosswalk(controls, CROSSWALK_OUT)
    update_framework_titles(titles, TITLES_PATH)

    print("\nDone.")


if __name__ == "__main__":
    main()
