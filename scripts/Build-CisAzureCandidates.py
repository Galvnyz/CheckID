#!/usr/bin/env python3
"""Generate candidate AZ-*/WIN-* check entries from SecFrame CIS Azure/Server CSV exports.

Usage:
    python scripts/Build-CisAzureCandidates.py
    python scripts/Build-CisAzureCandidates.py --csv-dir /tmp/cis-azure --scf-db /tmp/scf.db
    python scripts/Build-CisAzureCandidates.py --dry-run

Output: candidates/az-candidates.json
"""
import argparse
import csv
import json
import re
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SECTION_MAP_PATH = REPO_ROOT / "data" / "cis-azure-section-map.json"
AZ_CHECKS_PATH = REPO_ROOT / "data" / "az-assess-source-checks.json"
CANDIDATES_PATH = REPO_ROOT / "candidates" / "az-candidates.json"
DEFAULT_SCF_DB = Path("C:/git/SecFrame/SCF/scf.db")

# Maps CSV directory stem → section-map key
CSV_DIR_TO_MAP_KEY = {
    "CIS_Microsoft_Azure_Foundations_Benchmark_v5.0.0": "azure-foundations",
    "CIS_Microsoft_Azure_Compute_Services_Benchmark_v2.0.0": "azure-compute",
    "CIS_Microsoft_Azure_Database_Services_Benchmark_v2.0.0": "azure-database",
    "CIS_Azure_Kubernetes_Service_(AKS)_Benchmark_v1.8.0": "azure-aks",
    "CIS_Microsoft_Windows_Server_2025_Benchmark_v2.0.0": "windows-server-2025",
}

# Sheet names to skip in every benchmark
SKIP_SHEETS = {"license", "overview", "introduction", "about", "change log", "changelog",
               "mitre att&ck mappings", "mitre att&ck filtering"}

NIST_REF_RE = re.compile(r"[A-Z]{2,3}-\d+(?:\(\d+\))?")
REC_ID_RE = re.compile(r"^\d+(\.\d+)+$")


def load_section_map() -> dict:
    with SECTION_MAP_PATH.open(encoding="utf-8") as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if not k.startswith("_")}


def load_existing_checks() -> dict[str, int]:
    """Return dict of SERVICE-AREA prefix → highest existing sequence number."""
    highest: dict[str, int] = {}
    if not AZ_CHECKS_PATH.exists():
        return highest
    with AZ_CHECKS_PATH.open(encoding="utf-8") as f:
        checks = json.load(f)
    for check in checks:
        cid = check.get("checkId", "")
        parts = cid.rsplit("-", 1)
        if len(parts) == 2 and parts[1].isdigit():
            prefix = parts[0]
            highest[prefix] = max(highest.get(prefix, 0), int(parts[1]))
    return highest


def find_col(headers: list[str], *keywords: str) -> int | None:
    """Find first header index whose lowercase text contains any keyword."""
    for kw in keywords:
        for i, h in enumerate(headers):
            if kw in h.lower():
                return i
    return None


def read_csv_recommendations(csv_path: Path) -> list[dict]:
    """Read a CIS benchmark CSV and return recommendation records.

    CIS benchmark CSVs have two key columns:
    - 'Section #'      — hierarchical section number (1, 1.1, 2.1, ...)
    - 'Recommendation #' — actual recommendation ID (1.1.1, 5.2.3, ...)
      Empty for section-header rows; only rows with this populated are recommendations.
    """
    sheet_name = csv_path.stem.lower()
    if any(skip in sheet_name for skip in SKIP_SHEETS):
        return []

    with csv_path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.reader(f))

    if not rows:
        return []

    # Find the header row (first row containing 'section' or 'recommendation')
    header_idx = None
    for i, row in enumerate(rows[:20]):
        joined = " ".join(c.lower() for c in row if c.strip())
        if "section" in joined or "recommendation" in joined:
            header_idx = i
            break
    if header_idx is None:
        return []

    headers = [h.strip() for h in rows[header_idx]]
    headers_lower = [h.lower() for h in headers]

    rec_col = find_col(headers_lower, "recommendation #", "recommendation#", "rec #", "rec#")
    title_col = find_col(headers_lower, "title", "recommendation")
    desc_col = find_col(headers_lower, "description", "rationale", "detail")
    nist_col = find_col(headers_lower, "nist", "800-53", "800-171")

    if rec_col is None:
        # Fallback: no 'Recommendation #' column — use first col matching N.N.N
        recs = []
        for row in rows[header_idx + 1:]:
            first = row[0].strip() if row else ""
            if REC_ID_RE.match(first):
                recs.append({
                    "control_id": first,
                    "title": row[1].strip() if len(row) > 1 else "",
                    "description": row[2].strip() if len(row) > 2 else "",
                    "nist_ref": "",
                })
        return recs

    recs = []
    for row in rows[header_idx + 1:]:
        if len(row) <= rec_col:
            continue
        rec_id = row[rec_col].strip()
        if not rec_id or not REC_ID_RE.match(rec_id):
            continue

        def get(col: int | None) -> str:
            return row[col].strip() if col is not None and col < len(row) else ""

        recs.append({
            "control_id": rec_id,
            "title": get(title_col),
            "description": get(desc_col),
            "nist_ref": get(nist_col),
        })
    return recs


def lookup_scf_primary(nist_ref: str, conn: sqlite3.Connection) -> str | None:
    """Transitive lookup: NIST 800-53 control → SCF primary control ID."""
    refs = NIST_REF_RE.findall(nist_ref)
    if not refs:
        return None
    try:
        cur = conn.cursor()
        for ref in refs:
            # SCF framework ID 46 = NIST 800-53 R5
            cur.execute(
                """
                SELECT c.scf_id FROM control_mappings cm
                JOIN controls c ON cm.scf_control_id = c.id
                WHERE cm.framework_id = 46 AND cm.framework_control_id = ?
                LIMIT 1
                """,
                (ref.strip(),),
            )
            row = cur.fetchone()
            if row:
                return row[0]
    except sqlite3.Error:
        pass
    return None


def lookup_scf_meta(scf_id: str, conn: sqlite3.Connection) -> dict:
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT domain, control_name, description FROM controls WHERE scf_id = ? LIMIT 1",
            (scf_id,),
        )
        row = cur.fetchone()
        if row:
            return {"domain": row[0] or "TODO", "controlName": row[1] or "TODO",
                    "controlDescription": row[2] or "TODO"}
    except sqlite3.Error:
        pass
    return {"domain": "TODO", "controlName": "TODO", "controlDescription": "TODO"}


def build_candidates(
    csv_root: Path,
    section_map: dict,
    existing_highest: dict[str, int],
    scf_conn: sqlite3.Connection | None,
) -> list[dict]:
    candidates = []
    counters = dict(existing_highest)
    stats = {"total": 0, "need_scf": 0, "need_impact": 0, "skipped_unmapped": 0}

    for dir_stem, map_key in CSV_DIR_TO_MAP_KEY.items():
        csv_dir = csv_root / dir_stem
        if not csv_dir.exists():
            print(f"  [SKIP] {dir_stem}/ not found in {csv_root}", file=sys.stderr)
            continue

        area_map = section_map.get(map_key, {})
        use_wildcard = "*" in area_map
        seen_ids: set[str] = set()

        for csv_path in sorted(csv_dir.glob("*.csv")):
            recs = read_csv_recommendations(csv_path)
            for rec in recs:
                control_id = rec["control_id"]
                if control_id in seen_ids:
                    continue
                seen_ids.add(control_id)

                section = control_id.split(".")[0]
                if use_wildcard:
                    service_area = area_map["*"]
                elif section in area_map:
                    service_area = area_map[section]
                else:
                    stats["skipped_unmapped"] += 1
                    continue  # Unmapped sections are intentionally excluded

                counters[service_area] = counters.get(service_area, 0) + 1
                check_id = f"{service_area}-{counters[service_area]:03d}"

                scf_primary = "TODO"
                scf_meta = {"domain": "TODO", "controlName": "TODO",
                            "controlDescription": "TODO", "csfFunction": "TODO"}
                if scf_conn and rec["nist_ref"]:
                    found = lookup_scf_primary(rec["nist_ref"], scf_conn)
                    if found:
                        scf_primary = found
                        meta = lookup_scf_meta(found, scf_conn)
                        scf_meta.update(meta)

                if scf_primary == "TODO":
                    stats["need_scf"] += 1

                entry = {
                    "checkId": check_id,
                    "name": rec["title"] or f"CIS {control_id}",
                    "category": service_area.split("-", 1)[1] if "-" in service_area else service_area,
                    "collector": "AzAssess",
                    "hasAutomatedCheck": True,
                    "licensing": {"minimum": "AzureSubscription"},
                    "scf": {
                        "primaryControlId": scf_primary,
                        "domain": scf_meta["domain"],
                        "controlName": scf_meta["controlName"],
                        "controlDescription": rec["description"] or scf_meta["controlDescription"],
                        "csfFunction": scf_meta.get("csfFunction", "TODO"),
                    },
                    "frameworks": {},
                    "impactRating": {
                        "severity": "TODO",
                        "rationale": "TODO",
                    },
                    "_source": {
                        "cisControlId": control_id,
                        "cisTitle": rec["title"],
                        "nistRef": rec["nist_ref"],
                        "benchmark": map_key,
                        "sheet": csv_path.stem,
                    },
                }
                candidates.append(entry)
                stats["total"] += 1
                stats["need_impact"] += 1

    print(f"\nGenerated {stats['total']} candidates:")
    print(f"  {stats['need_scf']} need scf.primaryControlId")
    print(f"  {stats['need_impact']} need impactRating (all candidates)")
    print(f"  {stats['skipped_unmapped']} controls skipped (section not in section map)")
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate CIS Azure/Server check candidates for CheckID.")
    parser.add_argument("--csv-dir", type=Path,
                        default=Path("C:/git/SecFrame/csv-exports/CIS"),
                        help="Root directory containing per-XLSX CSV subdirectories")
    parser.add_argument("--scf-db", type=Path, default=DEFAULT_SCF_DB,
                        help="Path to SecFrame SCF SQLite database for transitive lookups")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print candidate count without writing output")
    args = parser.parse_args()

    section_map = load_section_map()
    existing_highest = load_existing_checks()

    scf_conn = None
    if args.scf_db.exists():
        scf_conn = sqlite3.connect(str(args.scf_db))
        print(f"SCF database loaded: {args.scf_db}")
    else:
        print(f"[WARNING] SCF database not found at {args.scf_db} — SCF lookups disabled",
              file=sys.stderr)

    try:
        candidates = build_candidates(args.csv_dir, section_map, existing_highest, scf_conn)
    finally:
        if scf_conn:
            scf_conn.close()

    if args.dry_run:
        print("Dry run — no output written.")
        return 0

    CANDIDATES_PATH.parent.mkdir(exist_ok=True)
    with CANDIDATES_PATH.open("w", encoding="utf-8") as f:
        json.dump(candidates, f, indent=2, ensure_ascii=False)
    print(f"\nOutput written to {CANDIDATES_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
