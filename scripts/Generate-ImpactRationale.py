#!/usr/bin/env python3
"""Auto-generate impactRationale for all checks in scf-check-mapping.json.

Uses SCF control_name (question) + associated risk names from scf.db.
Converts "Does the organization X?" -> "Failure to X exposes the tenant to: [risks]."

Usage:
    python scripts/Generate-ImpactRationale.py                 # updates scf-check-mapping.json in place
    python scripts/Generate-ImpactRationale.py --dry-run       # prints JSON to stdout, no file write
    python scripts/Generate-ImpactRationale.py --overwrite     # re-generate even if rationale already set
"""
import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
MAPPING_FILE = REPO_ROOT / "data" / "scf-check-mapping.json"
DEFAULT_SCF_DB = Path("C:/git/SecFrame/SCF/scf.db")

# Risks too generic/financial to be useful in a technical rationale
_SKIP_RISK_SUBSTRINGS = [
    "revenue", "cancelled contract", "competitive advantage",
    "reputation", "fines and judgements", "expense associated",
    "reduction in productivity", "reliance on the third-party",
    "use of product", "illegal content", "diminished",
    "loss of revenue", "cancelled",
]

MAX_RISKS = 3
MAX_RATIONALE_CHARS = 280


def _is_useful_risk(risk_name: str) -> bool:
    lower = risk_name.lower()
    return not any(s in lower for s in _SKIP_RISK_SUBSTRINGS)


def _question_to_statement(control_name: str) -> str:
    """Convert 'Does the organization X?' to 'ensure X'."""
    text = control_name.strip().rstrip("?")
    text = re.sub(r"^Does the organization\s+", "", text, flags=re.IGNORECASE)
    if text:
        text = text[0].lower() + text[1:]
    return text


def load_risks_for_controls(conn: sqlite3.Connection, scf_ids: list) -> dict:
    if not scf_ids:
        return {}
    placeholders = ",".join("?" for _ in scf_ids)
    cur = conn.cursor()
    cur.execute(
        f"SELECT cr.scf_id, r.risk_name FROM control_risks cr "
        f"JOIN risks r ON cr.risk_id = r.risk_id "
        f"WHERE cr.scf_id IN ({placeholders}) ORDER BY cr.scf_id, cr.risk_id",
        scf_ids,
    )
    result = {}
    for scf_id, risk_name in cur.fetchall():
        result.setdefault(scf_id, []).append(risk_name)
    return result


def load_control_names(conn: sqlite3.Connection, scf_ids: list) -> dict:
    if not scf_ids:
        return {}
    placeholders = ",".join("?" for _ in scf_ids)
    cur = conn.cursor()
    cur.execute(
        f"SELECT scf_id, control_name FROM controls WHERE scf_id IN ({placeholders})",
        scf_ids,
    )
    return {row[0]: row[1] for row in cur.fetchall() if row[1]}


def generate_rationale(control_name: str, risks: list) -> str:
    statement = _question_to_statement(control_name)
    useful_risks = [r for r in risks if _is_useful_risk(r)][:MAX_RISKS]
    if useful_risks:
        risk_str = ", ".join(useful_risks)
        rationale = f"Failure to {statement} exposes the tenant to: {risk_str}."
    else:
        rationale = f"Failure to {statement} may expose the tenant to unauthorized access or compliance gaps."
    if len(rationale) > MAX_RATIONALE_CHARS:
        rationale = rationale[:MAX_RATIONALE_CHARS].rsplit(" ", 1)[0].rstrip(",:") + "."
    return rationale


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Print JSON to stdout instead of writing file")
    parser.add_argument("--overwrite", action="store_true",
                        help="Re-generate rationale even if already set")
    parser.add_argument("--scf-db", default=str(DEFAULT_SCF_DB))
    args = parser.parse_args()

    with open(MAPPING_FILE, encoding="utf-8") as f:
        mapping = json.load(f)

    checks = mapping["checks"]
    scf_ids = list({c["scfPrimary"] for c in checks if c.get("scfPrimary")})

    conn = sqlite3.connect(args.scf_db)
    control_names = load_control_names(conn, scf_ids)
    all_risks = load_risks_for_controls(conn, scf_ids)
    conn.close()

    updated = 0
    for check in checks:
        if check.get("impactRationale") and not args.overwrite:
            continue
        scf_id = check.get("scfPrimary", "")
        name = control_names.get(scf_id, "")
        risks = all_risks.get(scf_id, [])
        if name:
            check["impactRationale"] = generate_rationale(name, risks)
            updated += 1
        elif not check.get("impactRationale"):
            check["impactRationale"] = "Failure to implement this control may expose the tenant to security risks."

    print(f"Generated rationale for {updated} checks", file=sys.stderr)

    if args.dry_run:
        print(json.dumps(mapping, indent=2, ensure_ascii=False))
    else:
        with open(MAPPING_FILE, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"Updated {MAPPING_FILE}", file=sys.stderr)


if __name__ == "__main__":
    main()
