#!/usr/bin/env python3
"""Build the master control registry (registry.json) from SCF as source of truth.

Reads scf-check-mapping.json (check → SCF assignments) and queries the SCF
SQLite database for all control metadata, framework mappings, risks, threats,
and assessment objectives. Produces registry.json v2.0.0.

Pipeline:
    scf-check-mapping.json  →  check definitions
           +
       scf.db               →  SCF metadata + framework derivation
           +
    scf-framework-map.json  →  which frameworks to include
           +
    framework-titles.json   →  human-readable titles
           ↓
       registry.json (v2.0.0)

Usage:
    python scripts/Build-Registry.py
    python scripts/Build-Registry.py --scf-db C:/git/SecFrame/SCF/scf.db
"""
import argparse
import io
import json
import re
import sqlite3
import sys
from collections import defaultdict, OrderedDict
from datetime import date
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )

SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent

SCHEMA_VERSION = "2.0.0"


# ---------------------------------------------------------------------------
# SCF database helpers
# ---------------------------------------------------------------------------

def load_scf_controls(conn: sqlite3.Connection) -> dict[str, dict]:
    """Load all SCF control metadata keyed by scf_id."""
    cur = conn.cursor()
    cur.execute(
        "SELECT scf_id, scf_domain, control_name, description, control_question, "
        "relative_weighting, csf_function, "
        "cmm_0_not_performed, cmm_1_informal, cmm_2_planned, "
        "cmm_3_defined, cmm_4_controlled, cmm_5_improving "
        "FROM controls"
    )
    controls = {}
    for row in cur.fetchall():
        controls[row[0]] = {
            "scfId": row[0],
            "domain": row[1],
            "controlName": row[2],
            "description": row[3],
            "controlQuestion": row[4],
            "relativeWeighting": row[5],
            "csfFunction": row[6],
            "cmm0": bool(row[7]),
            "cmm1": bool(row[8]),
            "cmm2": bool(row[9]),
            "cmm3": bool(row[10]),
            "cmm4": bool(row[11]),
            "cmm5": bool(row[12]),
        }
    return controls


def load_assessment_objectives(conn: sqlite3.Connection) -> dict[str, list[dict]]:
    """Load assessment objectives grouped by scf_id."""
    cur = conn.cursor()
    cur.execute("SELECT scf_id, ao_number, objective_text FROM assessment_objectives ORDER BY ao_number")
    aos: dict[str, list[dict]] = defaultdict(list)
    for scf_id, ao_number, text in cur.fetchall():
        if ao_number and text:
            aos[scf_id].append({"aoId": ao_number, "text": text.strip()})
    return dict(aos)


def load_control_risks(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """Load risk associations grouped by scf_id."""
    cur = conn.cursor()
    cur.execute("SELECT scf_id, risk_id FROM control_risks ORDER BY risk_id")
    risks: dict[str, list[str]] = defaultdict(list)
    for scf_id, risk_id in cur.fetchall():
        if risk_id:
            risks[scf_id].append(risk_id)
    return dict(risks)


def load_control_threats(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """Load threat associations grouped by scf_id."""
    cur = conn.cursor()
    cur.execute("SELECT scf_id, threat_id FROM control_threats ORDER BY threat_id")
    threats: dict[str, list[str]] = defaultdict(list)
    for scf_id, threat_id in cur.fetchall():
        if threat_id:
            threats[scf_id].append(threat_id)
    return dict(threats)


def load_framework_mappings(
    conn: sqlite3.Connection,
    framework_ids: list[int],
) -> dict[str, dict[int, list[str]]]:
    """Load control_mappings for specified framework IDs.

    Returns {scf_id: {framework_id: [control_ids]}}.
    """
    if not framework_ids:
        return {}
    placeholders = ",".join("?" for _ in framework_ids)
    cur = conn.cursor()
    cur.execute(
        f"SELECT scf_id, framework_id, framework_control_id "
        f"FROM control_mappings WHERE framework_id IN ({placeholders})",
        framework_ids,
    )
    mappings: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
    for scf_id, fw_id, ctrl_id in cur.fetchall():
        if ctrl_id:
            mappings[scf_id][fw_id].append(ctrl_id.strip())
    return dict(mappings)


# ---------------------------------------------------------------------------
# Framework map helpers
# ---------------------------------------------------------------------------

def build_framework_id_list(fw_map: dict) -> list[int]:
    """Extract all SCF framework IDs from the framework map config."""
    ids = []
    for key, cfg in fw_map.get("frameworks", {}).items():
        fid = cfg.get("scfFrameworkId")
        if isinstance(fid, list):
            ids.extend(fid)
        elif isinstance(fid, int):
            ids.append(fid)
        # Also include baseline IDs
        for baseline_cfg in cfg.get("baselines", {}).values():
            ids.append(baseline_cfg["scfFrameworkId"])
    return ids


def build_fwid_to_key(fw_map: dict) -> dict[int, str]:
    """Map SCF framework_id → CheckID framework key."""
    mapping = {}
    for key, cfg in fw_map.get("frameworks", {}).items():
        fid = cfg.get("scfFrameworkId")
        if isinstance(fid, list):
            for f in fid:
                mapping[f] = key
        elif isinstance(fid, int):
            mapping[fid] = key
    return mapping


def build_baseline_fwids(fw_map: dict) -> dict[str, dict[str, int]]:
    """Extract baseline framework IDs: {checkid_key: {profile_name: fw_id}}."""
    baselines = {}
    for key, cfg in fw_map.get("frameworks", {}).items():
        if "baselines" in cfg:
            baselines[key] = {
                name: bcfg["scfFrameworkId"]
                for name, bcfg in cfg["baselines"].items()
            }
    return baselines


# ---------------------------------------------------------------------------
# Title resolution
# ---------------------------------------------------------------------------

def load_framework_titles(path: Path) -> dict[str, dict[str, str]]:
    """Load framework-titles.json as {framework_key: {control_id: title}}."""
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: dict(v.items()) if isinstance(v, dict) else {} for k, v in data.items()}


def resolve_title(
    control_ids: str,
    framework_key: str,
    titles: dict[str, dict[str, str]],
) -> str | None:
    """Resolve human-readable title for semicolon-separated control IDs."""
    if not control_ids or framework_key not in titles:
        return None
    lookup = titles[framework_key]
    resolved = []
    for cid in control_ids.split(";"):
        cid = cid.strip()
        if not cid:
            continue
        title = lookup.get(cid) or lookup.get(cid.upper())
        if not title:
            # Try enhancement notation: AC-6(5) → AC-6.5
            dot_form = re.sub(r"\((\d+)\)", r".\1", cid)
            title = lookup.get(dot_form) or lookup.get(dot_form.upper())
        if not title:
            # Try stripping trailing sub-provision letter
            base = re.sub(r"[a-zA-Z]$", "", cid)
            title = lookup.get(base) or lookup.get(base.upper())
        if title and title not in resolved:
            resolved.append(title)
    return "; ".join(resolved) if resolved else None


# ---------------------------------------------------------------------------
# SCF domain sort key
# ---------------------------------------------------------------------------

SCF_DOMAIN_ORDER = [
    "Cybersecurity & Data Protection Governance",
    "Compliance",
    "Risk Management",
    "Threat Management",
    "Identification & Authentication",
    "Human Resources Security",
    "Security Awareness & Training",
    "Asset Management",
    "Data Classification & Handling",
    "Data Privacy",
    "Configuration Management",
    "Change Management",
    "Capacity & Performance Planning",
    "Continuous Monitoring",
    "Secure Engineering & Architecture",
    "Technology Development & Acquisition",
    "Third-Party Management",
    "Network Security",
    "Cloud Security",
    "Endpoint Security",
    "Mobile Device Management",
    "Embedded Technology",
    "Web Security",
    "Cryptographic Protections",
    "Physical & Environmental Security",
    "Business Continuity & Disaster Recovery",
    "Incident Response",
    "Vulnerability & Patch Management",
    "Maintenance",
    "Information Assurance",
    "Security Operations",
    "Project & Resource Management",
    "Artificial Intelligence & Autonomous Technologies",
]


def load_az_assess_source_checks(repo_root: Path) -> list[dict]:
    """Load manually-curated AZ-* checks for Az-Assess (Azure ARM surface).

    These checks are not SCF-database-derived — they are maintained directly in
    data/az-assess-source-checks.json and merged into the registry at build time.
    """
    source_path = repo_root / "data" / "az-assess-source-checks.json"
    if not source_path.exists():
        return []
    with open(source_path, encoding="utf-8") as f:
        entries = json.load(f)

    checks = []
    for entry in entries:
        check_obj = OrderedDict()
        check_obj["checkId"] = entry["checkId"]
        check_obj["name"] = entry["name"]
        check_obj["category"] = entry["category"]
        check_obj["collector"] = entry["collector"]
        check_obj["hasAutomatedCheck"] = entry.get("hasAutomatedCheck", True)

        lic = entry.get("licensing", {})
        check_obj["licensing"] = OrderedDict([("minimum", lic.get("minimum", "AzureSubscription"))])

        # SCF — use directly from source (no database enrichment for ARM checks)
        scf_src = entry.get("scf", {})
        scf_obj = OrderedDict()
        for key in ("primaryControlId", "domain", "controlName", "controlDescription"):
            if key in scf_src:
                scf_obj[key] = scf_src[key]
        check_obj["scf"] = scf_obj

        check_obj["frameworks"] = entry.get("frameworks", {})

        impact_src = entry.get("impactRating")
        if impact_src:
            impact = OrderedDict()
            for key in ("severity", "rationale"):
                if key in impact_src:
                    impact[key] = impact_src[key]
            check_obj["impactRating"] = impact

        checks.append(check_obj)

    return checks


def scf_sort_key(check: dict) -> tuple:
    """Sort key: SCF domain order → SCF ID (numeric sort)."""
    scf = check.get("scf", {})
    domain = scf.get("domain", "")
    try:
        domain_idx = SCF_DOMAIN_ORDER.index(domain)
    except ValueError:
        domain_idx = 999
    scf_id = scf.get("primaryControlId", "ZZZ-99")
    # Parse prefix and number for numeric sort: IAC-06.1 → ("IAC", 6, 1)
    match = re.match(r"^([A-Z]+)-(\d+)(?:\.(\d+))?$", scf_id)
    if match:
        prefix = match.group(1)
        major = int(match.group(2))
        minor = int(match.group(3)) if match.group(3) else 0
        return (domain_idx, prefix, major, minor)
    return (domain_idx, scf_id, 0, 0)


# ---------------------------------------------------------------------------
# Main build
# ---------------------------------------------------------------------------

def build_scf_object(
    scf_primary: str,
    scf_additional: list[str],
    scf_controls: dict[str, dict],
    all_aos: dict[str, list[dict]],
    all_risks: dict[str, list[str]],
    all_threats: dict[str, list[str]],
) -> dict | None:
    """Build the scf{} object for a check from its primary SCF control."""
    meta = scf_controls.get(scf_primary)
    if not meta:
        return None

    scf_obj = OrderedDict()
    scf_obj["primaryControlId"] = scf_primary
    if scf_additional:
        scf_obj["additionalControlIds"] = scf_additional
    scf_obj["domain"] = meta["domain"]
    scf_obj["controlName"] = meta["controlName"]
    scf_obj["controlDescription"] = meta["description"] or meta["controlName"] or ""
    if meta["controlQuestion"]:
        scf_obj["controlQuestion"] = meta["controlQuestion"]
    if meta["relativeWeighting"]:
        scf_obj["relativeWeighting"] = meta["relativeWeighting"]
    if meta["csfFunction"]:
        scf_obj["csfFunction"] = meta["csfFunction"]

    # Maturity levels
    scf_obj["maturityLevels"] = OrderedDict([
        ("cmm0_notPerformed", meta["cmm0"]),
        ("cmm1_informal", meta["cmm1"]),
        ("cmm2_planned", meta["cmm2"]),
        ("cmm3_defined", meta["cmm3"]),
        ("cmm4_controlled", meta["cmm4"]),
        ("cmm5_improving", meta["cmm5"]),
    ])

    # Assessment objectives (from primary control only to keep size manageable)
    aos = all_aos.get(scf_primary, [])
    if aos:
        scf_obj["assessmentObjectives"] = aos

    # Risks and threats (union of primary + additional)
    risk_set = set(all_risks.get(scf_primary, []))
    threat_set = set(all_threats.get(scf_primary, []))
    for add_id in scf_additional:
        risk_set.update(all_risks.get(add_id, []))
        threat_set.update(all_threats.get(add_id, []))
    if risk_set:
        scf_obj["risks"] = sorted(risk_set)
    if threat_set:
        scf_obj["threats"] = sorted(threat_set)

    return scf_obj


def get_parent_scf_id(scf_id: str) -> str | None:
    """Get the parent SCF control ID for a sub-control.

    IAC-21.3 → IAC-21, END-04.1 → END-04, IAC-21 → None (already a parent).
    """
    match = re.match(r"^([A-Z]{2,4}-\d{2})\.\d+$", scf_id)
    return match.group(1) if match else None


def derive_frameworks(
    scf_primary: str,
    scf_additional: list[str],
    all_fw_mappings: dict[str, dict[int, list[str]]],
    fwid_to_key: dict[int, str],
    baseline_fwids: dict[str, dict[str, int]],
    titles: dict[str, dict[str, str]],
) -> dict:
    """Derive framework mappings from SCF control_mappings for a check.

    When a sub-control (e.g., IAC-21.3) has no mapping for a framework,
    falls back to the parent control (IAC-21) to inherit its mappings.
    """
    frameworks = OrderedDict()
    # Collect control IDs per CheckID framework key from primary + additional
    key_controls: dict[str, set[str]] = defaultdict(set)

    scf_ids = [scf_primary] + scf_additional
    # Also include parent controls for fallback lookups
    scf_ids_with_parents = list(scf_ids)
    for scf_id in scf_ids:
        parent = get_parent_scf_id(scf_id)
        if parent and parent not in scf_ids_with_parents:
            scf_ids_with_parents.append(parent)

    for scf_id in scf_ids_with_parents:
        fw_map = all_fw_mappings.get(scf_id, {})
        for fw_id, ctrl_ids in fw_map.items():
            ck_key = fwid_to_key.get(fw_id)
            if ck_key:
                key_controls[ck_key].update(ctrl_ids)

    # Build framework entries
    for fw_key in sorted(key_controls.keys()):
        ctrl_ids = sorted(key_controls[fw_key])
        control_id_str = ";".join(ctrl_ids)
        entry = OrderedDict()
        entry["controlId"] = control_id_str

        title = resolve_title(control_id_str, fw_key, titles)
        if title:
            entry["title"] = title

        frameworks[fw_key] = entry

    # Resolve baseline profiles (e.g., NIST 800-53 Low/Moderate/High/Privacy)
    for fw_key, profile_map in baseline_fwids.items():
        if fw_key not in frameworks:
            continue
        # Check if any of the check's SCF controls (incl. parents) appear in baseline frameworks
        profiles = []
        for profile_name, baseline_fw_id in profile_map.items():
            for scf_id in scf_ids_with_parents:
                baseline_mappings = all_fw_mappings.get(scf_id, {}).get(baseline_fw_id, [])
                if baseline_mappings:
                    profiles.append(profile_name)
                    break
        if profiles:
            # Canonical order for NIST baselines
            order = ["Low", "Moderate", "High", "Privacy"]
            profiles = [p for p in order if p in profiles]
            frameworks[fw_key]["profiles"] = profiles

    return frameworks


def main():
    parser = argparse.ArgumentParser(description="Build CheckID registry.json from SCF")
    parser.add_argument(
        "--scf-db",
        default="C:/git/SecFrame/SCF/scf.db",
        help="Path to the SCF SQLite database",
    )
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "data" / "registry.json"),
        help="Output path for registry.json",
    )
    args = parser.parse_args()

    # Load input files
    mapping_path = REPO_ROOT / "data" / "scf-check-mapping.json"
    fw_map_path = REPO_ROOT / "data" / "scf-framework-map.json"
    title_path = REPO_ROOT / "data" / "framework-titles.json"

    print(f"Loading check mapping from {mapping_path}")
    with open(mapping_path, "r", encoding="utf-8") as f:
        check_mapping = json.load(f)

    print(f"Loading framework map from {fw_map_path}")
    with open(fw_map_path, "r", encoding="utf-8") as f:
        fw_map = json.load(f)

    print("Loading framework titles...")
    titles = load_framework_titles(title_path)

    # Load manual framework overrides (for gaps in SCF coverage)
    overrides_path = REPO_ROOT / "data" / "framework-overrides.json"
    fw_overrides: dict[str, dict] = {}
    if overrides_path.exists():
        with open(overrides_path, "r", encoding="utf-8") as f:
            overrides_data = json.load(f)
        fw_overrides = overrides_data.get("overrides", {})
        print(f"Loaded {len(fw_overrides)} framework overrides")

    # Connect to SCF database
    print(f"Connecting to SCF database at {args.scf_db}")
    conn = sqlite3.connect(args.scf_db)

    # Load all SCF data
    print("Loading SCF controls...")
    scf_controls = load_scf_controls(conn)
    print(f"  {len(scf_controls)} controls")

    print("Loading assessment objectives...")
    all_aos = load_assessment_objectives(conn)
    print(f"  {sum(len(v) for v in all_aos.values())} AOs across {len(all_aos)} controls")

    print("Loading risks and threats...")
    all_risks = load_control_risks(conn)
    all_threats = load_control_threats(conn)

    # Load framework mappings for all configured frameworks
    all_fw_ids = build_framework_id_list(fw_map)
    print(f"Loading framework mappings for {len(all_fw_ids)} framework IDs...")
    all_fw_mappings = load_framework_mappings(conn, all_fw_ids)
    print(f"  Mappings loaded for {len(all_fw_mappings)} SCF controls")

    fwid_to_key = build_fwid_to_key(fw_map)
    baseline_fwids = build_baseline_fwids(fw_map)

    # Build checks
    print(f"\nBuilding {len(check_mapping['checks'])} checks...")
    checks = []
    warnings = []

    for cm in check_mapping["checks"]:
        check_id = cm["checkId"]
        scf_primary = cm.get("scfPrimary", "")
        scf_additional = cm.get("scfAdditional", [])

        if not scf_primary:
            warnings.append(f"  WARN: {check_id} has no SCF primary — skipping SCF enrichment")
            continue

        # Build scf{} object
        scf_obj = build_scf_object(
            scf_primary, scf_additional,
            scf_controls, all_aos, all_risks, all_threats,
        )
        if not scf_obj:
            warnings.append(f"  WARN: {check_id} SCF control {scf_primary} not found in database")
            continue

        # Derive framework mappings from SCF
        frameworks = derive_frameworks(
            scf_primary, scf_additional,
            all_fw_mappings, fwid_to_key, baseline_fwids, titles,
        )

        # Overlay manual frameworks (CIS M365, CISA ScuBA, STIG — not in SCF)
        cis_id = cm.get("cisM365ControlId", "")
        if cis_id:
            cis_entry = OrderedDict([("controlId", cis_id)])
            cis_title = resolve_title(cis_id, "cis-m365-v6", titles)
            if cis_title:
                cis_entry["title"] = cis_title
            cis_profiles = cm.get("cisM365Profiles", [])
            if cis_profiles:
                cis_entry["profiles"] = cis_profiles
            frameworks["cis-m365-v6"] = cis_entry

        scuba_id = cm.get("cisaScubaControlId", "")
        if scuba_id:
            scuba_entry = OrderedDict([("controlId", scuba_id)])
            scuba_title = resolve_title(scuba_id, "cisa-scuba", titles)
            if scuba_title:
                scuba_entry["title"] = scuba_title
            frameworks["cisa-scuba"] = scuba_entry

        stig_id = cm.get("stigControlId", "")
        if stig_id:
            stig_entry = OrderedDict([("controlId", stig_id)])
            stig_title = resolve_title(stig_id, "stig", titles)
            if stig_title:
                stig_entry["title"] = stig_title
            frameworks["stig"] = stig_entry

        # Apply manual framework overrides (for gaps in SCF coverage)
        check_overrides = fw_overrides.get(check_id, {})
        for fw_key, fw_data in check_overrides.items():
            if fw_key not in frameworks and fw_data.get("controlId"):
                entry = OrderedDict([("controlId", fw_data["controlId"])])
                title = resolve_title(fw_data["controlId"], fw_key, titles)
                if title:
                    entry["title"] = title
                # Carry forward any extra fields (profiles, evidenceType)
                for extra_key in ("profiles", "evidenceType"):
                    if extra_key in fw_data:
                        entry[extra_key] = fw_data[extra_key]
                frameworks[fw_key] = entry

        # Ensure at least one framework exists
        if not frameworks:
            warnings.append(f"  WARN: {check_id} has no framework mappings — check SCF control {scf_primary}")

        # Build check object
        check_obj = OrderedDict()
        check_obj["checkId"] = check_id
        check_obj["name"] = cm["name"]
        check_obj["category"] = cm["category"]
        check_obj["collector"] = cm["collector"]
        check_obj["hasAutomatedCheck"] = cm.get("hasAutomatedCheck", True)
        check_obj["licensing"] = OrderedDict([("minimum", cm.get("licensing", "E3"))])
        check_obj["scf"] = scf_obj
        check_obj["frameworks"] = frameworks

        # Impact rating
        severity = cm.get("impactSeverity", "")
        if severity:
            impact = OrderedDict([("severity", severity)])
            rationale = cm.get("impactRationale", "")
            if rationale:
                impact["rationale"] = rationale
            weighting = scf_obj.get("relativeWeighting")
            if weighting:
                impact["scfWeighting"] = weighting
            check_obj["impactRating"] = impact

        checks.append(check_obj)

    # Sort by SCF domain → SCF ID
    checks.sort(key=scf_sort_key)

    # Merge AZ-Assess checks (Azure ARM surface — not SCF-database-derived)
    az_checks = load_az_assess_source_checks(REPO_ROOT)
    if az_checks:
        checks.extend(az_checks)
        checks.sort(key=scf_sort_key)
        print(f"Merged {len(az_checks)} AZ-* checks from az-assess-source-checks.json")

    # Build registry
    registry = OrderedDict()
    registry["schemaVersion"] = SCHEMA_VERSION
    registry["dataVersion"] = date.today().isoformat()
    sources = "data/scf-check-mapping.json + SecFrame/SCF/scf.db + data/scf-framework-map.json"
    if az_checks:
        sources += " + data/az-assess-source-checks.json"
    registry["generatedFrom"] = sources
    registry["checks"] = checks

    # Write output
    print(f"\nWriting registry to {args.output}")
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        json.dump(registry, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # Summary
    fw_counts = defaultdict(int)
    for c in checks:
        for k in c.get("frameworks", {}):
            fw_counts[k] += 1

    print(f"\n{'='*60}")
    print(f"Registry Build Summary (schema {SCHEMA_VERSION})")
    print(f"{'='*60}")
    print(f"Total checks:      {len(checks)}")
    print(f"Automated:         {sum(1 for c in checks if c.get('hasAutomatedCheck'))}")
    print(f"Manual:            {sum(1 for c in checks if not c.get('hasAutomatedCheck'))}")
    print(f"With impact rating:{sum(1 for c in checks if 'impactRating' in c)}")
    print(f"\nFramework coverage:")
    for k in sorted(fw_counts, key=lambda x: -fw_counts[x]):
        print(f"  {k:20s} {fw_counts[k]:4d} checks")

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for w in warnings:
            print(w)

    conn.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
