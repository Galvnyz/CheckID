#!/usr/bin/env python3
"""Build the master control registry (registry.json) from SCF as source of truth.

Reads scf-check-mapping.json (check → SCF assignments) and queries the SCF
SQLite database for all control metadata, framework mappings, risks, threats,
and assessment objectives. Produces registry.json v2.0.0.

Pipeline:
    scf-check-mapping.json       →  check definitions
           +
       scf.db                    →  SCF metadata + framework derivation
           +
    scf-framework-map.json       →  which frameworks to include
           +
    framework-titles.json        →  human-readable titles
           +
    az-assess-source-checks.json →  AZ-* checks (Azure ARM surface, optional)
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

SCHEMA_VERSION = "3.0.0"


# ---------------------------------------------------------------------------
# Strict JSON loader — defense in depth against the v2.22.0 dup-key bug class
# ---------------------------------------------------------------------------

def _strict_load_json(path: Path) -> object:
    """Load JSON, raising ValueError on duplicate keys.

    Python's json.load silently keeps the last value when an object contains
    duplicate keys. That bug class lost 4 framework overrides in v2.22.0 and
    was caught only by downstream cross-validation. This helper makes the
    same bug class structurally impossible at build time (mirrors the CI gate
    in scripts/Validate-NoDuplicateKeys.py).
    """
    def _reject_duplicates(pairs: list[tuple]) -> dict:
        seen: dict = {}
        for k, v in pairs:
            if k in seen:
                raise ValueError(
                    f"{path.name}: duplicate key '{k}'. "
                    "Merge the two entries instead of appending a second one."
                )
            seen[k] = v
        return seen

    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh, object_pairs_hook=_reject_duplicates)


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
            mappings[scf_id][fw_id].append(normalize_cmmc_id(ctrl_id.strip()))
    return dict(mappings)


# ---------------------------------------------------------------------------
# CIS M365 crosswalk and SCuBA NIST loaders
# ---------------------------------------------------------------------------

def load_cis_m365_crosswalk(repo_root: Path) -> dict:
    """{cisId: {title, nist800_53: [...], ...}} or {} if absent."""
    path = repo_root / "data" / "cis-m365-crosswalk.json"
    if not path.exists():
        return {}
    data = _strict_load_json(path)
    return data.get("controls", {})


def load_scuba_nist_mapping(repo_root: Path) -> dict:
    """{base_scuba_id: [nist_ids]} or {} if absent.

    Keys are version-stripped (e.g. 'MS.AAD.3.2') so they match regardless
    of which policy version the registry stores.
    """
    path = repo_root / "data" / "scuba-nist-mapping.json"
    if not path.exists():
        return {}
    data = _strict_load_json(path)
    return data.get("controls", {})


def merge_control_ids(primary: list[str], secondary_str: str) -> str:
    """Prepend primary IDs; append any secondary IDs not already present."""
    secondary = [x.strip() for x in secondary_str.split(";") if x.strip()]
    merged = primary + [x for x in secondary if x not in primary]
    return ";".join(merged)


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
    data = _strict_load_json(path)
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
    try:
        entries = _strict_load_json(source_path)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"WARN: az-assess-source-checks.json is invalid — skipping: {exc}")
        return []
    if not isinstance(entries, list):
        print(f"WARN: az-assess-source-checks.json must be a JSON array, got {type(entries).__name__} — skipping")
        return []

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
        for key in ("primaryControlId", "domain", "controlName", "controlDescription", "csfFunction"):
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

        remediation = entry.get("remediation", "")
        if remediation:
            check_obj["remediation"] = remediation

        impact = entry.get("impact", "")
        if impact:
            check_obj["impact"] = impact

        rationale = entry.get("rationale", "")
        if rationale:
            check_obj["rationale"] = rationale

        # Pass through inline overrides (v3.0+) — applied later by the
        # AZ enrichment loop in main(). Stored on check_obj as transient
        # build-time state; they're stripped before write since the
        # registry's frameworks/effort already reflect the applied data.
        if "frameworkOverrides" in entry:
            check_obj["frameworkOverrides"] = entry["frameworkOverrides"]
        if "effortOverride" in entry:
            check_obj["effortOverride"] = entry["effortOverride"]

        checks.append(check_obj)

    return checks


# ---------------------------------------------------------------------------
# CMMC profile derivation
# ---------------------------------------------------------------------------

# scf.db stores CMMC practice IDs without the separator dot, e.g. "ACL2.-3.1.1"
# instead of the standard "AC.L2-3.1.1". Normalize at load time.
_CMMC_MALFORMED = re.compile(r"^([A-Z]+)(L[123])\.-(.+)$")
_CMMC_LEVEL_TOKEN = re.compile(r"\.L([123])-")


def normalize_cmmc_id(ctrl_id: str) -> str:
    m = _CMMC_MALFORMED.match(ctrl_id)
    return f"{m.group(1)}.{m.group(2)}-{m.group(3)}" if m else ctrl_id


def derive_cmmc_profiles(control_id: str) -> list[str]:
    """Derive CMMC level profiles from a semicolon-delimited practice ID string.

    Returns the identity set of CMMC levels whose tokens appear in the
    controlId — e.g. "IA.L2-3.5.5" → ["L2"], "AC.L1-B.1.I;AC.L2-3.1.1" →
    ["L1","L2"]. Profiles describe what the practice IS, not the cumulative
    scope of assessments it participates in (see issue #248).
    """
    if not control_id:
        return []
    return sorted({f"L{n}" for n in _CMMC_LEVEL_TOKEN.findall(control_id)})


# ---------------------------------------------------------------------------
# Effort derivation
# ---------------------------------------------------------------------------

_SEVERITY_BASE = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 1}
_PHASED_COLLECTORS = {"DNS"}
_PHASED_NAME_KEYWORDS = {"enforcement", "quarantine", "reject"}
_USER_FACING_COLLECTORS = {"Entra", "CAEvaluator", "SharePoint", "Teams", "Forms", "PowerBI", "Intune"}
_EMAIL_COLLECTORS = {"ExchangeOnline", "DNS"}
_AZURE_COLLECTORS = {"AzAssess"}
_ADMIN_CATEGORIES = {"CLOUDADMIN", "ROLES", "AUDIT", "PRIVACCESS", "ADMIN", "LOGGING"}


def derive_effort(check_obj: dict, effort_override: dict | None) -> dict:
    """Derive effort fields for a check, then apply any inline override.

    `effort_override` is the per-check `effortOverride` dict from the source
    file (v3.0+). When present, its scalar fields override the derived
    defaults, and its `rationale` text becomes `effort.overrideReason` —
    preserved on the check (was silently stripped pre-v3.0).
    """
    check_id = check_obj.get("checkId", "")
    severity = check_obj.get("impactRating", {}).get("severity", "Medium")
    collector = check_obj.get("collector", "")
    category = check_obj.get("category", "").upper()
    name_lower = check_obj.get("name", "").lower()
    licensing_min = check_obj.get("licensing", {}).get("minimum", "E3")
    scf_weighting = (
        check_obj.get("scf", {}).get("relativeWeighting")
        or check_obj.get("impactRating", {}).get("scfWeighting")
    )

    # Complexity: severity base + adjustments, clamped to [1, 5]
    base = _SEVERITY_BASE.get(severity, 2)
    adj = 0
    if not check_obj.get("hasAutomatedCheck", True):
        adj += 1
    if licensing_min == "E5":
        adj += 1
    if scf_weighting and scf_weighting >= 8:
        adj += 1
    if category == "CONFIG":
        adj -= 1
    complexity = max(1, min(5, base + adj))

    # isPhased: conservative — only flag when high-confidence
    is_phased = (
        collector in _PHASED_COLLECTORS
        or any(kw in name_lower for kw in _PHASED_NAME_KEYWORDS)
        or complexity >= 4
    )
    phase_count = 3 if is_phased else 1

    # disruptionRisk + disruptionScope
    disruption_risk = False
    disruption_scope = None
    if severity in ("Critical", "High"):
        if collector in _USER_FACING_COLLECTORS:
            disruption_risk = True
            disruption_scope = "user-facing"
        elif collector in _EMAIL_COLLECTORS:
            disruption_risk = True
            disruption_scope = "service"
        elif collector in _AZURE_COLLECTORS:
            disruption_risk = True
            disruption_scope = "service"
        elif category in _ADMIN_CATEGORIES or any(
            kw in category for kw in ("AUDIT", "LOG", "ROLE", "ADMIN")
        ):
            disruption_risk = True
            disruption_scope = "admin-only"
    elif severity == "Medium" and collector in _USER_FACING_COLLECTORS:
        disruption_risk = True
        disruption_scope = "user-facing"

    # Apply inline override (only fields present in the override)
    if effort_override:
        complexity = effort_override.get("complexity", complexity)
        is_phased = effort_override.get("isPhased", is_phased)
        phase_count = effort_override.get("phaseCount", phase_count)
        disruption_risk = effort_override.get("disruptionRisk", disruption_risk)
        disruption_scope = effort_override.get("disruptionScope", disruption_scope)

    effort = OrderedDict([
        ("complexity", complexity),
        ("isPhased", is_phased),
        ("phaseCount", phase_count),
        ("disruptionRisk", disruption_risk),
    ])
    if disruption_risk and disruption_scope:
        effort["disruptionScope"] = disruption_scope
    if effort_override and effort_override.get("rationale"):
        # Preserve tribal knowledge from the override author (was '_rationale'
        # pre-v3.0, silently stripped from output).
        effort["overrideReason"] = effort_override["rationale"]

    return effort


_COLLECTOR_TAGS: dict[str, list[str]] = {
    "Entra": ["entra-id", "identity"],
    "CAEvaluator": ["conditional-access", "identity"],
    "ExchangeOnline": ["exchange-online", "email"],
    "DNS": ["dns", "email"],
    "Defender": ["defender", "email"],
    "Compliance": ["compliance", "purview"],
    "Intune": ["intune", "endpoint"],
    "SharePoint": ["sharepoint", "collaboration"],
    "Teams": ["teams", "collaboration"],
    "PowerBI": ["power-bi", "data"],
    "Purview": ["purview", "data-governance"],
    "StrykerReadiness": ["identity", "privileged-access"],
    "Forms": ["forms", "collaboration"],
    "PurviewRetention": ["purview", "data-governance", "retention"],
    "EntApp": ["app-registration", "identity"],
    "AzAssess": ["azure"],
}

_CATEGORY_TAGS: dict[str, list[str]] = {
    "MFA": ["mfa", "authentication"],
    "ENCRYPTION_AT_REST": ["encryption"],
    "ENCRYPTION_IN_TRANSIT": ["encryption", "tls"],
    "AUDIT": ["logging", "audit"],
    "LOGGING": ["logging", "audit"],
    "CLOUDADMIN": ["privileged-access", "admin"],
    "PRIVACCESS": ["privileged-access"],
    "ROLES": ["rbac", "privileged-access"],
    "GUESTACCESS": ["guest-access", "identity"],
    "SHARING": ["sharing", "data"],
    "RETENTION": ["retention", "data-governance"],
    "DLP": ["dlp", "data-governance"],
    "ANTIPHISHING": ["phishing", "email-security"],
    "ANTIMALWARE": ["malware", "endpoint"],
    "CA": ["conditional-access", "identity"],
    "APPREG": ["app-registration"],
    "NETWORK": ["network"],
    "CONFIG": ["configuration"],
}


def derive_tags(check_obj: dict) -> list[str]:
    """Derive functional tags from collector, category, and SCF domain."""
    collector = check_obj.get("collector", "")
    category = check_obj.get("category", "")
    domain = check_obj.get("scf", {}).get("domain", "")

    tags: list[str] = []
    tags.extend(_COLLECTOR_TAGS.get(collector, []))

    for cat_key, cat_tags in _CATEGORY_TAGS.items():
        if cat_key in category.upper():
            for t in cat_tags:
                if t not in tags:
                    tags.append(t)

    domain_lower = domain.lower().replace(" & ", "-").replace(" ", "-")
    if domain_lower and domain_lower not in tags:
        tags.append(domain_lower)

    return sorted(set(tags))


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


def apply_fw_overrides(
    frameworks: dict,
    check_overrides: dict,
    titles: dict,
) -> None:
    """Apply inline framework overrides to a check's frameworks dict in-place.

    `check_overrides` is the per-check `frameworkOverrides` dict from the
    source file (v3.0+). Every applied entry is tagged with
    `source: "manual-override"` so consumers can distinguish authored
    mappings from SCF-derived ones; an optional `reason` field is preserved
    when the override carries one.

    Mode semantics:
      - "replace" (default): fills when the key is absent; tags an existing
        SCF-derived entry as manual-override but does NOT overwrite its
        controlId. Right choice when the curator's mapping agrees with SCF
        and they only want to assert provenance.
      - "append": merges the override controlId into an existing entry.
        Use when both SCF's mapping and the curator's mapping should be
        expressed (separate criteria, multi-control coverage).
      - "force-replace": always builds a fresh entry from override data,
        discarding any SCF-derived controlId / title for this framework.
        Use when SCF's mapping is wrong for the framework — e.g., SCF maps
        SEA-18 to SOC 2 CC2.2 but CC2 is non-automatable per soc2-tsc.json,
        so we need to land on CC5 (Control Activities) instead.
    """
    for fw_key, fw_data in check_overrides.items():
        if not fw_data.get("controlId"):
            continue
        mode = fw_data.get("mode", "replace")
        if mode == "append" and fw_key in frameworks:
            existing_ids = [x.strip() for x in frameworks[fw_key].get("controlId", "").split(";") if x.strip()]
            frameworks[fw_key]["controlId"] = merge_control_ids(existing_ids, fw_data["controlId"])
            frameworks[fw_key]["source"] = "manual-override"
            if "reason" in fw_data:
                frameworks[fw_key]["reason"] = fw_data["reason"]
        elif mode == "force-replace" or fw_key not in frameworks:
            # force-replace discards any SCF-derived entry; "key not present"
            # has nothing to discard. Both build a fresh entry from override
            # data — same code path.
            entry = OrderedDict([("controlId", fw_data["controlId"])])
            title = resolve_title(fw_data["controlId"], fw_key, titles)
            if title:
                entry["title"] = title
            for extra_key in ("profiles", "evidenceType"):
                if extra_key in fw_data:
                    entry[extra_key] = fw_data[extra_key]
            entry["source"] = "manual-override"
            if "reason" in fw_data:
                entry["reason"] = fw_data["reason"]
            frameworks[fw_key] = entry
        else:
            # mode == "replace" (default) and key already present (SCF
            # derivation produced it). Keep the SCF-supplied controlId and
            # any extras (title, profiles), but tag the entry with
            # manual-override provenance — the curator's deliberate decision
            # to assert this mapping shouldn't be lost just because SCF
            # produced the same.
            frameworks[fw_key]["source"] = "manual-override"
            if "reason" in fw_data:
                frameworks[fw_key]["reason"] = fw_data["reason"]


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
            # Propagate cumulative baseline inheritance (Low ⊆ Moderate ⊆ High by NIST definition).
            # SCF 2026.1 maps controls to the *lowest* baseline tier only; we propagate upward.
            if "Low" in profiles:
                profiles += ["Moderate", "High"]
            elif "Moderate" in profiles:
                profiles += ["High"]
            order = ["Low", "Moderate", "High", "Privacy"]
            profiles = [p for p in order if p in profiles]
            frameworks[fw_key]["profiles"] = profiles

    # Derive CMMC L1/L2/L3 profiles from practice ID patterns in controlId
    if "cmmc" in frameworks:
        cmmc_profiles = derive_cmmc_profiles(frameworks["cmmc"].get("controlId", ""))
        if cmmc_profiles:
            frameworks["cmmc"]["profiles"] = cmmc_profiles

    # iso-27002 mirrors iso-27001 — same Annex A control IDs, different semantic label
    # (ISO 27001 = ISMS certification requirements; ISO 27002 = implementation guidance)
    if "iso-27001" in frameworks:
        frameworks["iso-27002"] = OrderedDict(frameworks["iso-27001"])

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
    check_mapping = _strict_load_json(mapping_path)

    print(f"Loading framework map from {fw_map_path}")
    fw_map = _strict_load_json(fw_map_path)

    print("Loading framework titles...")
    titles = load_framework_titles(title_path)

    # v3.0: framework and effort overrides are inlined per-check on
    # data/scf-check-mapping.json (M365) and data/az-assess-source-checks.json
    # (AZ-*). The standalone framework-overrides.json and effort-overrides.json
    # files were dissolved as part of the v3.0 schema restructure (#262 + #263).
    # Build-Registry now reads `frameworkOverrides` and `effortOverride`
    # directly from each check's source-file entry.

    # Load CIS M365 and SCuBA NIST sources
    cis_crosswalk = load_cis_m365_crosswalk(REPO_ROOT)
    if cis_crosswalk:
        print(f"Loaded CIS M365 crosswalk ({len(cis_crosswalk)} controls)")
    scuba_nist = load_scuba_nist_mapping(REPO_ROOT)
    if scuba_nist:
        print(f"Loaded SCuBA NIST mapping ({len(scuba_nist)} policies)")

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
            # Phase 1 of #347: pass-through enriched factual metadata when the
            # crosswalk has it. Fields are absent until the CIS XLSX is rebuilt
            # with the v1.2.0+ Build-CisM365Crosswalk.py.
            cis_meta = cis_crosswalk.get(cis_id, {})
            for key in ("sectionNumber", "assessmentStatus", "defaultValue"):
                if key in cis_meta:
                    cis_entry[key] = cis_meta[key]
            for key in ("cisControls", "cisSafeguardsByVersion", "references"):
                if key in cis_meta and cis_meta[key]:
                    cis_entry[key] = cis_meta[key]
            frameworks["cis-m365-v6"] = cis_entry

        # Enrich NIST 800-53 from M365-specific authoritative sources.
        # Priority: SCuBA (CISA, FedRAMP High) > CIS transitive path > SCF.
        # Each source adds IDs not already present; SCF-derived IDs stay as supplement.
        scuba_id_raw = cm.get("cisaScubaControlId", "")
        scuba_nist_ids: list[str] = []
        if scuba_id_raw:
            seen: set[str] = set()
            for sid in (s.strip() for s in scuba_id_raw.split(";") if s.strip()):
                base = re.sub(r'v\d+$', '', sid)
                for nid in scuba_nist.get(base, []):
                    if nid not in seen:
                        seen.add(nid)
                        scuba_nist_ids.append(nid)

        cis_nist_ids = cis_crosswalk.get(cis_id, {}).get("nist800_53", []) if cis_id else []

        combined = scuba_nist_ids + [x for x in cis_nist_ids if x not in scuba_nist_ids]
        if combined and "nist-800-53" in frameworks:
            frameworks["nist-800-53"]["controlId"] = merge_control_ids(
                combined, frameworks["nist-800-53"].get("controlId", "")
            )
            new_title = resolve_title(frameworks["nist-800-53"]["controlId"], "nist-800-53", titles)
            if new_title:
                frameworks["nist-800-53"]["title"] = new_title

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

        # Apply inline framework overrides (for gaps in SCF coverage)
        apply_fw_overrides(frameworks, cm.get("frameworkOverrides", {}), titles)

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

        check_obj["effort"] = derive_effort(check_obj, cm.get("effortOverride"))

        remediation = cm.get("remediation", "")
        if remediation:
            check_obj["remediation"] = remediation

        impact = cm.get("impact", "")
        if impact:
            check_obj["impact"] = impact

        rationale = cm.get("rationale", "")
        if rationale:
            check_obj["rationale"] = rationale

        references = cm.get("references", [])
        if references:
            check_obj["references"] = references

        tags = derive_tags(check_obj)
        if tags:
            check_obj["tags"] = tags

        checks.append(check_obj)

    # Merge AZ-Assess checks (Azure ARM surface — not SCF-database-derived).
    # Always SCF-derive and union with any hardcoded frameworks: hardcoded keys
    # win on collision so custom CMMC titles/controlIds stay as authored, but
    # missing frameworks (nist-800-171, soc2, fedramp, …) get filled in from SCF.
    # Prior behaviour skipped derivation whenever ANY hardcoded framework
    # existed, leaving 28 AZ-* checks with only their single hardcoded mapping.
    az_checks = load_az_assess_source_checks(REPO_ROOT)
    fw_derived = 0
    fw_enriched = 0
    for az in az_checks:
        hardcoded = az.get("frameworks") or {}
        scf_primary = az.get("scf", {}).get("primaryControlId", "")
        if scf_primary:
            derived = derive_frameworks(
                scf_primary, [],
                all_fw_mappings, fwid_to_key, baseline_fwids, titles,
            )
            # Union: keep all derived keys, then let hardcoded win on conflict.
            merged = {**derived, **hardcoded}
            az["frameworks"] = merged
            if not hardcoded:
                fw_derived += 1
            elif set(merged) - set(hardcoded):
                fw_enriched += 1
        # Apply inline overrides (same code path as SCF-driven checks).
        apply_fw_overrides(az.setdefault("frameworks", {}), az.get("frameworkOverrides", {}), titles)
        az["effort"] = derive_effort(az, az.get("effortOverride"))
        # Strip transient build-time fields — the override data is now
        # baked into az["frameworks"] and az["effort"], so the source
        # fields would only duplicate state and break schema validation.
        az.pop("frameworkOverrides", None)
        az.pop("effortOverride", None)
        az_tags = derive_tags(az)
        if az_tags:
            az["tags"] = az_tags
    checks.extend(az_checks)
    checks.sort(key=scf_sort_key)

    # Ensure CMMC profiles are set on all checks (AZ checks bypass derive_frameworks)
    for check in checks:
        fw = check.get("frameworks", {})
        if "cmmc" in fw and "profiles" not in fw["cmmc"]:
            p = derive_cmmc_profiles(fw["cmmc"].get("controlId", ""))
            if p:
                fw["cmmc"]["profiles"] = p
    if az_checks:
        print(f"Merged {len(az_checks)} AZ-* checks from az-assess-source-checks.json")
    if fw_derived:
        print(f"  Derived framework mappings for {fw_derived} checks with empty frameworks")
    if fw_enriched:
        print(f"  Enriched {fw_enriched} checks by unioning SCF-derived with hardcoded frameworks")

    # Build registry
    registry = OrderedDict()
    registry["schemaVersion"] = SCHEMA_VERSION
    registry["dataVersion"] = date.today().isoformat()
    sources = "data/scf-check-mapping.json + SecFrame/SCF/scf.db + data/scf-framework-map.json"
    if az_checks:
        sources += " + data/az-assess-source-checks.json"
    registry["generatedFrom"] = sources
    registry["checks"] = checks

    # Pre-write schema validation — defense in depth.
    # CI runs the same validation, but failing here prevents a malformed
    # registry from being written to disk (which would then propagate to
    # consumers who pull this branch locally before CI catches it).
    schema_validated = False
    schema_path = REPO_ROOT / "data" / "registry.schema.json"
    if schema_path.exists():
        try:
            import jsonschema  # soft import; skip with warning if missing
        except ImportError:
            print(
                "WARN: jsonschema not installed — skipping pre-write schema validation. "
                "CI will still validate. Install with: pip install jsonschema"
            )
        else:
            schema = _strict_load_json(schema_path)
            try:
                jsonschema.validate(registry, schema)
                print(f"  Pre-write schema validation: PASS ({len(checks)} checks)")
                schema_validated = True
            except jsonschema.ValidationError as exc:
                raise ValueError(
                    f"Built registry fails schema validation: {exc.message} "
                    f"at {list(exc.absolute_path)}. Refusing to write."
                ) from exc

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

    effort_complexity: dict[int, int] = defaultdict(int)
    for c in checks:
        effort_complexity[c.get("effort", {}).get("complexity", 0)] += 1
    phased_count = sum(1 for c in checks if c.get("effort", {}).get("isPhased"))
    disruptive_count = sum(1 for c in checks if c.get("effort", {}).get("disruptionRisk"))
    print(f"\nEffort distribution (complexity 1-5):")
    for score in sorted(effort_complexity):
        print(f"  Complexity {score}: {effort_complexity[score]:4d} checks")
    print(f"  Phased rollout:   {phased_count:4d} checks")
    print(f"  Disruption risk:  {disruptive_count:4d} checks")

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for w in warnings:
            print(w)

    conn.close()

    # One-line affirmation that all guards passed (#258).
    schema_status = "schema validated" if schema_validated else "schema validation SKIPPED"
    print(
        f"\n[OK] {len(checks)} checks, {len(fw_counts)} frameworks, "
        f"0 dup-key violations, {schema_status}. Done."
    )


if __name__ == "__main__":
    main()
