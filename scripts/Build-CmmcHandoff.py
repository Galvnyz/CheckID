"""Build data/cmmc-ez-handoff.json — EZ-CMMC handoff artifact.

Computes the gap between the full CMMC 2.0 L1/L2/L3 practice set (from SCF
database) and what CheckID currently covers (from registry.json). Outputs a
machine-readable artifact for the EZ-CMMC partner project listing every
practice CheckID cannot fully address, classified as:

  out-of-scope — no M365 equivalent (physical, HR, infra-level)
  partial      — M365 partially addresses; gap remains
  coverable    — future CheckID checks could address this practice

Usage:
    python scripts/Build-CmmcHandoff.py
    python scripts/Build-CmmcHandoff.py --scf-db C:/git/SecFrame/SCF/scf.db
"""
import argparse
import json
import re
import sqlite3
from collections import OrderedDict
from datetime import date
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent

parser = argparse.ArgumentParser(description="Build EZ-CMMC handoff artifact")
parser.add_argument("--scf-db", default=str(Path("C:/git/SecFrame/SCF/scf.db")), help="Path to scf.db")
args = parser.parse_args()

SCF_DB = Path(args.scf_db)
REGISTRY = REPO_ROOT / "data" / "registry.json"
OUTPUT = REPO_ROOT / "data" / "cmmc-ez-handoff.json"

L1_FW_ID = 99
L2_FW_ID = 101
L3_FW_ID = 102

conn = sqlite3.connect(SCF_DB)
cur = conn.cursor()


def normalize_id(raw_id: str) -> str:
    """Normalize CMMC practice IDs to standard dotted format.

    ATL2.-3.2.2  → AT.L2-3.2.2
    ACL2.-3.1.1  → AC.L2-3.1.1
    IAL3.-3.5.1E → IA.L3-3.5.1E
    AC.L1-B.1.I  → AC.L1-B.1.I  (already standard)
    """
    m = re.match(r'^([A-Z]{2,3})L(\d)\.-(.+)$', raw_id)
    if m:
        return f"{m.group(1)}.L{m.group(2)}-{m.group(3)}"
    return raw_id


def get_practices(fw_id: int) -> dict:
    cur.execute(
        "SELECT cm.framework_control_id, c.scf_id, c.scf_domain, c.control_name, c.description "
        "FROM control_mappings cm JOIN controls c ON c.scf_id = cm.scf_id "
        "WHERE cm.framework_id = ?",
        (fw_id,)
    )
    result = {}
    for row in cur.fetchall():
        raw_id, scf_id, domain, ctrl_name, desc = row
        norm = normalize_id(raw_id)
        if norm not in result:
            result[norm] = {
                "raw_id": raw_id,
                "scf_id": scf_id,
                "domain": domain,
                "name": ctrl_name,
                "description": (desc or "").strip()[:400],
            }
    return result


l1_practices = get_practices(L1_FW_ID)
l2_practices = get_practices(L2_FW_ID)
l3_practices = get_practices(L3_FW_ID)

# Build covered set — normalize all IDs from registry to canonical format
with open(REGISTRY, encoding="utf-8") as f:
    reg = json.load(f)

covered = set()
for check in reg["checks"]:
    fw = check.get("frameworks", {})
    if "cmmc" in fw:
        for part in fw["cmmc"].get("controlId", "").split(";"):
            part = part.strip()
            if part:
                covered.add(normalize_id(part))

print(f"L1 practices in SCF: {len(l1_practices)}")
print(f"L2 practices in SCF: {len(l2_practices)}")
print(f"L3 practices in SCF: {len(l3_practices)}")
print(f"Unique normalized CMMC IDs covered in registry: {len(covered)}")

# -----------------------------------------------------------------
# Classification: out-of-scope vs partial vs coverable
# Use normalized IDs throughout
# -----------------------------------------------------------------

OUT_OF_SCOPE = {
    # Physical & Environmental — no M365 equivalent
    "PE.L1-B.1.VIII", "PE.L1-B.1.IX",
    "PE.L2-3.10.1", "PE.L2-3.10.2", "PE.L2-3.10.3",
    "PE.L2-3.10.4", "PE.L2-3.10.5", "PE.L2-3.10.6",
    # Maintenance — physical device maintenance
    "MA.L2-3.7.1", "MA.L2-3.7.2", "MA.L2-3.7.4", "MA.L2-3.7.6",
    # Personnel Security — HR processes
    "PS.L2-3.9.1",
    # Security Awareness — org-wide training program (not M365 config)
    "AT.L2-3.2.2", "AT.L2-3.2.3",
    # Media protection — physical media sanitization/transport
    "MP.L2-3.8.5", "MP.L2-3.8.8",
    # Secure Engineering — network segmentation design (infra, not cloud config)
    "SC.L2-3.13.2", "SC.L2-3.13.4", "SC.L2-3.13.5",
    # Network segmentation — infrastructure-level
    "SC.L1-B.1.XI",
    # Information Assurance — SSPs/POA&Ms (documentation processes)
    "CA.L2-3.12.2", "CA.L2-3.12.4",
    # Audit time sync — infrastructure (NTP server management)
    "AU.L2-3.3.7",
    # Incident response exercises — org process
    "IR.L2-3.6.3",
}

PARTIAL = {
    # Network access control — CA policies cover some scope, not full segmentation
    "SC.L2-3.13.3", "SC.L2-3.13.14",
    # Identity assurance — some M365 coverage (PIV/FIDO2) but not complete
    "IA.L2-3.5.10", "IA.L2-3.5.11",
}

DOMAIN_REASONS = {
    "Physical & Environmental Security": (
        "Physical access controls require on-premises infrastructure management. "
        "No M365 configuration equivalent exists."
    ),
    "Maintenance": (
        "Controlled maintenance of organizational systems involves physical device access "
        "and media handling. Not addressable via M365 cloud configuration."
    ),
    "Human Resources Security": (
        "Personnel screening, role agreements, and termination processes are "
        "organizational HR practices. Not addressable via M365 configuration."
    ),
    "Security Awareness & Training": (
        "Organization-wide security awareness training programs are HR/process controls. "
        "M365 Defender Attack Simulation provides partial coverage but cannot satisfy "
        "the full practice requirement as a standalone M365 configuration."
    ),
    "Data Classification & Handling": (
        "Physical media sanitization, transport, and disposal requirements cannot "
        "be addressed by M365 cloud configuration alone."
    ),
    "Secure Engineering & Architecture": (
        "Network architecture design, system boundary enforcement, and network "
        "segmentation at the infrastructure level are outside M365's configuration surface."
    ),
    "Network Security": (
        "Network-level segmentation and traffic filtering require infrastructure "
        "controls (firewalls, routers, VLANs) beyond M365's configuration scope."
    ),
    "Information Assurance": (
        "Security assessment plans, Plans of Action & Milestones (POA&Ms), and "
        "system security plan maintenance are governance documentation processes, "
        "not M365 configuration controls."
    ),
    "Incident Response": (
        "Incident response testing, exercises, and tabletop simulations are "
        "organizational process requirements. M365 Defender provides IR tooling "
        "but not the programmatic testing practice itself."
    ),
}

PARTIAL_REASONS = {
    "SC.L2-3.13.3": (
        "Security engineering principles applied to M365 architecture are partially "
        "addressed by Secure Score and Defender recommendations, but full network "
        "architecture engineering for CUI environments requires broader controls."
    ),
    "SC.L2-3.13.14": (
        "Prohibiting remote activation of collaborative computing devices is partially "
        "addressed by Teams/M365 meeting policies, but physical-layer controls "
        "(camera/microphone hardware) are outside M365's scope."
    ),
    "IA.L2-3.5.10": (
        "Employing replay-resistant authentication is partially addressed by "
        "phishing-resistant MFA (FIDO2/Passkeys) in Entra ID, but full practice "
        "coverage requires PIV/CAC card deployment which is infrastructure-level."
    ),
    "IA.L2-3.5.11": (
        "Multi-factor authentication for network access is partially covered by "
        "Entra ID Conditional Access, but network-level authentication for "
        "non-web protocols (SSH, RDP, VPN) requires infrastructure controls."
    ),
}


def classify_and_reason(norm_id: str, info: dict):
    if norm_id in OUT_OF_SCOPE:
        domain = info["domain"]
        reason = DOMAIN_REASONS.get(domain,
            f"Practice in the {domain} domain requires controls outside the M365 configuration surface.")
        return "out-of-scope", True, reason
    if norm_id in PARTIAL:
        reason = PARTIAL_REASONS.get(norm_id,
            f"M365 partially addresses this practice; full compliance requires additional controls outside CheckID's scope.")
        return "partial", False, reason
    level = "L1" if ".L1-" in norm_id else ("L3" if ".L3-" in norm_id else "L2")
    return "coverable", False, (
        f"No CheckID check currently covers this {level} practice. "
        "Future M365 check development could address this gap."
    )


# Build gap entries
gaps = []

def process_level(practices_dict: dict, level_label: str):
    for norm_id, info in sorted(practices_dict.items()):
        if norm_id in covered:
            continue
        classification, ez, reason = classify_and_reason(norm_id, info)
        entry = OrderedDict([
            ("practiceId", norm_id),
            ("level", level_label),
            ("domain", info["domain"]),
            ("controlName", info["name"]),
            ("description", info["description"]),
            ("classification", classification),
            ("reason", reason),
            ("ezCmmc", ez),
        ])
        gaps.append(entry)


process_level(l1_practices, "L1")
process_level(l2_practices, "L2")
process_level(l3_practices, "L3")

conn.close()

# Summary
by_level = {}
by_class = {}
for g in gaps:
    by_level[g["level"]] = by_level.get(g["level"], 0) + 1
    by_class[g["classification"]] = by_class.get(g["classification"], 0) + 1

print(f"\nTotal gap practices: {len(gaps)}")
print(f"By level: {by_level}")
print(f"By classification: {by_class}")
print(f"ezCmmc=true (EZ-CMMC scope): {sum(1 for g in gaps if g['ezCmmc'])}")

covered_l1 = len(l1_practices) - by_level.get("L1", 0)
covered_l2 = len(l2_practices) - by_level.get("L2", 0)
covered_l3 = len(l3_practices) - by_level.get("L3", 0)

output = OrderedDict([
    ("schemaVersion", "1.0.0"),
    ("generated", str(date.today())),
    ("description", (
        "CMMC 2.0 practices not covered by CheckID, derived from SCF database gap analysis. "
        "Classification: 'out-of-scope' = no M365 equivalent (EZ-CMMC handles these); "
        "'partial' = M365 partially addresses, gap remains; "
        "'coverable' = future CheckID checks could address this practice."
    )),
    ("coverage", OrderedDict([
        ("totalL1Practices", len(l1_practices)),
        ("totalL2Practices", len(l2_practices)),
        ("totalL3Practices", len(l3_practices)),
        ("coveredL1", covered_l1),
        ("coveredL2", covered_l2),
        ("coveredL3", covered_l3),
        ("gapL1", by_level.get("L1", 0)),
        ("gapL2", by_level.get("L2", 0)),
        ("gapL3", by_level.get("L3", 0)),
    ])),
    ("practices", gaps),
])

with open(OUTPUT, "w", encoding="utf-8", newline="\n") as f:
    json.dump(output, f, indent=2, ensure_ascii=False)
    f.write("\n")

print(f"\nWrote {OUTPUT}")
