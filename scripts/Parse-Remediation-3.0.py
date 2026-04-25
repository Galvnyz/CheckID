#!/usr/bin/env python3
"""One-shot parser for v3.0.0: convert string `remediation` to structured shape.

Reads each check's free-form `remediation` string in:
    data/scf-check-mapping.json
    data/az-assess-source-checks.json
…and converts it to the v3.0 structured shape:
    {
        "powershell": {"command": "..."} | null,
        "portal":     {"path": "...", "steps": [...]} | null,
        "graph":      null,         # populated by future authoring (Backlog)
        "cli":        {"command": "..."} | null,
        "notes":      "..." | null
    }

Heuristic patterns (in order of preference):
    1. "Run: <ps-cmd>." or "Run: <ps-cmd>$"  → powershell
    2. "Or: <az|gcloud|aws> <cmd>"           → cli (alternative to portal)
    3. "<Service> admin center > <path>" or "<Portal> Portal > <path>"
       or "Computer Configuration > <path>"  → portal
    4. Everything else (and any unparseable leftover) → notes

Schema constraint (post-v3.0): at least one of {powershell, portal,
graph, cli, notes} must be non-null. Pure-prose remediation lands in
`notes`.

Usage (from repo root):
    python scripts/Parse-Remediation-3.0.py

Run once; verify the diff; commit. Subsequent rebuilds use the new
structured shape directly — Build-Registry.py is shape-agnostic.
"""

from __future__ import annotations

import json
import re
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA = REPO_ROOT / "data"

# Portal-name signals: when we see one of these followed by " > ",
# the rest of the navigation up to the next sentence-end is the portal path.
PORTAL_PREFIXES = [
    r"Microsoft Entra admin center",
    r"Entra admin center",
    r"Azure Portal",
    r"Microsoft Purview",
    r"Microsoft 365 admin center",
    r"M365 admin center",
    r"M365 Admin Center",
    r"Microsoft 365 Admin Center",
    r"Exchange admin center",
    r"Defender admin center",
    r"Defender portal",
    r"Security admin center",
    r"Microsoft Defender",
    r"Defender for Office",
    r"SharePoint admin center",
    r"Teams admin center",
    r"Teams Admin Center",
    r"Intune admin center",
    r"Intune",
    r"Power BI Admin portal",
    r"Power BI",
    r"Computer Configuration",
    r"User Configuration",
    r"Forms",
    r"security\.microsoft\.com\S*",
    r"compliance\.microsoft\.com\S*",
    r"entra\.microsoft\.com\S*",
    r"portal\.azure\.com\S*",
    r"admin\.microsoft\.com\S*",
]
PORTAL_RE = re.compile(
    # Match prefix + navigation. Stop at sentence boundary (period followed by
    # whitespace then uppercase letter, which signals a new sentence), at "Or:"
    # (CLI alternative coming), or end of string. This allows periods inside
    # the path itself — version numbers like "TLS 1.2" don't truncate the match.
    r"(?P<portal>(?:" + "|".join(PORTAL_PREFIXES) + r")\s+>\s+.+?)(?=\.\s+[A-Z]|\s+Or(?:\s+use)?:|$)",
    re.IGNORECASE | re.DOTALL,
)

# PowerShell pattern: "Run: <cmd>" or "Use: <cmd>" — capture greedily until we
# hit a known portal marker, "Or:", or end of string. Periods inside commands
# (e.g., ".Name" method calls, "(Get-AcceptedDomain).Name") are preserved.
_PS_TERMINATOR = (
    r"(?=\s+(?:" + "|".join(PORTAL_PREFIXES) + r")|"
    r"\s+Or(?:\s+use)?:|\s+Connect to|$)"
)
PS_RE = re.compile(
    r"(?:^|\s)Run:\s*(?P<cmd>.+?)" + _PS_TERMINATOR,
    re.IGNORECASE | re.DOTALL,
)

# CLI pattern: "Or: az ..." or "Or use: az ..." — Azure CLI / gcloud / aws.
CLI_RE = re.compile(
    r"(?:Or(?:\s+use)?:\s*)(?P<cmd>(?:az|gcloud|aws)\s+\S+(?:\s+[^.]+?))(?:\.\s|\.$|$)",
)

# Windows Group Policy pattern: "GPMC: <path-with-backslashes> > <setting>: <value>"
# Most WIN-* checks use this. The full string up to next sentence-end is the
# portal navigation; backslashes are path separators within the GP tree.
GPMC_RE = re.compile(
    r"GPMC:\s*(?P<path>[^.]+?)(?:\.\s|\.$|$)",
)

# Microsoft Graph API pattern: "PATCH https://graph.microsoft.com/..." with body.
# These are high-fidelity automation alternatives to portal navigation.
GRAPH_RE = re.compile(
    r"(?:via\s+)?Microsoft\s+Graph\s+API:?\s*(?P<verb>GET|POST|PATCH|PUT|DELETE)\s+(?P<endpoint>https?://graph\.microsoft\.com\S+)(?:\s+(?P<body>\{[^}]*\}))?",
    re.IGNORECASE,
)


def parse_remediation(text: str) -> dict:
    """Parse a remediation string into the v3.0 structured shape.

    Returns an OrderedDict so the JSON output preserves a consistent
    field order (powershell, portal, graph, cli, notes).
    """
    result: dict = OrderedDict()
    if not text or not text.strip():
        return result

    remaining = text.strip()

    # 1. Extract PowerShell first (most specific signal).
    ps_match = PS_RE.search(remaining)
    if ps_match:
        cmd = ps_match.group("cmd").strip().rstrip(".").strip()
        if cmd:
            result["powershell"] = OrderedDict([("command", cmd)])
        remaining = (remaining[: ps_match.start()] + " " + remaining[ps_match.end():]).strip()

    # 2. Extract Microsoft Graph API call.
    graph_match = GRAPH_RE.search(remaining)
    if graph_match:
        endpoint = graph_match.group("endpoint").strip()
        verb = graph_match.group("verb").upper()
        body = graph_match.group("body")
        entry: OrderedDict = OrderedDict([("endpoint", endpoint), ("method", verb)])
        if body:
            entry["body"] = body.strip()
        result["graph"] = entry
        remaining = (remaining[: graph_match.start()] + " " + remaining[graph_match.end():]).strip()

    # 3. Extract CLI (az/gcloud/aws).
    cli_match = CLI_RE.search(remaining)
    if cli_match:
        cmd = cli_match.group("cmd").strip().rstrip(".").strip()
        if cmd:
            result["cli"] = OrderedDict([("command", cmd)])
        remaining = (remaining[: cli_match.start()] + " " + remaining[cli_match.end():]).strip()

    # 4. Extract Windows Group Policy (GPMC) path. Most WIN-* checks use this.
    gpmc_match = GPMC_RE.search(remaining)
    if gpmc_match:
        path = "GPMC: " + gpmc_match.group("path").strip()
        raw_steps = re.split(r"\\|\s+>\s+", gpmc_match.group("path"))
        steps = [s.strip() for s in raw_steps if s.strip()]
        entry = OrderedDict([("path", path)])
        if len(steps) > 1:
            entry["steps"] = steps
        result["portal"] = entry
        remaining = (remaining[: gpmc_match.start()] + " " + remaining[gpmc_match.end():]).strip()

    # 5. Extract portal path (only when GPMC didn't already populate it).
    if "portal" not in result:
        portal_match = PORTAL_RE.search(remaining)
        if portal_match:
            path = portal_match.group("portal").strip().rstrip(".").strip()
            steps = [s.strip() for s in path.split(" > ")]
            if steps:
                entry = OrderedDict([("path", path)])
                if len(steps) > 1:
                    entry["steps"] = steps
                result["portal"] = entry
            remaining = (remaining[: portal_match.start()] + " " + remaining[portal_match.end():]).strip()

    # Whatever's left is notes (sentence cleanup: trim leading/trailing
    # punctuation and whitespace, collapse internal multi-spaces).
    leftover = re.sub(r"\s+", " ", remaining.strip().strip(".").strip())
    if leftover:
        result["notes"] = leftover

    # Re-order keys so JSON output is consistent: channels first, notes last.
    ordered = OrderedDict()
    for key in ("powershell", "portal", "graph", "cli", "notes"):
        if key in result:
            ordered[key] = result[key]
    return ordered


def convert_check(check: dict) -> bool:
    """Convert a single check's `remediation` field to structured shape.

    Returns True when conversion ran (text was a string), False when
    no conversion was needed (already structured or absent).
    """
    rem = check.get("remediation")
    if not isinstance(rem, str):
        return False
    if not rem:
        # Skip empty strings; the schema's required-field gate will catch
        # any missing remediation separately.
        return False
    check["remediation"] = parse_remediation(rem)
    return True


def main() -> int:
    m365_path = DATA / "scf-check-mapping.json"
    az_path = DATA / "az-assess-source-checks.json"

    if not m365_path.exists() or not az_path.exists():
        print("ERROR: source files not found", file=sys.stderr)
        return 1

    m365 = json.loads(m365_path.read_text(encoding="utf-8"))
    az = json.loads(az_path.read_text(encoding="utf-8"))

    converted_m365 = sum(1 for c in m365["checks"] if convert_check(c))
    converted_az = sum(1 for c in az if convert_check(c))

    # Distribution stats — useful for sanity-checking the parser.
    stats = defaultdict(int)
    for c in m365["checks"] + az:
        rem = c.get("remediation")
        if not isinstance(rem, dict):
            continue
        channels = [k for k in ("powershell", "portal", "graph", "cli") if k in rem]
        notes_only = not channels and "notes" in rem
        if not channels and "notes" not in rem:
            stats["empty"] += 1
        elif notes_only:
            stats["notes-only"] += 1
        else:
            stats["+".join(channels) or "no-channel"] += 1

    m365_path.write_text(json.dumps(m365, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    az_path.write_text(json.dumps(az, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"Converted: {converted_m365} M365 + {converted_az} AZ-* = {converted_m365 + converted_az} total")
    print()
    print("Channel distribution after parsing:")
    for shape, count in sorted(stats.items(), key=lambda kv: -kv[1]):
        print(f"  {shape:40s} {count:5d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
