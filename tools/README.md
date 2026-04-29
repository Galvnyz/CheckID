# tools/

Consumer-side scripts that don't ship as part of the registry build pipeline. Each is run on the consumer's machine against their own data — output stays local and is gitignored where applicable.

## `import-cis-prose.py`

**Purpose.** Imports CIS-authored prose (Description, Rationale Statement, Impact Statement, Remediation Procedure, Audit Procedure, Additional Information) from your licensed copy of the CIS M365 v6 spreadsheet into a gitignored local artifact at `data/cis-m365-v6-authored.local.json`. Once present, `scripts/Build-Registry.py` merges this prose into each check's `frameworks.cis-m365-v6.cisAuthored` block during build.

**Why it's here, not in `scripts/`.** The CIS SecureSuite membership agreement permits members to use CIS Benchmark content for internal use within the member organization but does not permit public redistribution. CheckID respects this constraint: the public repository ships the *structure* (the `cisAuthored` schema block) and the *importer*, but never the prose itself. Each consumer populates their local artifact from their own licensed copy. See [`LICENSES/CIS-CONSUMER-SIDE.md`](../LICENSES/CIS-CONSUMER-SIDE.md) for the full posture.

**Prerequisites.**

- A licensed copy of `CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.xlsx` (CIS SecureSuite membership grants this)
- Python 3.11+ with `openpyxl` (`pip install openpyxl`)

**Default location for the XLSX.** `../SecFrame/CIS/CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.xlsx` (matches the existing `scripts/Build-CisM365Crosswalk.py` convention). Override with `--cis-dir`.

**Usage.**

```bash
# All fields
python tools/import-cis-prose.py

# Custom XLSX location
python tools/import-cis-prose.py --cis-dir /path/to/cis-files

# Subset of fields (e.g., audit procedure only for verifier UX)
python tools/import-cis-prose.py --include description,rationale

# Then rebuild the registry to merge the prose into your local registry.json
python scripts/Build-Registry.py
```

**Output.** `data/cis-m365-v6-authored.local.json` — gitignored. Contains a `_warning` field reminding consumers not to commit or redistribute. The output is not committed by accident because:

1. `.gitignore` excludes `*.local.json` and the specific path
2. The output file's `_warning` field surfaces the constraint at the data layer
3. CI does not produce or consume this file

**Field semantics.** All six fields are CIS-authored prose, distinct from CheckID's check-level authored content:

| Local field | CIS column | Distinct from CheckID's... |
|---|---|---|
| `description` | Description | (no CheckID equivalent — CheckID has `name` only) |
| `rationale` | Rationale Statement | check-level `rationale` (CheckID-authored, paraphrased) |
| `impact` | Impact Statement | check-level `impact` (CheckID-authored) |
| `remediation` | Remediation Procedure | check-level `remediation` (structured, channel-typed) |
| `audit` | Audit Procedure | `hasAutomatedCheck` (CheckID's automation status) |
| `additionalInfo` | Additional Information | (no CheckID equivalent) |

**Downstream consumers (M365-Assess, etc.).** When CheckID's local registry build includes `cisAuthored` blocks, downstream consumers can render side-by-side panels: CheckID-authored narrative for the practitioner audience + CIS-authored verbatim text for compliance evidence. The two streams stay distinct so consumers can label each appropriately.

**Re-running.** Re-run the importer after each CIS Benchmark version bump or whenever you've updated your licensed XLSX. The output is fully regenerated each run.

---

## `migrate-checkid-3.0.ps1`

PowerShell port of the v2.x → v3.0 registry migration parser. Converts a v2.x registry to v3.0 shape locally for consumer testing without depending on Python tooling. See [`docs/SCHEMA-MIGRATION-3.0.md`](../docs/SCHEMA-MIGRATION-3.0.md).
