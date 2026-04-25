# CheckID

[![Checks](https://img.shields.io/badge/checks-1092-blue)](https://github.com/Galvnyz/CheckID/blob/main/data/registry.json)
[![Frameworks](https://img.shields.io/badge/frameworks-18-blue)](https://github.com/Galvnyz/CheckID/blob/main/SCHEMA.md#supported-frameworks-18)
[![Release](https://img.shields.io/github/v/release/Galvnyz/CheckID)](https://github.com/Galvnyz/CheckID/releases/latest)

Stable, unique identifiers for security configuration checks — mapped across compliance frameworks via the [Secure Controls Framework (SCF)](https://securecontrolsframework.com/).

## What Is CheckID?

CheckID gives every security check a permanent ID and maps it to controls across multiple compliance frameworks simultaneously. Instead of tracking "CIS 1.1.3" in one report and "AC-6(5)" in another, you reference `ENTRA-ADMIN-001` and get both — plus ISO 27001, HIPAA, SOC 2, FedRAMP, and more.

**Source of truth:** SCF (Secure Controls Framework) — 1,451 controls mapped across 261 compliance frameworks. Every CheckID check is anchored to an SCF control, which provides the bridge to all other frameworks.

**Format:** `{SERVICE}-{AREA}-{NNN}` (e.g., `ENTRA-ADMIN-001`, `DEFENDER-SAFELINKS-001`)

**Current coverage:**
- 278 checks across Microsoft 365 (Entra ID, Exchange Online, Defender, SharePoint, Teams, Intune, Compliance)
- 814 checks across Azure infrastructure sourced from 5 CIS benchmarks:
  - CIS Microsoft Azure Foundations Benchmark v5.0.0
  - CIS Microsoft Azure Compute Services Benchmark v2.0.0
  - CIS Microsoft Azure Database Services Benchmark v2.0.0
  - CIS Azure Kubernetes Service (AKS) Benchmark v1.8.0
  - CIS Microsoft Windows Server 2025 Benchmark v2.0.0
- 18 compliance frameworks mapped per check
- Full SCF metadata: maturity levels, assessment objectives, risks, and threats

The identifier format, registry schema, and framework mapping approach are platform-agnostic — new services and platforms can be added without breaking existing consumers.

## Quick Start

### Add as a git submodule (recommended)

```bash
git submodule add https://github.com/Galvnyz/CheckID.git lib/CheckID
```

```powershell
# Import the module from the submodule path
Import-Module ./lib/CheckID/CheckID.psd1

# Load all checks
$checks = Get-CheckRegistry

# Look up a specific check
$check = Get-CheckById 'ENTRA-ADMIN-001'
$check.name          # "Ensure that between two and four global admins are designated"
$check.frameworks    # All framework mappings with titles

# Search by framework, control ID, or keyword
Search-Check -Framework 'hipaa' -Keyword 'password'
Search-Check -ControlId 'AC-6'

# Query SCF metadata
Get-ScfControl 'ENTRA-ADMIN-001'  # domain, maturity, risks, threats, AOs
Search-CheckByScf -ScfId 'IAC-06'
Search-CheckByScf -Domain 'Endpoint Security'
```

### Clone the repo

```bash
git clone https://github.com/Galvnyz/CheckID.git
```

```powershell
Import-Module ./CheckID/CheckID.psd1
```

### CI cache sync

Consumer repos can sync `data/registry.json` and `data/frameworks/*.json` via CI rather than using a submodule. See [REFERENCES.md](REFERENCES.md) for the recommended CI workflow.

### Use the registry data directly

`data/registry.json` is a standalone JSON file — consume it from any language:

```python
import json
with open('lib/CheckID/data/registry.json') as f:
    registry = json.load(f)

for check in registry['checks']:
    if 'hipaa' in check['frameworks']:
        print(f"{check['checkId']}: {check['frameworks']['hipaa']['controlId']}")
```

### Generate a compliance matrix (XLSX)

```powershell
./lib/CheckID/scripts/Export-ComplianceMatrix.ps1 -AssessmentFolder ./output
```

## Supported Frameworks

All framework mappings are derived from the SCF database, supplemented by manual overrides for gaps in SCF coverage and for frameworks not in SCF (CIS M365, CISA ScuBA, STIG).

| Framework | Key | Coverage | Source | Profiles |
|-----------|-----|----------|--------|----------|
| NIST SP 800-53 Rev 5 | `nist-800-53` | 1,033 checks | SCF | Low, Moderate, High, Privacy |
| FedRAMP Rev 5 | `fedramp` | 1,033 checks | SCF | |
| CMMC 2.0 | `cmmc` | 1,067 checks | SCF | |
| SOC 2 Trust Services Criteria | `soc2` | 1,064 checks | SCF + override | |
| CIS Controls v8.1 | `cis-controls-v8` | 991 checks | SCF | |
| ISO/IEC 27001:2022 | `iso-27001` | 990 checks | SCF | |
| PCI DSS v4.0.1 | `pci-dss` | 1,013 checks | SCF | |
| NIST Cybersecurity Framework 2.0 | `nist-csf` | 801 checks | SCF + override | |
| Essential Eight (ASD) | `essential-eight` | 617 checks | SCF | ML1, ML2, ML3 |
| NIS2 | `nis2` | 300 checks | SCF | |
| HIPAA | `hipaa` | 477 checks | SCF | |
| MITRE ATT&CK v10 | `mitre-attack` | 863 checks | SCF | |
| CIS Microsoft 365 v6.0.1 | `cis-m365-v6` | 178 checks | Manual | E3-L1, E3-L2, E5-L1, E5-L2 |
| CISA SCuBA | `cisa-scuba` | 54 checks | Manual | |
| DISA STIG | `stig` | 13 checks | Manual | |
| EU GDPR | `gdpr` | 11 checks | SCF | |

### NIST 800-53 Baseline Profiles

NIST 800-53 Rev 5 defines 1,189 controls covering everything from physical security to cloud configuration. CheckID maps the subset that is verifiable through automated configuration assessment — across M365, Azure, and Windows Server.

Each registry entry's `nist-800-53` mapping includes a `profiles` array indicating which NIST baselines the mapped controls belong to (Low ⊆ Moderate ⊆ High by NIST definition):

| Baseline | Total Controls | CheckID-Assessable |
|----------|---------------|--------------------|
| Low | 149 | assessed by M365 + Azure + Windows checks |
| Moderate | 287 | assessed by M365 + Azure + Windows checks |
| High | 370 | assessed by M365 + Azure + Windows checks |
| Privacy | 96 | assessed by M365 checks |

Controls not covered include physical security (PE), contingency planning (CP), personnel security (PS), media protection (MP), and other organizational/procedural domains — CheckID assesses configuration state, not procedural compliance.

Consumers can use baseline profiles to report accurately: *"Of the 287 Moderate baseline controls, X are assessable and we check all X"* rather than the misleading *"X of 1,189 total controls."*

### Essential Eight Maturity Model

The [Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) is a set of baseline mitigation strategies published by the Australian Signals Directorate (ASD). It defines three maturity levels (ML1–ML3) across eight strategies:

| Strategy | Key | Description |
|----------|-----|-------------|
| Application Control | P1 | Prevent execution of unapproved programs |
| Patch Applications | P2 | Patch security vulnerabilities in applications |
| Configure Microsoft Office Macro Settings | P3 | Disable macros for users without a business requirement |
| User Application Hardening | P4 | Harden web browsers and applications |
| Restrict Administrative Privileges | P5 | Validate and monitor privileged access |
| Patch Operating Systems | P6 | Patch security vulnerabilities in operating systems |
| Multi-Factor Authentication | P7 | Require stronger authentication for sensitive systems |
| Regular Backups | P8 | Back up data, applications, and settings |

Each registry entry's `essential-eight` mapping uses control IDs in the format `ML{level}-P{strategy}` (e.g., `ML1-P4;ML2-P4;ML3-P4`). Of the eight strategies, seven (P1–P7) are assessable through M365 configuration export. P8 (Regular Backups) requires infrastructure-level assessment beyond M365 configuration state.

Essential Eight mappings are derived directly from SCF control mappings (framework_id=219).

## Repository Structure

```
CheckID/
├── data/                              Registry data
│   ├── registry.json                  Master registry (1,092 checks, 18 frameworks, schema v2.0.0)
│   ├── scf-check-mapping.json         M365 check → SCF control assignments (source of truth)
│   ├── az-assess-source-checks.json   Azure/Windows checks from CIS benchmarks (814 checks)
│   ├── cis-azure-section-map.json     CIS benchmark section → SERVICE-AREA prefix config
│   ├── scf-framework-map.json         SCF framework ID → CheckID key config
│   ├── framework-overrides.json       Manual framework mappings for SCF coverage gaps
│   ├── framework-titles.json          Human-readable control titles
│   └── frameworks/                    Framework definitions (18 JSON files)
├── candidates/                        Human-review staging area for new checks
│   ├── README.md                      Promote workflow documentation
│   └── az-candidates.json             Generated candidates (promote → az-assess-source-checks.json)
├── scripts/
│   ├── Build-Registry.py              Generates registry.json from SCF database + source checks
│   ├── Build-Registry.ps1             PowerShell wrapper for Build-Registry.py
│   ├── Build-CisAzureCandidates.py    Generates candidates from CIS benchmark CSVs (SecFrame)
│   ├── Build-ScfMigration.py          One-time NIST→SCF migration script
│   ├── Build-FrameworkTitles.py       Title lookup generator from OSCAL
│   ├── Export-ComplianceMatrix.ps1    XLSX multi-framework compliance report
│   └── Test-RegistryData.ps1          Data quality validation
├── tests/                             Pester 5.x tests
│   ├── registry-integrity.Tests.ps1   Schema + SCF validation tests
│   └── scf-mapping.Tests.ps1          SCF consistency tests
└── docs/
    ├── architecture.md                Mermaid architecture diagrams
    └── CheckId-Guide.md               Detailed system documentation
```

## Registry Schema (v2.0.0)

Each check in `registry.json` contains:

```json
{
  "checkId": "ENTRA-ADMIN-001",
  "name": "Ensure that between two and four global admins are designated",
  "category": "ADMIN",
  "collector": "Entra",
  "hasAutomatedCheck": true,
  "licensing": { "minimum": "E3" },
  "scf": {
    "primaryControlId": "IAC-21.3",
    "domain": "Identification & Authentication",
    "controlName": "Privileged Account Management...",
    "controlDescription": "Mechanisms exist to restrict...",
    "relativeWeighting": 10,
    "csfFunction": "Protect",
    "maturityLevels": { "cmm0_notPerformed": true, "cmm1_informal": true, "..." : "..." },
    "assessmentObjectives": [{ "aoId": "IAC-21.3_A01", "text": "..." }],
    "risks": ["R-AC-1", "R-AC-2"],
    "threats": ["NT-7", "MT-1"]
  },
  "frameworks": {
    "nist-800-53": { "controlId": "AC-6(5)", "title": "...", "profiles": ["Moderate", "High"] },
    "cis-m365-v6": { "controlId": "1.1.3", "profiles": ["E3-L1", "E5-L1"] },
    "iso-27001": { "controlId": "5.18;8.2" },
    "fedramp": { "controlId": "AC-6(5)" },
    "soc2": { "controlId": "CC6.1;CC6.3" }
  },
  "impactRating": { "severity": "Medium", "scfWeighting": 10 }
}
```

Top-level fields: `schemaVersion` (matches `CheckID.psd1` `ModuleVersion` — pinned, see VERSIONING.md), `dataVersion` (date), `generatedFrom`, `checks[]`.

## Data Quality Guarantees

What CI enforces about `registry.json`, what's tracked but not gated, and what consumers can safely assume — see [`docs/data-quality-guarantees.md`](docs/data-quality-guarantees.md).

## v3.0.0 Migration

If you're a downstream consumer (M365-Assess, M365-Remediate, StrykerScan, or other registry reader), v3.0.0 is a breaking schema change. See [`docs/SCHEMA-MIGRATION-3.0.md`](docs/SCHEMA-MIGRATION-3.0.md) for what changed, before/after examples, the backward-compat cmdlet, and a migration checklist.

## Rebuilding the Registry

The registry is built from two sources merged at build time:

- **M365 checks** — defined in `data/scf-check-mapping.json` with full SCF enrichment from `scf.db`
- **Azure/Windows checks** — curated in `data/az-assess-source-checks.json`; framework mappings derived from each check's SCF primary control at build time

```powershell
# Requires SecFrame/SCF/scf.db accessible locally
python scripts/Build-Registry.py
# Or via PowerShell wrapper:
./scripts/Build-Registry.ps1
```

### Adding Azure/Windows checks

New CIS benchmark checks flow through a candidate pipeline:

```
SecFrame (csv-exports/CIS/) → Build-CisAzureCandidates.py → candidates/az-candidates.json
                                                                       ↓ human review
                                             data/az-assess-source-checks.json → registry.json
```

Run locally:
```powershell
python scripts/Build-CisAzureCandidates.py --csv-dir C:/git/SecFrame/csv-exports/CIS --scf-db C:/git/SecFrame/SCF/scf.db
```

CI automatically regenerates candidates when SecFrame CSV exports change (via `secframe-azure-updated` repository dispatch → `.github/workflows/rebuild-cis-azure-candidates.yml`).

Then validate:

```powershell
./scripts/Test-RegistryData.ps1          # Data quality checks
Invoke-Pester ./tests/ -Output Detailed  # 35 integrity + SCF consistency tests
```

## Contributing

Contributions are welcome — especially new check-to-SCF mappings, additional service coverage, and tooling improvements.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/add-checks`)
3. Edit `data/scf-check-mapping.json` and run `python scripts/Build-Registry.py`
4. Run tests: `Invoke-Pester ./tests/` and `./scripts/Test-RegistryData.ps1`
5. Open a PR

**Areas we'd love help with:**
- Checks for platforms beyond M365 (AWS, GCP, Azure IaaS)
- Additional SCF-derived framework coverage (261 frameworks available)
- Language-specific client libraries (Python, Go, TypeScript)
- Documentation and guides

## License

[MIT](LICENSE)
