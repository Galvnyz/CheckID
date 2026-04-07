# CheckID Registry Schema

This document describes the `data/registry.json` schema (v2.0.0, SCF-based).

## Top-Level Structure

```json
{
  "schemaVersion": "2.0.0",
  "dataVersion": "YYYY-MM-DD",
  "generatedFrom": "scf-check-mapping.json + SecFrame/SCF/scf.db (SCF 2025.4)",
  "checks": [ ... ]
}
```

## Check Entry Fields

| Field | Type | Description |
|-------|------|-------------|
| `checkId` | string | Unique identifier. Pattern: `SERVICE-AREA-NNN` (e.g. `ENTRA-MFA-001`) |
| `name` | string | Human-readable check name |
| `category` | string | Functional area within the service (e.g. `MFA`, `SHARING`) |
| `collector` | string | Data collector service (e.g. `Entra`, `SharePoint`, `ExchangeOnline`) |
| `hasAutomatedCheck` | boolean | Whether M365-Assess can evaluate this check automatically |
| `licensing` | object | `{ "minimum": "E3" \| "E5" }` — minimum Microsoft 365 license required |
| `scf` | object | SCF control metadata (see below) |
| `frameworks` | object | Compliance framework mappings (see below) |
| `impactRating` | object | `{ "severity": "Critical\|High\|Medium\|Low\|Informational", "rationale": "...", "scfWeighting": 1-10 }` |

## SCF Object

```json
"scf": {
  "primaryControlId": "IAC-21.3",
  "additionalControlIds": ["IAC-15"],
  "domain": "Identity & Access Management",
  "controlName": "...",
  "controlDescription": "...",
  "relativeWeighting": 8,
  "csfFunction": "Protect",
  "maturityLevels": { "cmm0_notPerformed": true, ... },
  "assessmentObjectives": [ { "aoId": "IAC-21.3a", "text": "..." } ],
  "risks": ["R-AC-1", "R-AC-2"],
  "threats": ["T-AC-1"]
}
```

## Frameworks Object

Each key is a CheckID framework identifier. Values differ by framework type:

**SCF-backed frameworks** (auto-derived from scf.db):
```json
"nist-800-53": { "controlId": "AC-2", "title": "Account Management", "profiles": ["Moderate"] }
```

**Manual frameworks** (from scf-check-mapping.json):
```json
"cis-m365-v6": { "controlId": "1.1.1", "title": "Ensure Administrative accounts are cloud-only", "profiles": ["E3-L1", "E5-L1"] }
```

## Supported Frameworks (18)

| Key | Framework | Source |
|-----|-----------|--------|
| `cis-m365-v6` | CIS Microsoft 365 Foundations v6.0.1 | Manual |
| `cisa-scuba` | CISA SCuBA M365 Baselines | Manual |
| `stig` | DISA STIG | Manual |
| `nist-800-53` | NIST 800-53 R5 | SCF (fw_id 45) |
| `nist-csf` | NIST CSF 2.0 | SCF (fw_id 69) |
| `nist-800-171` | NIST 800-171 R2 | SCF (fw_id 62) |
| `iso-27001` | ISO 27001:2022 | SCF (fw_id 24,25) |
| `iso-27017` | ISO 27017:2015 | SCF (fw_id 26) |
| `pci-dss` | PCI DSS 4.0.1 | SCF (fw_id 72) |
| `cmmc` | US CMMC 2.0 | SCF (fw_id 93,95,96) |
| `hipaa` | US HIPAA | SCF (fw_id 130–134) |
| `soc2` | AICPA SOC 2 TSC | SCF (fw_id 1) |
| `fedramp` | US FedRAMP R5 | SCF (fw_id 118) |
| `cis-controls-v8` | CIS Controls v8.1 | SCF (fw_id 4) |
| `essential-eight` | Australia Essential Eight | SCF (fw_id 219) |
| `mitre-attack` | MITRE ATT&CK 10 | SCF (fw_id 33) |
| `gdpr` | EU GDPR | SCF (fw_id 175) |
| `nis2` | EU NIS2 Directive | SCF (fw_id 176) |

## v2.0.0 Migration Notes (from v1.x)

If you were consuming `registry.json` before v2.0.0:

| v1.x field | v2.0.0 equivalent |
|------------|-------------------|
| `frameworks.cisM365.controlId` | `frameworks.cis-m365-v6.controlId` |
| `impactSeverity` (top-level string) | `impactRating.severity` |
| *(no SCF data)* | `scf.*` object (new in v2.0.0) |
| `licensing` (string `"E3"`) | `licensing.minimum` (object) |

Framework keys changed from camelCase (`cisM365`) to kebab-case (`cis-m365-v6`).
