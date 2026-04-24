# CheckID Registry Schema

This document describes the `data/registry.json` schema (v2.22.0, SCF-based).

## Top-Level Structure

```json
{
  "schemaVersion": "2.22.0",
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
| `effort` | object | Implementation effort metadata (see below) |

## Effort Object

Every check includes an `effort` object derived algorithmically from existing fields and corrected by manual overrides in `data/effort-overrides.json`.

```json
"effort": {
  "complexity": 3,
  "isPhased": true,
  "phaseCount": 3,
  "disruptionRisk": true,
  "disruptionScope": "user-facing"
}
```

| Field | Type | Values | Description |
|---|---|---|---|
| `complexity` | integer | 1–5 | 1 = single config toggle; 5 = multi-team, multi-phase project |
| `isPhased` | boolean | — | True when sequential stages are required (e.g. DMARC: monitor → quarantine → reject) |
| `phaseCount` | integer | 1–n | Number of sequential phases; 1 when `isPhased` is false |
| `disruptionRisk` | boolean | — | True when the change risks disrupting users, services, or admins |
| `disruptionScope` | enum | `user-facing \| admin-only \| service` | Who bears the disruption risk; omitted when `disruptionRisk` is false |

**Complexity scale:**

| Score | Meaning |
|---|---|
| 1 | Toggle a setting, no user impact |
| 2 | Config change, limited blast radius |
| 3 | Multi-step config, some coordination needed |
| 4 | Org-wide policy change, staged rollout advisable |
| 5 | Multi-team project, mandatory phasing required |

**Manual overrides:** Add entries to `data/effort-overrides.json` to correct derived values. The `_rationale` field documents research findings and is stripped from registry output.

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

## v2.1.0 Changes (from v2.0.0)

| Change | Notes |
|---|---|
| New `effort` field on every check | Algorithmically derived; correctable via `data/effort-overrides.json` |
| New `data/effort-overrides.json` source file | Manual effort corrections with `_rationale` research annotations |

## v2.0.0 Migration Notes (from v1.x)

If you were consuming `registry.json` before v2.0.0:

| v1.x field | v2.0.0 equivalent |
|------------|-------------------|
| `frameworks.cisM365.controlId` | `frameworks.cis-m365-v6.controlId` |
| `impactSeverity` (top-level string) | `impactRating.severity` |
| *(no SCF data)* | `scf.*` object (new in v2.0.0) |
| `licensing` (string `"E3"`) | `licensing.minimum` (object) |

Framework keys changed from camelCase (`cisM365`) to kebab-case (`cis-m365-v6`).
