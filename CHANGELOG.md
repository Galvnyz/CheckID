# Changelog

All notable changes to the CheckID module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.22.1] - 2026-04-24

### Fixed

- **`framework-overrides.json` duplicate-key silent data loss.** 4 check IDs
  (`ENTRA-AUTHMETHOD-004`, `ENTRA-PASSWORD-002`, `ENTRA-PASSWORD-003`,
  `ENTRA-PASSWORD-005`) had two override entries each; `json.load` kept only
  the last, silently discarding the first. Merged the pairs. Restores
  `soc2=CC6.1` on `ENTRA-PASSWORD-003` (flagged by M365-Assess CI) plus
  three lost `nist-csf=PR.AA-*` overrides.
- **AZ-`*` checks with hardcoded `cmmc` lost all SCF-derived frameworks.** The
  AZ enrichment path in `Build-Registry.py` skipped derivation whenever any
  hardcoded framework existed, leaving 26 AZ-`*` checks with only their single
  hardcoded mapping. Fix: union derived + hardcoded, hardcoded wins on
  collision so custom CMMC titles stay. Adds ~400 previously-missing
  framework mappings (nist-800-171, soc2, fedramp, hipaa, pci-dss, etc.).
- **`framework-overrides.json` now applies to AZ-`*` checks too.** The override
  pass previously ran only in the SCF-driven check-building path. Refactored
  into `apply_fw_overrides()` helper and invoked from both paths.
- **Added 9 AZ-`*` overrides** (`AZ-AKS-001`, `AZ-DEFENDER-001`/`002`,
  `AZ-GOVERNANCE-001`, `AZ-IDENTITY-002`/`003`, `AZ-KEYVAULT-001`/`002`/`003`)
  to close the `nist-800-171` and `soc2` gaps surfaced by post-fix scans.

### Added

- **Load-time guard** in `Build-Registry.py`: `framework-overrides.json` is
  parsed with an `object_pairs_hook` that raises `ValueError` on any duplicate
  key. Makes the v2.22.0 dup-key bug structurally impossible to recur.
- **Pester consistency tests** (framework pairing rules):
  - no duplicate check-id keys in `framework-overrides.json`
  - every CMMC-mapped check also has a `nist-800-171` mapping (CMMC L2
    practice IDs are literally NIST 800-171 controls)
  - every check mapping to NIST 800-53 AC/AU/IA/SC/SI families also has a
    SOC 2 mapping (mirrors M365-Assess's downstream consistency gate)

Closes #251 (typo fix confirmed shipped in v2.22.0; no regression).

## [2.22.0] - 2026-04-24

### Changed

- **Breaking (data semantics):** `frameworks.cmmc.profiles` now uses identity
  semantics — it lists only the levels whose tokens appear in `controlId`
  (e.g. `IA.L2-3.5.5` → `["L2"]`), not the cumulative superset
  (`["L1","L2"]`). Closes #248. Registry regenerated: 790 previously-uniform
  `[L1,L2]` entries are now `[L2]`; `[L2,L3]` is now representable (was
  impossible before). Downstream consumers that filtered by profile should
  review their logic.
- **Versioning policy:** `CheckID.psd1` `ModuleVersion` and `registry.json`
  `schemaVersion` are now pinned to each other, and both track the release
  tag. CI (Pester test in `tests/registry-integrity.Tests.ps1` and
  `scripts/Test-RegistryData.ps1`) fails if they diverge. Reconciles
  historical drift where tags reached v2.21.0 while these fields lagged at
  2.6.0 / 2.2.0. See VERSIONING.md.

## [2.6.0] - 2026-04-17

### Added

- 4 new CMMC L2 checks (Phase 4 — all remaining M365-assessable gaps), confirmed feasible via spike research:
  - `INTUNE-VPNCONFIG-001` — Prevent VPN Split Tunneling on Managed Devices (SC.L2-3.13.7 / CFG-03.4)
  - `INTUNE-WIFI-001` — WiFi Enterprise Authentication and Encryption (AC.L2-3.1.16 + AC.L2-3.1.17 / NET-15.1)
  - `CA-REMOTEDEVICE-001` — Remote Access Enforces Device Compliance via CA Policy (AC.L2-3.1.13 / NET-14.2)
  - `INTUNE-REMOTEVPN-001` — Always-On VPN for Managed Remote Access Routing (AC.L2-3.1.14 / NET-14.3)
- `docs/cmmc-l2-coverage-audit.md` — formal audit table for all 110 CMMC L2 practices with M365 vs EZ-CMMC disposition
- Override append mode in `Build-Registry.py` — `mode: "append"` in `framework-overrides.json` entries now merges controlIds into existing framework mappings (backwards-compatible; default behavior unchanged)

### Fixed

- `ENTRA-ADMINROLE-SEPARATION-001` CMMC mapping now correctly includes `SC.L2-3.13.3` alongside SCF-derived `AC.L2-3.1.5;AC.L2-3.1.6`, using the new override append mode

### Changed

- Registry: 302 → **306 checks** (+4)
- CMMC coverage: 295 → **299 checks** (+4); **83 of 107 L2 practices now covered**
- All remaining 24 L2 gaps are formally documented as EZ-CMMC handoff or out-of-scope (no M365-assessable L2 practices remain unaddressed)

## [2.5.0] - 2026-04-17

### Added

- 10 new CMMC L2 checks (Sprint 1 + Sprint 2 of Phase 3 continuation), closing assessable gaps from the Phase 3 coverage audit
  - `COMPLIANCE-COMMS-001` — Communication Compliance Policies Enabled (MON-01.3)
  - `COMPLIANCE-DLP-003` — DLP Policies Cover Exchange and SharePoint/OneDrive (NET-03.5)
  - `COMPLIANCE-LABELS-002` — Auto-Sensitivity Labeling Policies Configured (DCH-04.1)
  - `INTUNE-REMOVABLEMEDIA-001` — Removable Media Blocked on Managed Devices (DCH-10 / MP.L2-3.8.7)
  - `ENTRA-ADMINROLE-SEPARATION-001` — Admin Accounts Separated from Daily-Use Accounts (IAC-21.2 / SC.L2-3.13.3)
  - `ENTRA-CA-SESSIONFREQ-001` — CA Sign-In Frequency Enforcement (NET-07 / SC.L2-3.13.9)
  - `INTUNE-MOBILECODE-001` — PowerShell Execution Policy Restriction (END-10 / SC.L2-3.13.13)
  - `ENTRA-SESSIONAUTH-001` — Legacy Auth Block / Session Authenticity (NET-09 / SC.L2-3.13.15)
  - `SPO-CUIACCESS-001` — SharePoint External Sharing CUI Access Restriction (DCH-03 / MP.L2-3.8.2)
  - `BACKUP-ENABLED-001` — M365 Backup Protection for Backup CUI (BCD-11.4 / MP.L2-3.8.9)
- 5 CMMC framework overrides in `framework-overrides.json` for practices with no SCF→CMMC DB mappings (SC.L2-3.13.9/13/15, MP.L2-3.8.2/9)
- 10-spike M365 API feasibility research for Phase 3 gap candidates — 5 confirmed assessable, 5 documented as out-of-scope (network/OS/physical/procedural controls)

### Changed

- Registry: 292 → **302 checks** (+10)
- CMMC coverage: 285 → **295 checks** (+10)

## [2.1.0] - 2026-03-23

### Added

- `data/framework-overrides.json` — manual framework mappings for 59 checks where SCF lacks coverage (NIST CSF 2.0 and SOC 2 gaps)
- HIPAA HICP frameworks (Small/Medium/Large Practice) added to `scf-framework-map.json`
- Parent control fallback in `Build-Registry.py` — sub-controls (e.g., IAC-21.3) inherit parent (IAC-21) framework mappings when missing

### Changed

- All 15 frameworks now meet or exceed v1.1.0 coverage levels — zero regressions
- Framework coverage improvements vs v2.0.0:
  - HIPAA: 84 → 203 (+119, via HICP frameworks)
  - NIST CSF: 124 → 207 (+83, via parent fallback + overrides)
  - SOC 2: 202 → 222 (+20, via overrides)
  - MITRE ATT&CK: 187 → 213 (+26, via parent fallback)
  - ISO 27001: 193 → 210 (+17, via parent fallback)
  - CIS Controls: 174 → 199 (+25, via parent fallback)
  - Essential Eight: 82 → 103 (+21, via parent fallback)
  - CMMC: 206 → 215 (+9, via parent fallback)
  - PCI DSS: 205 → 213 (+8, via parent fallback)
- Updated all documentation for current coverage numbers

## [2.0.0] - 2026-03-22

### Added

- **SCF as source of truth**: Every check now has a required `scf{}` object with primaryControlId, domain, controlName, controlDescription, maturityLevels (CMM 0-5), assessmentObjectives, risks, and threats
- `Build-Registry.py` — new Python build script that queries SCF SQLite database directly
- `Build-ScfMigration.py` — one-time migration script bridging NIST 800-53 → SCF
- `data/scf-check-mapping.json` — new source of truth for check → SCF assignments (222 checks)
- `data/scf-framework-map.json` — configurable mapping of SCF framework IDs to CheckID keys
- `tests/scf-mapping.Tests.ps1` — 7 new SCF consistency tests
- `Get-ScfControl` cmdlet — returns SCF metadata for a check
- `Search-CheckByScf` cmdlet — search by SCF control ID or domain
- `-ScfId` and `-ScfDomain` parameters on `Search-Check`
- EU GDPR framework (8 checks) — 15th framework
- `impactRating.scfWeighting` field

### Removed

- `data/framework-mappings.csv` — replaced by SCF database queries
- `data/check-id-mapping.csv` — replaced by `scf-check-mapping.json`
- `data/standalone-checks.json` — absorbed into `scf-check-mapping.json`
- `data/derived-mappings.json` — all frameworks now derived directly from SCF
- `scripts/Build-DerivedMappings.py` — logic absorbed into `Build-Registry.py`
- `scripts/Import-NistBaselines.ps1` — NIST baselines derived from SCF

### Changed

- **Schema version**: 1.1.0 → 2.0.0 (breaking: new required `scf` field)
- **Module version**: 1.3.0 → 2.0.0 (new cmdlets, 9 exports)
- All framework mappings now derived from SCF database instead of manual CSVs
- CIS M365, CISA ScuBA, and STIG carried as manual overlays (not in SCF)
- Check sort order: SCF domain → SCF ID (was CIS section order)
- Registry `generatedFrom` references SCF sources
- Framework coverage changes (SCF-authoritative mappings): FedRAMP +55, CMMC +51, PCI DSS +50, GDPR +8, Essential Eight +25, CIS Controls +28
- ISO 27001 now includes ISO 27002 (Annex A controls) from SCF
- HIPAA uses both Administrative Simplification and Security Rule from SCF
- CI workflows updated for SCF-based validation

## [1.3.0] - 2026-03-20

### Added

- 8 CA coverage gap analysis checks: CA-COVERAGE-001..008 (#80)
- 3 API permission severity checks: ENTRA-APPS-002..004 (#81)
- 5 enhanced PIM checks: ENTRA-PIM-006..010 (#82)
- 7 Entra security checks: ENTRA-APPS-005..006, ENTRA-APPREG-002..003, ENTRA-ADMIN-004, ENTRA-GROUP-004..005 (#83)
- Essential Eight framework mappings for all 23 new checks
- Cross-repo CI workflows for SecFrame → CheckID → downstream cascade (#97)

### Removed

- All 94 MANUAL-CIS entries removed from the registry (222 checks total)
- `supersededBy` field removed from all registry entries (was on 81 checks)
- `SupersededBy` column removed from CSV data files
- `tests/search-registry.Tests.ps1` deleted
- PSGallery publishing infrastructure (#94)

### Changed

- 14 former MANUAL-CIS checks converted to proper `{SERVICE}-{AREA}-{NNN}` identifiers
- `Import-ControlRegistry.ps1`, `Search-Registry.ps1`, and `Show-CheckProgress.ps1` removed — superseded by module cmdlets (`Get-CheckRegistry`, `Search-Check`, `Get-CheckAutomationGaps`) (#85)
- Reconciled 53 downstream checks into registry (#95)

## [1.2.0] - 2026-03-17

### Added

- Framework definition JSONs for all 14 frameworks with unified schema
  - 4 existing definitions updated with `registryKey`, `csvColumn`, `displayOrder`, and `colors` fields
  - 7 new coverage-scored frameworks: NIST CSF 2.0, ISO 27001:2022, DISA STIG, PCI DSS v4.0.1, CMMC 2.0, HIPAA, CISA SCuBA
  - 3 derived frameworks: CIS Controls v8.1, FedRAMP Rev 5, MITRE ATT&CK v10
- `tests/framework-definitions.Tests.ps1` with comprehensive schema validation (158 new tests)
- `totalControls` field to SOC 2 (11) and Essential Eight (24) definitions
- Profile-level `colors` for CIS L2 and NIST 800-53 High/Privacy profiles
- Light and dark theme color support for all framework tags

### Changed

- Updated `CheckID.psd1` FileList to include all 14 framework definition files

## [1.1.0] - 2026-03-14

### Added

- `Get-FrameworkCoverage` cmdlet for framework-level coverage reporting
- Hash-indexed `Get-CheckById` for O(1) lookups
- Essential Eight (ASD) framework definition

### Fixed

- HIPAA encoding corruption in registry data
- Missing framework files in module FileList

## [1.0.0] - 2026-03-09

### Added

- Initial release with 233 security configuration checks
- 14 compliance framework mappings (CIS, NIST 800-53, NIST CSF, ISO 27001, DISA STIG, PCI DSS, CMMC, HIPAA, CISA SCuBA, SOC 2, Essential Eight, CIS Controls v8, FedRAMP, MITRE ATT&CK)
- `Get-CheckRegistry`, `Get-CheckById`, `Search-Check`, `Test-CheckRegistryData` cmdlets
- JSON Schema validation for registry.json
- CI pipeline with Python build script validation
