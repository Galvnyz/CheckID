# Changelog

All notable changes to the CheckID module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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

## [Unreleased] - 2026-03-20

### Added

- 8 CA coverage gap analysis checks: CA-COVERAGE-001..008 (#80)
- 3 API permission severity checks: ENTRA-APPS-002..004 (#81)
- 5 enhanced PIM checks: ENTRA-PIM-006..010 (#82)
- 7 Entra security checks: ENTRA-APPS-005..006, ENTRA-APPREG-002..003, ENTRA-ADMIN-004, ENTRA-GROUP-004..005 (#83)
- Essential Eight framework mappings for all 23 new checks

### Removed

- All 94 MANUAL-CIS entries removed from the registry (169 checks remain, down from 250)
- `supersededBy` field removed from all registry entries (was on 81 checks)
- `SupersededBy` column removed from CSV data files
- `tests/search-registry.Tests.ps1` deleted

### Changed

- 14 former MANUAL-CIS checks converted to proper `{SERVICE}-{AREA}-{NNN}` identifiers
- `Import-ControlRegistry.ps1`, `Search-Registry.ps1`, and `Show-CheckProgress.ps1` removed — superseded by module cmdlets (`Get-CheckRegistry`, `Search-Check`, `Get-CheckAutomationGaps`) (#85)
- Updated documentation to reflect new check counts and removal of supersession tracking

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
