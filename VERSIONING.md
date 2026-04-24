# Versioning

CheckID is a shared library consumed by multiple downstream projects. This document defines the versioning contract so consumers can pin safely.

## Version Types

| Version | Location | Format | Bumps when |
|---------|----------|--------|------------|
| **App / Module** | `CheckID.psd1` `ModuleVersion` | semver | PowerShell module API changes **or** registry shape/semantic changes |
| **Schema** | `registry.json` `schemaVersion` | semver | **Always equals ModuleVersion** (enforced by CI) |
| **Data** | `registry.json` `dataVersion` | YYYY-MM-DD | Every `Build-Registry.py` run (informational only) |

### Coupling policy

`schemaVersion` is **pinned** to `ModuleVersion`: both are treated as one release
version for the CheckID package. Either file's version SHOULD NOT drift; CI fails
if they diverge (`tests/registry-integrity.Tests.ps1`). Bump both in the same PR.

Why a single version: consumers pin CheckID as a whole (module API + registry
data shape). Splitting the two added cognitive overhead with no real benefit —
any schema change forces a module-version review, and vice versa.

**Historical note:** Prior to v2.22.0, git tags and GitHub releases ran ahead of
`ModuleVersion` and `schemaVersion` (tags reached v2.21.0 while the psd1 still
said `2.6.0` and the registry said `2.2.0`). As of v2.22.0, **all three
track the release tag** — bumping the release tag means bumping `ModuleVersion`
and `schemaVersion` to the same value in the same PR.

### Package Version (`ModuleVersion` == `schemaVersion`)

Governs both the PowerShell module API **and** the `registry.json` shape/semantics.
Bump the highest category that applies — any major-level trigger forces a major bump
for both.

| Bump | When |
|------|------|
| **Major** | Removed/renamed exported functions; changed parameter signatures; removed/renamed registry fields; changed check-object shape or framework key names; breaking change to the meaning of an existing field (e.g. issue #248: CMMC `profiles` semantics flip) |
| **Minor** | New exported functions; new optional parameters on existing functions; new registry fields or framework mappings; new metadata properties |
| **Patch** | Bug fixes in existing functions; performance improvements; data-only corrections (encoding fixes, title updates, non-semantic profile corrections) |

### Data Version (`registry.json` `dataVersion`)

YYYY-MM-DD date that bumps on every `Build-Registry.py` run. Purely informational —
never pin to it.

## Breaking Change Examples

| Change | Bump | Breaking? |
|--------|------|-----------|
| Rename `checkId` to `id` | Major | Yes |
| Remove `Search-Check` cmdlet | Major | Yes |
| Flip CMMC `profiles` from cumulative to identity semantics (#248) | Major | Yes |
| Add `gdpr` framework to checks | Minor | No |
| Add `Get-FrameworkCoverage` cmdlet | Minor | No |
| Add `-Profile` param to `Search-Check` | Minor | No |
| Fix HIPAA encoding | Patch | No |

## Consumer Guidance

- **Pin to major version**: `RequiredModules = @(@{ModuleName='CheckID'; ModuleVersion='2.22.0'})`
- **Schema compatibility**: `registry.json` `schemaVersion` always matches the module
  `ModuleVersion` — comparing either is equivalent.
- **Data version is informational only** — never pin to it.

## Downstream Consumers

| Consumer | Integration | Depends on |
|----------|-------------|------------|
| M365-Assess | PSGallery module (planned) | registry.json structure, module API |
| M365-Remediate | Submodule (build-time) | registry.json `checkId` field, `frameworks` object |
| Stitch-M365 | Submodule | registry.json structure, module API |
| Darn | Submodule (planned) | registry.json structure (C# deserialization) |
