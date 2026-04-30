# Changelog

All notable changes to the CheckID module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Documentation

- **`docs/audits/conditional-access.md`** — first domain audit under the v3.4.0 umbrella ([#326](https://github.com/Galvnyz/CheckID/issues/326)). Resolves spike [#327](https://github.com/Galvnyz/CheckID/issues/327). Catalogs **42 canonical CA patterns** across 5 sub-domains (foundational, surface-area, external/guest, anti-pattern, modern 2024-2026), maps them against the registry's 26 existing CA-related checks, identifies **17 coverage gaps** to file as `feat:` issues, **6 narrative-refresh candidates**, and one consolidation opportunity (`ENTRA-CA-001` ↔ `CA-LEGACYAUTH-001`). Includes an AiTM defense matrix mapping CA controls to which adversary-in-the-middle phishing tradecraft they break, and a Graph endpoint detection-method appendix. Sets the methodology template for the remaining 13 v3.4.0 domain spikes.
- **`docs/audits/privileged-access.md`** — second domain audit. Resolves spike [#328](https://github.com/Galvnyz/CheckID/issues/328). Catalogs **34 canonical privileged-access patterns** across 5 sub-domains (activation hygiene, assignment hygiene, tier separation, emergency access, anti-patterns), maps them against the registry's 15 existing privileged-access checks, identifies **15 gap CheckIDs**, **3 narrative-refresh candidates**, and one structural gap: CheckID has no canonical Tier-0 role inventory, so a `data: introduce data/role-tiers.json` issue is filed to give all consumers (M365-Assess, Az-Assess, EZ-CMMC) one source of truth. Threat-pattern map covers standing-credential abuse, AiTM privilege persistence, external-tenant compromise cascading, and break-glass key compromise.
- **`docs/audits/sharepoint-onedrive.md`** — eighth domain audit. Resolves spike [#337](https://github.com/Galvnyz/CheckID/issues/337). Catalogs **30 unique patterns** across 6 sub-domains (tenant-level sharing, external user controls, site-level overrides, CA integration, OneDrive specifics, anti-patterns). Maps against the 27 existing `SPO-*` checks. Identifies **8 gap CheckIDs**, **4 narrative-refresh candidates**, and one possible **inversion bug** on `SPO-SYNC-002` (the name "Mac Sync App Enabled" sounds like it confirms Mac sync IS enabled, but the audit verdict should be checking it's RESTRICTED — worth re-reading implementation, may need to file as bug). Detection appendix documents the SPO PowerShell + Graph beta split with 8 edge cases (SharingCapability enum vs UI labels confusion, OneDrive-vs-SharePoint distinction, tenant-sharing-as-ceiling invariant, ConditionalAccessPolicy `LimitedAccess` requiring paired CA session control, sensitivity-label site protection cross-reference).
- **`docs/audits/defender-for-office.md`** — seventh domain audit. Resolves spike [#332](https://github.com/Galvnyz/CheckID/issues/332). Catalogs **31 unique patterns** across 7 sub-domains (preset adoption, anti-phishing, Safe Attachments, Safe Links, anti-malware, anti-spam, anti-patterns). Maps against the 27 existing MDO-related checks across `DEFENDER-*` and `EXO-*` namespaces. Identifies **18 gap CheckIDs** (MDO has many discrete per-property gaps), **5 narrative-refresh candidates**, and **3 namespace consolidation chores** (`DEFENDER-ANTIPHISH-001` ↔ `EXO-ANTIPHISH-001`, similar for anti-spam + malware — likely duplicates that should pick one namespace). Notes a **detection-method shift**: this is the first audit where detection lives almost entirely in Exchange Online + Security & Compliance PowerShell, not Microsoft Graph; the appendix focuses on the EXO-PS contract with 8 edge cases (policy + rule pair contract, effective-policy-per-user evaluation, preset-vs-custom reconciliation, Quarantine bit-flag semantics, etc.).
- **`docs/audits/external-collaboration.md`** — sixth domain audit. Resolves spike [#333](https://github.com/Galvnyz/CheckID/issues/333). Catalogs **17 canonical patterns** across 4 sub-domains (cross-tenant access defaults, per-partner overrides, guest user controls, federation). Maps against the registry's 8 Entra-namespace external-collaboration checks plus **3 boundary checks** (`AZ-IDENTITY-015/016/041` are Entra controls in the AZ namespace, mirroring the boundary issue surfaced in #331). Identifies **10 gap CheckIDs**, **3 narrative-refresh candidates**, **1 boundary chore** (reconcile `AZ-IDENTITY-015/016/041` with `ENTRA-GUEST-001/002/003`), and **1 namespace duplication chore** (`PBI-*` and `POWERBI-*` appear to cover the same Power BI guest/sharing controls — consolidation needed; flagged for #336 audit). Workload-side checks (SPO, Teams, EXO, Forms, Power BI) cross-referenced and deferred to their domain spikes.
- **`docs/audits/token-session-security.md`** — fifth domain audit. Resolves spike [#331](https://github.com/Galvnyz/CheckID/issues/331). Catalogs **22 canonical token + session security patterns** across 5 sub-domains (CAE coverage, sign-in frequency + session controls, Token Protection, refresh token + revocation, anti-patterns). Maps against the registry's 8 M365-scope token/session checks plus 1 boundary-issue check (`AZ-IDENTITY-039` is in the AZ namespace but governs Entra Token Protection). Identifies **9 gap CheckIDs**, **1 narrative-refresh candidate**, **2 cross-spike CheckID consolidations** (TP-Edge with #327; SP credential rotation with #328), and **1 boundary chore** (relocate `AZ-IDENTITY-039` to `ENTRA-TOKEN-PROTECTION-001`). Completes the AiTM kill-chain layered defense matrix started in #327 — token theft + session reuse stages now have explicit catalog of which controls disrupt them.
- **`docs/audits/authentication-methods.md`** — fourth domain audit. Resolves spike [#330](https://github.com/Galvnyz/CheckID/issues/330). Catalogs **23 canonical authentication methods patterns** across 5 sub-domains (strong methods deployed, onboarding readiness, weak/legacy method state, configuration nuance, anti-patterns) and maps them against the registry's 8 `ENTRA-AUTHMETHOD-*` checks plus 3 cross-domain checks. Identifies **8 gap CheckIDs**, **4 narrative-refresh candidates**, and 2 cross-spike CheckID consolidations (admin-weak-method shared with #328/#329; break-glass MFA-registered shared with #328). Threat-pattern map maps each control to the AiTM kit / push-bombing / SIM-swap / counterfeit-FIDO2 / TAP-interception tradecraft it defeats. Detection appendix documents 8 Graph endpoint edge cases, particularly `policyMigrationState` as the foundational gating signal for everything else in the auth methods picture.
- **`docs/audits/mfa-enforcement.md`** — third domain audit. Resolves spike [#329](https://github.com/Galvnyz/CheckID/issues/329). Catalogs **27 canonical MFA enforcement patterns** plus a **mechanism reconciliation guide** for the multi-mechanism (Security Defaults, per-user MFA legacy, CA-driven, MS-managed, authentication strength) overlap problem with a per-user decision tree. Maps against 16 M365-side MFA-related checks across `CA-MFA-*`, `CA-PHISHRES-*`, `ENTRA-MFA-*`, `ENTRA-AUTHMETHOD-*`, `ENTRA-PERUSER-*`, `ENTRA-SECDEFAULT-*`, `ENTRA-ADMIN-004`. Identifies **9 gap CheckIDs**, **5 narrative-refresh candidates**, **2 cross-spike CheckID consolidations** (#327 `CA-LEGACY-MFA-GRANT-001` ↔ this audit's `ENTRA-MFA-STRENGTH-ADOPTION-001`; #327 `CA-MSMANAGED-MFA-MANDATE-001` ↔ `ENTRA-MSMANAGED-MFA-001`), and one Azure-vs-M365 audit boundary chore (`AZ-IDENTITY-030` may duplicate `CA-MFA-ALL-001`). Threat map covers push-bombing, AiTM phishing, MFA registration spoofing, hybrid-mechanism gaps, cross-tenant trust abuse.
- **`docs/audits/intune.md`** — eleventh domain audit. Resolves spike [#334](https://github.com/Galvnyz/CheckID/issues/334). Catalogs **31 unique patterns** across 6 sub-domains (compliance policy fundamentals, configuration profiles + baselines, App Protection Policies / MAM, Conditional Access integration, Autopilot + enrollment, anti-patterns). Maps against the 20 existing `INTUNE-*` checks. Identifies **11 gap CheckIDs** (largest cluster: 5 in MAM/App Protection — the most under-covered area in the existing Intune namespace), **2 narrative-refresh candidates**. 4 cross-spike CheckIDs already covered by #327's CA device-compliance / mobile-MAM checks. Detection appendix documents the Microsoft Graph `/deviceManagement` + `/deviceAppManagement` contract with 8 edge cases (per-platform `@odata.type` discrimination, most-restrictive-wins compliance evaluation, three-shape configuration model — Settings Catalog vs legacy templates vs intents, security baseline version comparison for drift detection, MAM-vs-MDM org-strategy distinction, Autopilot ESP blocking-timeout setting, Multi-Admin Approval scope configuration).
- **`docs/audits/teams.md`** — ninth domain audit. Resolves spike [#340](https://github.com/Galvnyz/CheckID/issues/340). Catalogs **30 unique patterns** across 6 sub-domains (external access/federation, B2B Direct Connect, guest access, meeting policies, app + custom integration, anti-patterns). Maps against the 20 existing `TEAMS-*` checks. Identifies **8 gap CheckIDs** (custom app sideloading restriction, E2EE meetings, federation/XTAS drift detection, shared channel creation, guest message-delete + calling controls, anonymous-meeting + lobby-bypassed combo), **3 narrative-refresh candidates**, and **3 cross-spike consolidations** (#333 B2B Direct Connect, #327/#333 guest MFA, #335 sensitivity labels). Central deliverable is an **external-surface reconciliation guide** distinguishing the four distinct external surfaces (federation, B2B Direct Connect, guest access, anonymous meeting join) that share names but have different threat models. Threat-pattern map names Midnight Blizzard / Storm-0539 Teams chat phishing tradecraft. Completes the **collaboration triad** of v3.4.0 audits — #332 (MDO content protection) + #337 (SPO file-share) + #340 (Teams chat/meeting/app).
- **`docs/audits/mail-flow.md`** — tenth domain audit. Resolves spike [#339](https://github.com/Galvnyz/CheckID/issues/339). Catalogs **27 unique patterns** across 5 sub-domains (transport rule hygiene, connector posture, accepted + remote domains, mailbox-level forwarding, anti-patterns). Maps against the 9 existing mail-flow-scope checks (`EXO-TRANSPORT-*`, `EXO-FORWARD-001`, `EXO-DIRECTSEND-001`, `EXO-AUTH-002`, `DNS-SPF-001`, `DNS-DKIM-001`, `DNS-DMARC-001`, `EXO-EXTTAG-001`). Identifies **12 gap CheckIDs**, **3 narrative-refresh candidates**, and proposes a new **`data/transport-rule-actions.json`** reference file (mirrors the canonical-data-file pattern from `data/role-tiers.json` + `data/microsoft-first-party-appids.json` proposals). Central deliverable is the **three-surface auto-forwarding reconciliation guide** — auto-forwarding to external is governed independently by Remote Domain default `AutoForwardEnabled`, outbound spam policy `AutoForwardingMode`, and per-mailbox `DeliverToMailboxAndForward`; all three must align for blocking to be effective. Threat-pattern map covers Storm-X actor server-side mailbox persistence (hidden inbox rules per Microsoft DART; MITRE T1564.008), mass external auto-forwarding from compromised account, open mail relay, header-rewrite spoofing, SMTP AUTH password spray, and DMARC-bypass spoof exfil. Detection appendix documents 11 EXO-PS cmdlets and 8 edge cases including transport rule action enum classification, per-mailbox iteration scaling, hidden-name detection, and DKIM severity reassessment recommendation.

### Added

- **CIS M365 v6 phase-1 enrichment** ([#347](https://github.com/Galvnyz/CheckID/issues/347)). Crosswalk schema bumped to **v1.2.0** with optional factual metadata fields per recommendation: `sectionNumber`, `assessmentStatus` (Manual / Automated), `cisSafeguardsByVersion` (v8 + v7 safeguards grouped by Implementation Group with `applicableIGs`), `defaultValue` (Microsoft factory state), and `references` (citation URLs). `scripts/Build-CisM365Crosswalk.py` reads these from the CIS XLSX when columns are present; `scripts/Build-Registry.py` passes them through onto each check's `frameworks.cis-m365-v6` block. `data/registry.schema.json` extended with the new optional properties + a `cisSafeguardIGBreakdown` `$def`. Pester gates added to validate shape when populated. **CIS-authored prose (Description, Rationale Statement, Impact Statement, Remediation Procedure, Audit Procedure, Additional Information) is deferred pending licensing resolution** — this PR lands the schema + ingestion infrastructure; a phase-2 PR populates prose once the CC BY-NC-SA / MIT compatibility question is answered. **User action required:** rerun `python scripts/Build-CisM365Crosswalk.py && python scripts/Build-Registry.py` against the v6 XLSX to materialize the new fields onto existing recommendations.
- **CIS M365 v6 phase-2 enrichment — consumer-side ingestion (Path A)** ([#347](https://github.com/Galvnyz/CheckID/issues/347)). After analyzing the CIS SecureSuite member terms (which forbid public redistribution per Section II.B.1: *"Customer and its Affiliates may not sell, resell, or distribute any CIS SecureSuite Product or Customized Benchmark, whether in part or in whole, on its own or as part of an offering, product or service"*) and CC BY-NC-SA 4.0 + non-member rider clause (E) (*"create any derivative work based directly on a Non-Member CIS Product or any component thereof"*), CheckID adopts a **consumer-side ingestion model** for CIS-authored prose. The public repository never carries CIS-authored content; consumers populate it locally from their own licensed XLSX. Adds: `tools/import-cis-prose.py` (consumer-side importer reading the licensed XLSX → gitignored `data/cis-m365-v6-authored.local.json`), `tools/README.md` (usage + licensing notes), `LICENSES/CIS-CONSUMER-SIDE.md` (full posture + verbatim CIS license text references), `cisAuthored` block on `frameworkMapping` in `data/registry.schema.json` (with `$defs.cisAuthoredProse` defining the 6 optional prose fields), `Build-Registry.py` merge-when-present logic, `.gitignore` exclusion of `*.local.json` and the specific path, and two Pester gates: shape validation when present + a public-build invariant that fails CI if `cisAuthored` ever appears in the public registry without the local artifact present.
- **`force-replace` override mode** in `scripts/Build-Registry.py` `apply_fw_overrides()`. Until now, `mode: "replace"` (the default) only filled when the framework key was absent — if SCF had already produced an entry, the override silently became a no-op for the controlId. The new `force-replace` mode fully discards the SCF-derived entry and rebuilds it from override data (controlId, title resolved from `framework-titles.json`, profiles, evidenceType, source, reason). Use it when SCF's mapping is wrong for a framework — e.g., SCF maps SEA-18 to SOC 2 CC2.2 but `soc2-tsc.json` classifies CC2 as `nonAutomatableCriteria`. ([#316](https://github.com/Galvnyz/CheckID/issues/316))
- **`tests/test_build_registry_overrides.py`** — pytest unit tests covering all three modes (`replace`, `append`, `force-replace`) including the case where `force-replace` has no SCF entry to discard.

### Fixed

- **`ENTRA-TOU-001` SOC 2 mapping** ([#316](https://github.com/Galvnyz/CheckID/issues/316)). Changed from `CC2.2` (Internal Communication, classified as non-automatable per `soc2-tsc.json`) to `CC5` (Control Activities — *"Security policies and procedures are in place and operating effectively"*) using the new `force-replace` mode. Terms of Use enforcement is automatable via Graph and is a textbook control activity, not an internal-communication policy review.
- **`ENTRA-PASSWORD-003` and `ENTRA-PASSWORD-004` missing NIST CSF override** ([#253](https://github.com/Galvnyz/CheckID/issues/253)). Their three peers (`-001`, `-002`, `-005`) all carried `nist-csf: PR.AA-01`; the override author got partway through the family and stopped. Added the missing override on both — the password / smart-lockout / banned-password-list controls now consistently map to PR.AA-01 (Identities and credentials are managed). Surfaced during cross-session review with M365-Assess after the v2.22.1 SOC 2 pairing test caught the analogous SOC 2 gap; this is the NIST CSF equivalent.
- **HIPAA framework taxonomy expanded beyond Security Rule** ([#325](https://github.com/Galvnyz/CheckID/issues/325)). `data/frameworks/hipaa.json` previously declared only the 5 Security Rule sections (Subpart C: §164.308–316), but `data/registry.json` references 15 distinct §164.xxx codes across three subparts. Downstream consumers (e.g. M365-Assess) rendered ~10 unmapped HIPAA rows in their breakdown panels. Added §164.306 (General Rules) plus 10 missing entries from Subpart D (Breach Notification: §164.404 / §164.408 / §164.412) and Subpart E (Privacy Rule: §164.506 / §164.508 / §164.510 / §164.512 / §164.514 / §164.530 / §164.532). Each entry now also carries a `subpart` annotation (C/D/E) so consumers can group by subpart later — sets up cleanly for the multi-axis taxonomy spike (#317). Framework `version` field updated to "Administrative Simplification (Security + Privacy + Breach Notification Rules)" to reflect the broadened scope.

### Changed

- **`tests/migration-3.0.Tests.ps1`** — added a `postMigrationRetargets` exemption list for the framework-overrides round-trip test. Distinguishes intentional `force-replace` re-targets (where the v2.23 controlId is no longer literally present in the registry) from accidental data loss during migration. Each entry documents the reason and references the issue number.
- **CIS M365 v6 phase-2 architecture refinement: output separation** ([#347](https://github.com/Galvnyz/CheckID/issues/347)). `scripts/Build-Registry.py` now writes the canonical `data/registry.json` **always prose-free** regardless of consumer state, and additionally writes `data/registry.local.json` (gitignored) with prose merged when the consumer artifact is present. Eliminates the previous footgun where a local rebuild would contaminate the committable diff. Downstream consumers load `registry.local.json` if it exists, falling back to `registry.json`. The Pester invariant guard fires unconditionally now (no skip path) since the canonical registry should never carry prose.

### Fixed

- **CIS M365 v6 phase-1 References URL parsing** ([#347](https://github.com/Galvnyz/CheckID/issues/347)). The CIS v6.0.1 spreadsheet stores References as colon-joined URLs with no whitespace (e.g. `https://a/foo:https://b/bar:https://c/baz`); the previous `https?://\S+` regex greedy-matched across colons and emitted one giant concatenated URL. Replaced with a `(?=https?://)` lookahead split that yields one entry per URL.
- **CIS M365 v6 phase-1 `cisControls` field removed** ([#347](https://github.com/Galvnyz/CheckID/issues/347)). The "CIS Controls" XLSX column doesn't carry top-level CIS Controls numbers — it contains structured prose (`TITLE:... CONTROL:v8 X.Y DESCRIPTION:...`) where the IDs duplicate the per-IG safeguard data already captured in `cisSafeguardsByVersion`, and the title/description sub-fields are CIS-authored prose subject to the licensing constraints. Removed the redundant + licensing-risky `cisControls` array from the schema; consumers can compute top-level CIS Controls numbers from the safeguard IDs if needed.

## [3.0.0] - 2026-04-25

**Theme:** Schema Foundation — provenance + structured remediation. **BREAKING CHANGE.** Consumers must update their renderers; see `docs/SCHEMA-MIGRATION-3.0.md`.

### Breaking changes

- **`remediation` is now a structured object, not a string.** Channels: `powershell`, `portal`, `graph`, `cli`, `notes`. Null channels are omitted, not stored as null. At least one channel is always present.
- **`data/framework-overrides.json` deleted.** Its 95 override entries (119 mappings total) moved onto each check's `frameworks.<id>` with `source: "manual-override"` provenance.
- **`data/effort-overrides.json` deleted.** Its 59 override entries moved onto each check's `effort` object. The previously-stripped `_rationale` annotations are now preserved as `effort.overrideReason`.
- **Schema-strict gate now requires `impactRating` and `remediation` per check** (already enforced informally in v2.23.0; now explicit in `data/registry.schema.json`).

### Added

- **Per-mapping provenance** ([#260](https://github.com/Galvnyz/CheckID/issues/260)). Optional `source` + `reason` fields on every framework mapping. `source` enum: `scf-derived` (default if absent), `manual-override`, `cis-paraphrased`, `stig-manual`, `eidsca-crosswalk`.
- **`effort.overrideReason`** ([#263](https://github.com/Galvnyz/CheckID/issues/263)). Free-text rationale preserved on the 59 hand-overridden effort entries.
- **Migration round-trip CI gate** ([#266](https://github.com/Galvnyz/CheckID/issues/266)). New `tests/migration-3.0.Tests.ps1` validates that every override-file entry survives onto the corresponding check post-migration with correct provenance.
- **Consumer migration helper** ([#265](https://github.com/Galvnyz/CheckID/issues/265)):
  - `ConvertTo-LegacyRemediationString` cmdlet in `CheckID.psm1` — backward-compat bridge that reconstructs a v2.x string from a v3.0 structured object. Emits a deprecation warning once per session. **Slated for removal in v3.3.0** ([#295](https://github.com/Galvnyz/CheckID/issues/295)).
  - `tools/migrate-checkid-3.0.ps1` — PowerShell port of the parser, converts a v2.x registry to v3.0 shape locally for testing.
- **Migration documentation** ([#267](https://github.com/Galvnyz/CheckID/issues/267)). `docs/SCHEMA-MIGRATION-3.0.md` — what changed, before/after JSON, PowerShell consumer guide, provenance usage, migration checklist, removal timeline.
- **One-shot migration scripts** (committed for reproducibility/audit, not used in regular builds):
  - `scripts/Migrate-Overrides-3.0.py` — inlined override files into source files
  - `scripts/Parse-Remediation-3.0.py` — heuristic parser that converted 1,105 string remediations into structured shape

### Changed

- **`scripts/Build-Registry.py`** — `apply_fw_overrides()` and `derive_effort()` take per-check inline override data (previously: global lookup dicts). `load_effort_overrides()` removed. `load_az_assess_source_checks()` passes through new inline override fields. Transient build-time fields stripped from check_obj before write to satisfy `additionalProperties: false`.
- **Replace-mode override semantics**: when an override entry's framework key already exists from SCF derivation, the entry is now still tagged with `source: "manual-override"` to preserve the curator's deliberate intent. Pre-v3.0, replace-mode was a no-op fallback when SCF produced the same key.
- **`tests/registry-integrity.Tests.ps1`** — replaced the now-stale "framework-overrides.json has no duplicate keys" test with a registry-wide checkId uniqueness check (the same bug class, surfaced in the right place post-migration).

### Channel distribution after parse

Of 1,105 checks with structured remediation:
- portal: 898
- portal + cli: 69 (Azure with `az` alternative)
- powershell + portal: 53 (Entra/SPO/EXO with both)
- notes-only: 75 (6.8%; legitimate prose-only remediation like "Connect to Exchange Online and verify…")
- powershell-only: 9
- graph: 1

Closes #260, #261, #262, #263, #264, #265, #266, #267.

## [2.23.0] - 2026-04-25

**Theme:** Silent-Loss Prevention. CI hardening makes the v2.22.0-class data-loss bug structurally impossible. Plus framework metadata contract and release channels for downstream consumers.

### Added

- **Duplicate-key CI gate** ([#254](https://github.com/Galvnyz/CheckID/issues/254)). New `scripts/Validate-NoDuplicateKeys.py` rejects any `data/*.json` containing duplicate object keys; mirrored as a Pester gate. Hard-fails CI under the *Validate Python Scripts* job. Closes the bug class that lost 4 framework overrides in v2.22.0.
- **Mapping-count regression gate** ([#255](https://github.com/Galvnyz/CheckID/issues/255)). New `scripts/Compare-MappingCounts.py` compares per-framework mapping counts against `main` and fails CI when any framework drops more than 2%. Override via `ALLOW_MAPPING_DROP=<framework>` PR label. Posts a sticky PR comment with the delta table even when passing. Catches the v2.22.0 AZ-enrichment bug class where ~400 mappings were silently dropped across 26 AZ-* checks.
- **Schema-strict validation** ([#256](https://github.com/Galvnyz/CheckID/issues/256)). `data/registry.schema.json` now requires `impactRating` and `remediation` per check. All 1,105 production checks already populate both — this codifies the existing contract.
- **Enrichment metrics PR comment** ([#257](https://github.com/Galvnyz/CheckID/issues/257)). New `scripts/Compute-EnrichmentMetrics.py` computes per-framework rationale/impact/references population %, posts a sticky comment with delta vs `main`. Informational only — the hard release-gate for Critical/High enrichment lands in v3.2.0 ([#281](https://github.com/Galvnyz/CheckID/issues/281)).
- **Build-Registry defense-in-depth guards** ([#258](https://github.com/Galvnyz/CheckID/issues/258)). Module-level `_strict_load_json` helper used by all 7 input JSON loads; pre-write schema validation refuses to write a malformed registry locally; final affirmation line `[OK] N checks, M frameworks, 0 dup-key violations, schema validated.` Honest reporting — says "SKIPPED" if `jsonschema` isn't installed.
- **Data quality guarantees doc** ([#259](https://github.com/Galvnyz/CheckID/issues/259)). New `docs/data-quality-guarantees.md` — one-page statement of what CI enforces, what's tracked but not gated, what's planned for future milestones, plus consumer guidance on safe assumptions and defensive coding. Linked from `README.md`.
- **Framework metadata JSON Schema** at `data/frameworks.schema.json` (mirrors the `data/registry.schema.json` convention). Validates the 20 framework metadata files under `data/frameworks/` for required fields (frameworkId, label, version, totalControls, registryKey, csvColumn, displayOrder, scoring) and enforces the known scoring methods. Wired into `validate.yml`.
- **Release channels** for downstream consumers. `notify-downstream.yml` emits `"channel": "stable"` on tag push (existing behavior, now labeled). New `notify-downstream-preview.yml` emits `"channel": "preview"` on every push to `main` that touches registry data. Consumers declare their channel; preview-channel consumers track main HEAD, stable-channel consumers track tagged releases.
- **EZ-CMMC** added to the downstream dispatch list (stable + preview).

### Changed

- `data/registry.schema.json` `$defs/check.required` extended to include `impactRating` and `remediation`.
- `scripts/Build-Registry.py` reorganized: `_strict_load_json` helper at module level replaces the local `_reject_duplicates` function that previously guarded only `framework-overrides.json`.

### Test infrastructure

- 9 new Pester test files / helpers (+38 tests total): `duplicate-keys.Tests.ps1`, `mapping-counts.Tests.ps1`, `schema-strict.Tests.ps1`, `enrichment-metrics.Tests.ps1`, `build-registry-guards.Tests.ps1` plus their fixtures under `tests/fixtures/`.

Closes #254, #255, #256, #257, #258, #259.

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
