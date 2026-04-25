# CheckID — Findings Communication, Schema Consolidation & Content Enrichment

> **Status:** Approved 2026-04-24. Milestones and issues filed.
> **Tracking:**
> - v2.23.0 — Silent-Loss Prevention (#36) — issues [#254](https://github.com/Galvnyz/CheckID/issues/254)–[#259](https://github.com/Galvnyz/CheckID/issues/259)
> - v2.24.0 — Schema Foundation (#37) — issues [#260](https://github.com/Galvnyz/CheckID/issues/260)–[#268](https://github.com/Galvnyz/CheckID/issues/268)
> - v2.25.0 — CIS M365 v6 Pilot (#38) — issues [#269](https://github.com/Galvnyz/CheckID/issues/269)–[#275](https://github.com/Galvnyz/CheckID/issues/275)
> - v2.26.0 — Critical/High Backfill (#39) — issues [#276](https://github.com/Galvnyz/CheckID/issues/276)–[#282](https://github.com/Galvnyz/CheckID/issues/282)
> - Backlog (#26) — issues [#283](https://github.com/Galvnyz/CheckID/issues/283)–[#290](https://github.com/Galvnyz/CheckID/issues/290)

## Context

CheckID v2.22.1 (released 2026-04-24) just shipped a "data integrity bundle" that fixed two silent-loss bugs: a `json.load` duplicate-key clobber that lost 4 framework overrides, and an AZ-enrichment skip that lost ~400 framework mappings. CI structure validates shape but not content; bugs were caught only by downstream consumer cross-validation.

At the same time, the registry has a strong structural backbone (1,105 checks, 100% remediation populated, SCF-anchored) but a weak narrative layer: only **~27%** of checks have both `rationale` and `impact` populated. Remediation is a single string that mixes PowerShell with portal click-paths, blocking richer UX. Two override files (`framework-overrides.json`, `effort-overrides.json`) carry valuable tribal knowledge but live outside each check's record, where consumers can't see the *why*.

This plan splits the work into **four sequenced milestones**, each telling one coherent story:

| # | Milestone | Story | Scope |
|---|---|---|---|
| 1 | **v2.23.0 — Silent-Loss Prevention** | Stop the bleeding before changing anything | ~1 week |
| 2 | **v2.24.0 — Schema Foundation: Provenance + Structured Remediation** | Lay the slab; preserve override data with first-class provenance | 2–3 weeks |
| 3 | **v2.25.0 — CIS M365 v6 Enrichment Pilot** | Prove the schema with 180 fully-authored checks | 2–3 weeks |
| 4 | **v2.26.0 — Critical/High Backfill** | Scale enrichment to remaining 300–400 high-severity checks | 4+ weeks |

A **Backlog** milestone holds deferred items (Graph API blocks, consumer UX guide, CVSS scoring, Low/Info backfill).

---

## Decisions Locked-In (from clarification)

1. **v2.24 strategy:** Clean break with migration script. Override files are removed *as files*; their data moves onto each check with `source` + `reason` provenance. No data is lost.
2. **CI strictness (v2.23):** Hard gates on structural fields only. Content (rationale/impact) population tracked as a metric and posted as a non-blocking PR comment.
3. **Authoring model (v2.25/v2.26):** LLM-drafted, human-reviewed, with `contentSource` provenance flag on each check. Pilot uses hand-authoring for the first 30 to set voice; remainder uses LLM-assist with the pilot as exemplars.

---

## Milestone 1 — v2.23.0: Silent-Loss Prevention

**Theme:** Harden CI so v2.22.0-class bugs cannot ship again. No schema change, no content change.

### Issues

1. **CI: duplicate-key detection across all `data/*.json` files** ([#254](https://github.com/Galvnyz/CheckID/issues/254))
   - Add `scripts/Validate-NoDuplicateKeys.py` using a strict JSON parser (e.g. `object_pairs_hook` raising on duplicates).
   - Wire into `.github/workflows/validate.yml` as a hard gate.
   - Pester test coverage in `tests/registry-integrity.Tests.ps1` mirrors the gate.

2. **CI: framework-mapping count regression check** ([#255](https://github.com/Galvnyz/CheckID/issues/255))
   - Compare per-framework mapping counts in PR vs. `main`. Fail if any framework drops by >2% without an explicit `ALLOW_MAPPING_DROP=<framework>` label on the PR.
   - Catches the v2.22.0 AZ-enrichment-class bug structurally.

3. **CI: schema-strict validation** ([#256](https://github.com/Galvnyz/CheckID/issues/256))
   - Tighten `data/registry.schema.json` so required fields are explicit on every check (`checkId`, `name`, `category`, `collector`, `scf.primaryControlId`, `frameworks`, `impactRating.severity`, `remediation`).
   - Run `ajv` (or Python `jsonschema`) in CI as a hard gate.

4. **CI metric: rationale/impact population % per framework** ([#257](https://github.com/Galvnyz/CheckID/issues/257))
   - Bot computes population delta vs. `main` and posts a PR comment with a table.
   - Non-blocking — informational only.

5. **Build-Registry.py: load-time guards mirror schema requirements** ([#258](https://github.com/Galvnyz/CheckID/issues/258))
   - `Build-Registry.py` raises on the same conditions CI checks (defense in depth).

6. **Doc: `docs/data-quality-guarantees.md`** ([#259](https://github.com/Galvnyz/CheckID/issues/259))
   - One-page statement of what CI enforces and what it does *not* enforce. Sets honest expectations for consumers.

**Tag after merge:** `v2.23.0` (with user approval per CLAUDE.md).

---

## Milestone 2 — v2.24.0: Schema Foundation — Provenance + Structured Remediation

**Theme:** Restructure the schema so override data, remediation, and provenance are first-class on every check. Breaking change for consumers.

### Issues

1. **Schema: add per-mapping provenance** ([#260](https://github.com/Galvnyz/CheckID/issues/260))
   - Every entry in `frameworks.*` gains optional `source` (`"scf-derived" | "manual-override" | "cis-paraphrased" | "stig-manual"`) and optional `reason` (free-text annotation, e.g. "SCF lacks PR.AA-05 coverage for sign-in frequency").

2. **Schema: structured remediation object** ([#261](https://github.com/Galvnyz/CheckID/issues/261))
   - `remediation` becomes:
     ```json
     {
       "powershell": { "command": "...", "module": "...", "requiresAdmin": true } | null,
       "portal": { "path": "...", "steps": ["..."] } | null,
       "graph": { "endpoint": "...", "method": "PATCH", "body": {...} } | null,
       "cli": { "command": "..." } | null,
       "notes": "free-text caveats" | null
     }
     ```
   - At least one of `powershell|portal|graph|cli` must be non-null.

3. **Migration: dissolve `framework-overrides.json` into checks** ([#262](https://github.com/Galvnyz/CheckID/issues/262))
   - `Build-Registry.py` merges every entry into the target check's `frameworks` object, sets `source: "manual-override"`.
   - Override-file's per-entry comments → `reason` field on the merged mapping.
   - **Override file is deleted from `data/` after migration verified.**

4. **Migration: dissolve `effort-overrides.json` into checks** ([#263](https://github.com/Galvnyz/CheckID/issues/263))
   - Effort overrides merge into each check's `effort` object.
   - Existing `_rationale` build-time annotations → `effort.overrideReason` (preserved, no longer stripped).
   - **Override file is deleted from `data/` after migration verified.**

5. **Migration: split current `remediation` strings into structured object** ([#264](https://github.com/Galvnyz/CheckID/issues/264))
   - Heuristic parser for the four shapes already in the registry (PowerShell+portal, GPEdit, prose, portal-only).
   - Output reviewed in batches by collector (Entra, Exchange, Defender, SPO, AZ, Win).
   - Anything ambiguous goes into `notes` for human triage.

6. **Migration: provide downstream consumer helper** ([#265](https://github.com/Galvnyz/CheckID/issues/265))
   - `tools/migrate-checkid-2.24.ps1` — given a v2.23 registry, emit a v2.24-shaped one.
   - PowerShell module `CheckID.psm1` exposes `ConvertTo-LegacyRemediationString`. Deprecated on arrival; slated for removal in v2.27.

7. **CI: migration round-trip test** ([#266](https://github.com/Galvnyz/CheckID/issues/266))
   - `tests/migration-2.24.Tests.ps1` verifies no override-file byte is lost. Compares pre-migration override files to post-migration check fields.

8. **Doc: `docs/SCHEMA-MIGRATION-2.24.md`** ([#267](https://github.com/Galvnyz/CheckID/issues/267))
   - For downstream consumers (M365-Assess, M365-Remediate, StrykerScan). Includes before/after JSON examples and a snippet for PowerShell consumers showing the new access pattern.

9. **Heads-up to downstream repos** ([#268](https://github.com/Galvnyz/CheckID/issues/268))
   - Issue filed in M365-Assess, M365-Remediate, StrykerScan referencing this milestone with a target consumption date.

**Tag after merge:** `v2.24.0`.

---

## Milestone 3 — v2.25.0: CIS M365 v6 Enrichment Pilot

**Theme:** Author rationale + impact + references for all 180 CIS M365 v6 checks. Prove the schema with real content. Establish authoring voice.

### Issues

1. **Authoring style guide: `docs/authoring-guide.md`** ([#269](https://github.com/Galvnyz/CheckID/issues/269))
   - Voice (active, present-tense, second-person admin), length targets (rationale 80–200 chars, impact 80–250 chars), structure mirroring CIS Foundations (Rationale / Impact / References) without copying CIS prose.
   - Examples drawn from existing well-authored M365 checks (e.g., `SPO-SHARING-001`).

2. **Schema: `contentSource` field per check** ([#270](https://github.com/Galvnyz/CheckID/issues/270))
   - Values: `"human-authored"`, `"llm-drafted-reviewed"`, `"scf-derived"`, `"cis-paraphrased"`, `"placeholder"`.
   - Required on any check with `rationale` or `impact` populated.

3. **Phase 1 — hand-author 30 voice-setting checks** ([#271](https://github.com/Galvnyz/CheckID/issues/271))
   - Pick 30 from the highest-impact CIS M365 controls (admin MFA, external sharing, audit log, anti-phishing).
   - Daren-authored. Becomes the gold-standard exemplar set for Phase 2.

4. **Phase 2 — LLM-draft remaining 150 CIS M365 checks** ([#272](https://github.com/Galvnyz/CheckID/issues/272))
   - Use the 30 exemplars + style guide as the LLM prompt context.
   - Output stored in a review queue (`drafts/cis-m365-v6/<checkId>.json`).

5. **Phase 3 — human review pass on Phase 2 output** ([#273](https://github.com/Galvnyz/CheckID/issues/273))
   - Daren accepts/edits drafts. Approved drafts flow into `registry.json` with `contentSource: "llm-drafted-reviewed"`.

6. **References enrichment** ([#274](https://github.com/Galvnyz/CheckID/issues/274))
   - Populate `references[]` for all 180 with Microsoft Learn URLs and CIS Benchmark section IDs (no benchmark prose, just citations).

7. **CI metric: CIS M365 v6 enrichment %** ([#275](https://github.com/Galvnyz/CheckID/issues/275))
   - Bot reports population % for the framework on every PR.

**Tag after merge:** `v2.25.0`.

---

## Milestone 4 — v2.26.0: Critical/High Severity Backfill

**Theme:** Extend pilot model to all remaining checks where `impactRating.severity ∈ {Critical, High}` and rationale/impact is missing (~300–400 checks).

### Issues

1. **Scope identification** ([#276](https://github.com/Galvnyz/CheckID/issues/276))
   - Generate `data/_backfill-cohort.json` listing every Critical/High check missing rationale or impact. Group by collector (Entra, Defender, AZ, Win, etc.).

2. **LLM-drafting in collector batches** ([#277](https://github.com/Galvnyz/CheckID/issues/277))
   - One batch per collector. Each batch uses the v2.25 exemplars + style guide. Output queued for review.

3. **Human review pass** ([#278](https://github.com/Galvnyz/CheckID/issues/278))
   - Daren reviews per-batch. Approved drafts merged.

4. **References enrichment for the cohort** ([#279](https://github.com/Galvnyz/CheckID/issues/279))
   - Microsoft Learn / vendor doc URLs per check.

5. **Schema: optional `blastRadius` derived field** ([#280](https://github.com/Galvnyz/CheckID/issues/280))
   - Surfaces `effort.disruptionScope + impactRating.severity` as one normalized triage signal (e.g., `"high-impact, user-facing"`). Computed at build time, not authored.

6. **CI metric: Critical/High enrichment % per release** ([#281](https://github.com/Galvnyz/CheckID/issues/281))
   - Becomes a release-gating metric: any release that drops Critical/High enrichment % triggers a hard CI failure.

7. **Stretch: `placeholder` content for remaining gaps** ([#282](https://github.com/Galvnyz/CheckID/issues/282))
   - Where authoring isn't possible, set `contentSource: "placeholder"` with a `needs-authoring` tag so renderers can degrade gracefully ("Rationale not yet authored — see references").

**Tag after merge:** `v2.26.0`.

---

## Backlog Milestone — Deferred

Items intentionally out of scope for the four milestones above:

- Graph API remediation blocks ([#283](https://github.com/Galvnyz/CheckID/issues/283))
- Azure CLI remediation blocks ([#284](https://github.com/Galvnyz/CheckID/issues/284))
- Consumer UX guidance doc ([#285](https://github.com/Galvnyz/CheckID/issues/285))
- Severity re-scoring from CVSS ([#286](https://github.com/Galvnyz/CheckID/issues/286))
- Low / Informational severity backfill ([#287](https://github.com/Galvnyz/CheckID/issues/287))
- Per-check `lastReviewed` timestamp ([#288](https://github.com/Galvnyz/CheckID/issues/288))
- SCF version provenance ([#289](https://github.com/Galvnyz/CheckID/issues/289))
- Multi-language remediation ([#290](https://github.com/Galvnyz/CheckID/issues/290))

---

## Critical Files (modified across milestones)

| File | Milestones touched | Purpose |
|---|---|---|
| `data/registry.json` | 2, 3, 4 | Output artifact |
| `data/registry.schema.json` | 1, 2, 3 | Schema spec; tightened in 1, restructured in 2, extended in 3 |
| `data/framework-overrides.json` | 2 | Deleted in v2.24 |
| `data/effort-overrides.json` | 2 | Deleted in v2.24 |
| `scripts/Build-Registry.py` | 1, 2, 3 | Build pipeline; gains migration logic in 2 |
| `scripts/Validate-NoDuplicateKeys.py` | 1 | New |
| `.github/workflows/validate.yml` | 1, 2, 4 | CI hardening |
| `tests/registry-integrity.Tests.ps1` | 1, 2 | Pester guards |
| `tests/migration-2.24.Tests.ps1` | 2 | New, migration round-trip |
| `tools/migrate-checkid-2.24.ps1` | 2 | New, consumer helper |
| `docs/data-quality-guarantees.md` | 1 | New |
| `docs/SCHEMA-MIGRATION-2.24.md` | 2 | New |
| `docs/authoring-guide.md` | 3 | New |
| `CheckID.psm1` | 2 | Adds `ConvertTo-LegacyRemediationString` |

---

## Verification

**Per milestone:**
- `git log --oneline v<prev>..v<this>` shows commits aligned to milestone issues only (no scope creep).
- `pwsh -NoProfile -File ./tests/Run-AllTests.ps1` passes.
- CI green on the release commit.
- Tag exists, release notes drafted, consumer issues closed.

**Whole arc:**
- After v2.26.0: CI metric shows ≥95% of Critical/High checks have both rationale and impact populated.
- After v2.24.0: `data/framework-overrides.json` and `data/effort-overrides.json` no longer exist; round-trip test passes; downstream consumers have migrated.
- After v2.23.0: `validate.yml` gates duplicate-key, mapping-count regression, and schema-strict — proven by deliberately broken PR test.

**End-to-end smoke test (after v2.26.0):**
- Pick 5 checks across collectors. Open each in registry.json. Verify: structured remediation, populated rationale + impact + references, `contentSource` flag, per-mapping provenance. If a CIS M365 check, verify it carries `cis-paraphrased` provenance and a CIS Benchmark section reference.

---

## Why This Sequencing

- **Validation first** because everything that follows changes the schema; without hardened CI, a single typo silently breaks consumers (we just lived this).
- **Schema before content** because content authored into a weak schema is wasted effort. The 27% rationale/impact population today is a feature, not a bug — the missing 73% is the cohort that will benefit from the new schema, structured remediation, and authoring guide.
- **CIS M365 pilot before broad backfill** because it's the highest-leverage 180 checks (E3/E5 customers, real auditor scrutiny), it's small enough to hand-author the voice-setting subset, and it produces the LLM exemplars for v2.26.
- **Critical/High before Low/Info** (which is in backlog) because triage value is concentrated at the top of the severity distribution.
