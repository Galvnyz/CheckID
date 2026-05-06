# 0004 — Source-of-truth precedence for portal paths

- **Status:** Proposed
- **Date:** 2026-05-06
- **Deciders:** maintainers
- **Tags:** schema, data-pipeline, framework-completeness

## Context

Portal paths in the registry come from two source files:

- `data/scf-check-mapping.json` — M365 / Entra checks. 31 of these currently use the stale `Protection >` parent.
- `data/az-assess-source-checks.json` — Azure / Windows checks (sourced from CIS benchmark CSVs via `scripts/Build-CisAzureCandidates.py`). 18 currently use stale `Security >` or `Users >` parents.

ADR-0002 establishes a vocabulary for the first two segments and enforces it in CI. That catches the parent-rename failure mode. It does **not** answer the next question: when a path needs correction or the upstream blade structure changes more deeply (new sub-blade, renamed leaf), where does the corrected path come from?

The discovery report (`docs/plans/399-sspr-research.md` §1.2) found:

- 14 of the 31 stale `Protection >` entries in `scf-check-mapping.json` carry a `cisM365ControlId` — they are CIS-derived and a corresponding row exists in SecFrame's `Combined Profiles-CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.csv`.
- That CSV uses the current `Entra ID >` parent 53 times and the stale `Protection >` parent only 2 times. CIS itself is 96% current; CheckID's staleness is mostly transcription drift from older benchmark versions or hand-authored entries that were never refreshed.
- All 18 stale entries in `az-assess-source-checks.json` are AZ-IDENTITY-* and similarly trace back to CIS Azure benchmark CSVs ingested via the candidate pipeline.

There is no rule today about whether portal paths should track the upstream source automatically (and which upstream that is) or whether they live as hand-curated values in CheckID's source files. Both happen, inconsistently. The candidate pipeline (`Build-CisAzureCandidates.py` → `candidates/az-candidates.json`) does pull paths from CIS CSVs at candidate-generation time, but once promoted into `az-assess-source-checks.json` they are no longer kept in sync — a future CIS benchmark refresh that corrects a path won't propagate.

This connects to two memory rules:

- "Framework data completeness — if we claim a framework is supported, carry real data." Carrying real data also means carrying *current* data; a path frozen at the moment of original transcription is not real data after the upstream changes.
- The build pipeline already treats `data/registry.json` as build output (regenerated, never hand-edited). The same logic argues for treating other derivable fields the same way.

## Decision

**Portal paths follow a tiered precedence:**

1. **CIS-mapped entries (those carrying a `cisM365ControlId`, `cisAzureControlId`, `cisWindowsControlId`, or equivalent CIS reference): the path is sourced from the corresponding SecFrame CIS CSV at build time.** The build script reads the path field from the CSV row matching the entry's CIS control ID; the value in `data/scf-check-mapping.json` / `data/az-assess-source-checks.json` becomes a cache, not the source of truth. If the cache and the CSV disagree, the CSV wins and CI either auto-updates the source file or fails with a diff (see Implementation Notes for the choice).
2. **Non-CIS entries (CheckID-authored, or mapped to a framework whose upstream does not publish portal paths): the path lives in the source file as authored, and is verified manually against Microsoft Learn at the time of authoring.** The verification expectation is recorded in the entry's `lastVerified` metadata (date) so future maintainers can judge staleness.
3. **In all cases, the result must satisfy ADR-0002's vocabulary constraint** — sourcing a path from CIS does not exempt it from validation; it only changes who is responsible for keeping it current.

**Rationale for the split:**

- CIS publishes portal paths per recommendation; we already ingest CIS CSVs upstream of the registry; the marginal cost of treating CIS as source-of-truth is low (one build-time lookup) and the marginal benefit is large (49 stale paths today, plus automatic propagation of every future CIS refresh).
- Microsoft Learn does not publish a structured machine-readable navigation map. For non-CIS entries, the human-verified source file remains the only practical source.
- Treating *all* paths as build-derived would orphan the non-CIS entries (no upstream to derive from). Treating none as build-derived perpetuates the current drift problem for the CIS-mapped subset.

## Consequences

**Intended:**

- The 14 of 31 stale `Protection >` entries in `scf-check-mapping.json` self-correct on the first build after the secframe sync lands; future CIS refreshes propagate without manual transcription. Same for the AZ-namespace entries.
- The 17 non-CIS Protection-stale entries and the AZ-IDENTITY-031 deprecated-blade case (which needs blade rework, not just a parent rename) are explicitly out of scope for the auto-sync mechanism — they get manual fixes, but the rule for *future* manual entries is now documented.
- The build pipeline gains a documented dependency on SecFrame's CIS CSV exports for portal-path freshness. This is consistent with how the registry already depends on `scf.db` for SCF metadata.

**Accepted costs:**

- Build-time dependency on a specific SecFrame file path layout. Mitigation: same as the existing `scf.db` dependency — the path is configured in `scripts/Build-Registry.ps1`/`.py`, not hard-coded in dozens of places.
- When CIS itself ships an obsolete path (the report found 2 cases of `Protection >` in the v6.0.1 CSV), CheckID inherits that staleness for those entries until the next CIS refresh. Acceptable: this affects ~2 entries vs. ~14 self-corrected; net win is large.
- The `lastVerified` metadata on non-CIS entries adds a small authoring burden. Mitigation: it's a single date field; tooling can default it to the commit date.

**Out of scope:**

- Retroactively populating `lastVerified` for the existing 1,105 entries. Treat absent `lastVerified` as "unknown / pre-rule"; new and modified entries acquire it going forward.
- Sourcing portal paths from any upstream other than CIS CSVs (e.g., scraping Microsoft Learn). Out of scope for the same reasons listed in ADR-0002.

## Alternatives considered

- **Auto-sync everything from secframe (option B3 in the research), no manual paths.** Rejected: orphans non-CIS-mapped entries, of which there are many (CheckID-authored entries and entries mapped only to frameworks that don't publish portal paths).
- **Mechanical parent rename now, no automation, document expectation.** Rejected as a long-term solution: it's exactly what we've been doing implicitly and explains why we have 49 stale paths today. Acceptable as a one-time data fix for the *non*-CIS subset; that's how the rule lands.
- **Per-entry verification of every path against Microsoft Learn at build time** (option B2 / E3 in the research). Rejected: too brittle, doc churn, no structured source.

## Implementation notes

- A new build-time component (`scripts/Sync-CisPortalPaths.py` or equivalent, possibly merged into `Build-Registry.py`) reads the SecFrame CIS CSV(s) at `C:/git/SecFrame/csv-exports/CIS/...` and substitutes the path into the in-memory registry build for entries with a CIS reference.
- Open implementation question: when the cached value in the source JSON diverges from the CSV, does the build (a) auto-update the source JSON and commit, (b) fail the build with a diff for human review, or (c) silently substitute and warn? Recommendation: (b) on local builds, (a) on the existing scheduled CI workflow that already regenerates candidates from SecFrame dispatch events. The accept/reject of that recommendation is left for the implementing PR — the rule is "CSV wins"; the *mechanism* is implementation detail.
- ADR-0002's vocabulary check runs *after* the sync substitution, on the assembled `registry.json`. So if a CSV row itself violates the vocabulary, the build still fails — preventing CIS-side staleness from silently entering the registry.

## References

- `docs/plans/399-sspr-research.md` §1.2 (stale-parent inventory by source file) and §Phase 2 Decision B / E5 (auto-sync option)
- `docs/architecture.md` (registry build pipeline)
- ADR-0002 — portal-path navigation parents are a constrained vocabulary
