# 0002 — Portal-path navigation parents are a constrained vocabulary

- **Status:** Proposed
- **Date:** 2026-05-06
- **Deciders:** maintainers
- **Tags:** schema, validation, data-quality

## Context

Each registry entry's `remediation.portal.path` describes how an operator navigates to the relevant blade — e.g., `Entra admin center > Entra ID > Authentication methods > Registration campaign`. The schema defines `path` as a non-empty string with no further constraint:

```json
"path": { "type": "string", "minLength": 1 }
```

Any string passes. There is no allow-list of valid top-level navigation parents and no deny-list of obsolete ones. The Pester suite (`tests/*.Tests.ps1`) has no assertion that a `path` is current; the only `portal.path` reference is in `migration-helper.Tests.ps1`, which only checks the field is preserved during migration.

The cost of this gap is documented in `docs/plans/399-sspr-research.md` §1.2:

| Source file | Stale `Protection >` | Stale `Security >` | Stale `Users > Password reset` | Total |
| --- | ---: | ---: | ---: | ---: |
| `data/scf-check-mapping.json` | 31 | 0 | 0 | 31 |
| `data/az-assess-source-checks.json` | 0 | 14 | 4 | 18 |

49 stale paths reach `data/registry.json` via the build, plus one entry (`AZ-IDENTITY-031`) pointing at a fully deprecated blade. The Microsoft Entra admin center has exactly five top-level product areas (`Entra ID`, `ID Protection`, `Identity Governance`, `Verified ID`, `Global Secure Access`) per Microsoft Learn `entra-admin-center.md` (`updated_at: 2026-04-06`); `Protection`, `Security` directly under the admin center, and `Users` directly under the admin center are not among them.

PR #397 (the ENTRA-SSPR-001 rebadge) shipped with the assertion that the path was "already correct" precisely because nothing automatically flagged it.

## Decision

The first two segments of `remediation.portal.path` (the portal name and its top-level node) are drawn from a constrained vocabulary, enforced in CI.

**Allow-list (portal → top-level nodes):**

| Portal name (segment 1) | Valid top-level nodes (segment 2) |
| --- | --- |
| `Entra admin center` / `Microsoft Entra admin center` | `Entra ID`, `ID Protection`, `Identity Governance`, `Verified ID`, `Global Secure Access`, `Settings` |
| `Azure portal` | `<service category>` (Azure portal navigation is open-vocabulary; segment 2 is not constrained for Azure) |
| `Microsoft 365 admin center` | `<exact admin-center node>` (open-vocabulary; not constrained) |
| `Exchange admin center` | (open-vocabulary; not constrained) |
| `Microsoft Defender portal` / `Microsoft 365 Defender portal` | (open-vocabulary; not constrained) |
| `Microsoft Purview portal` | (open-vocabulary; not constrained) |
| `Power Platform admin center` | (open-vocabulary; not constrained) |
| `Power BI Admin portal` | (open-vocabulary; not constrained) |
| `Intune admin center` / `Microsoft Intune admin center` | (open-vocabulary; not constrained) |

The Entra admin center is the only portal with a hard allow-list because (a) its top-level taxonomy is small and stable, (b) Microsoft has reorganized it twice (most recently 2024–2025) leaving stale paths in any data set that wasn't migrated, and (c) the bulk of CheckID's stale paths (49 of 49) fall under it.

**Deny-list (Entra admin center top-level segments that are *known stale*):**

- `Protection >` (former parent for Authentication methods, Conditional Access, Password protection, Password reset; folded into `Entra ID >` 2024–2025)
- `Security >` (never a top-level node of the Entra admin center; appears to be carried over from Azure portal navigation)
- `Users >` directly under `(Microsoft) Entra admin center >` (`Users` is a sub-node of `Entra ID`, not a top-level node)

**Enforcement:**

- A new Pester test in `tests/registry-integrity.Tests.ps1` (or a new file `tests/portal-paths.Tests.ps1`) asserts every `remediation.portal.path` segments-1-and-2 against this vocabulary.
- The assertion runs against `data/registry.json`. Validating source files separately is unnecessary because the registry is the build output and a stale source-file path that survives the build is the failure mode we want caught.
- The test additionally asserts that when `steps[]` is present, its first one or two entries reference the same parent navigation as `path` (the "drift between path and steps" gap noted in the research §1.6).

**Update process when Microsoft reorganizes the portal:**

- Update the allow/deny-list in this ADR (with a `Status: Superseded by NNNN` entry if the change is structural enough to warrant a new ADR) and the corresponding test.
- Update affected `data/scf-check-mapping.json` and `data/az-assess-source-checks.json` entries in the same PR; do not let the deny-list expand without the data being migrated.

## Consequences

**Intended:**

- 49 stale paths surface as test failures the moment the rule lands — the data fix and the rule landing in the same PR is the simplest path.
- Future stale paths can no longer enter the registry silently; a CIS benchmark refresh or a manually-authored entry that uses an obsolete parent fails CI immediately.
- The class-of-bug that PR #397 papered over (assertion of "already correct" with no test backing it) becomes structurally impossible for parent-segment staleness.

**Accepted costs:**

- The allow-list is opinionated and Entra-centric. Other portals (Azure, Defender, Purview, etc.) have larger or more fluid taxonomies and are not constrained beyond the portal-name segment. If those portals start showing similar staleness patterns, this ADR can be superseded with broader coverage; for now we constrain only what we have evidence for.
- Microsoft can rename a top-level node at any time. The maintenance cost is one ADR amendment (or supersession) plus a data migration per such event. The 2024–2025 reorganization that caused the current 49 stale paths is the kind of event that motivates this rule, not an outlier.

**Out of scope:**

- Validating segment 3 and beyond (specific blade names within a portal). These change too frequently and aren't covered by Microsoft's published navigation taxonomy. ADR-0004 covers a complementary mechanism (sourcing CIS-mapped paths from upstream) that handles deep-blade drift for a meaningful subset of checks.
- Automatic remediation. The rule fails CI; a human still authors the corrected path.

## Alternatives considered

- **Schema-only constraint** (extend `registry.schema.json` with a `pattern` regex on `path`). Rejected: regex over a path string is brittle, hard to evolve, and the failure message is unhelpful. A Pester test produces a clearer failure (the offending CheckID and current path).
- **Fetch Microsoft Learn pages and validate paths against current docs** (the report's E3 option). Rejected for now: too brittle, too much maintenance, false positives from doc churn. The deny-list approach catches the most common failure mode (stale parents) at vastly lower cost.

## References

- `docs/plans/399-sspr-research.md` §1.1 (Entra admin center ground truth) and §1.2 (stale-parent inventory)
- Microsoft Learn — [Microsoft Entra admin center](https://learn.microsoft.com/en-us/entra/fundamentals/entra-admin-center) (`updated_at: 2026-04-06`)
