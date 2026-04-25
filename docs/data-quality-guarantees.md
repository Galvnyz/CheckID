# Data Quality Guarantees

What CI enforces about `data/registry.json` — and what it doesn't.

> Status as of **v2.23.0** (2026-04-25). Hard guarantees grow with future milestones; revisit this doc when consuming a new version.

## TL;DR

| Property | Status |
|---|---|
| Required per-check fields populated (`checkId`, `name`, `category`, `collector`, `scf.primaryControlId`, `frameworks`, `impactRating.severity`, `remediation`) | Hard guarantee |
| No duplicate keys in any `data/*.json` file | Hard guarantee |
| No silent loss of framework mappings (>2% drop blocks PR) | Hard guarantee |
| `rationale`, `impact`, `references` populated | Tracked, not gated |
| Structured remediation (`{powershell, portal, graph, cli}` object) | Planned for v3.0.0 |
| ≥95% Critical/High enrichment | Planned for v3.2.0 |

---

## Hard guarantees (CI fails on violation)

### 1. No duplicate keys in any `data/*.json` file

Every JSON file under `data/` is parsed with a strict `object_pairs_hook` that raises on duplicate keys. Python's default `json.load` silently keeps the last value when an object contains duplicate keys; that bug class lost 4 framework overrides in v2.22.0 (commit `8634df0`).

Enforced by:
- CI job **Validate Python Scripts** → step *Validate no duplicate JSON keys* (`scripts/Validate-NoDuplicateKeys.py`)
- `scripts/Build-Registry.py` `_strict_load_json` helper — local builds also fail (defense in depth)

Closed by [#254](https://github.com/Galvnyz/CheckID/issues/254), [#258](https://github.com/Galvnyz/CheckID/issues/258).

### 2. Per-check required fields

Every check in `registry.json` is validated against `data/registry.schema.json`. Required fields:

- `checkId` (matches `^[A-Z]+-[A-Z0-9-]+-\d{3}$`)
- `name`, `category`, `collector`
- `licensing.minimum` (one of `E3`, `E5`, `AzureSubscription`)
- `scf.primaryControlId` (matches `^[A-Z]{2,4}-\d{2}(?:\.\d+)?$`)
- `frameworks` (object, at least 1 entry)
- `impactRating.severity` (one of `Critical`, `High`, `Medium`, `Low`, `Informational`)
- `remediation` (string)
- `effort` block (`complexity`, `isPhased`, `phaseCount`, `disruptionRisk`)
- `hasAutomatedCheck` (boolean)

Enforced by:
- CI job **Validate Data Files** → step *Validate registry against JSON Schema* (`python -m jsonschema`)
- `scripts/Build-Registry.py` pre-write schema validation — refuses to write a malformed registry locally

Closed by [#256](https://github.com/Galvnyz/CheckID/issues/256), [#258](https://github.com/Galvnyz/CheckID/issues/258).

### 3. No silent loss of framework mappings

On every PR, CI compares per-framework mapping counts in `registry.json` against `main`. The build fails if any framework drops by more than 2%. Override via `ALLOW_MAPPING_DROP=<framework>` PR label for intentional removals (framework deprecation, cohort migration, etc.).

Catches the v2.22.0 AZ-enrichment bug class where ~400 mappings were silently dropped across 26 AZ-* checks.

Enforced by CI job **Mapping Count Regression** (`scripts/Compare-MappingCounts.py`). Posts a sticky PR comment with the delta table even when passing.

Closed by [#255](https://github.com/Galvnyz/CheckID/issues/255).

---

## Tracked but not gated

These metrics are surfaced as informational PR comments but do **not** block builds.

### Content enrichment population

Every PR gets a sticky comment with per-framework population % for `rationale`, `impact`, and `references[]`. Current overall (v2.23.0): ~26% across all three. Frameworks vary widely — CIS M365 v6 is 100%; Essential Eight is 22%.

Why not gated: gating now would block all routine PRs until ~74% of checks are hand-authored. The hard release-gate for **Critical/High** severity arrives in v3.2.0 ([#281](https://github.com/Galvnyz/CheckID/issues/281)).

Enforced by CI job **Enrichment Metrics** (`scripts/Compute-EnrichmentMetrics.py`). Closed by [#257](https://github.com/Galvnyz/CheckID/issues/257).

---

## Not yet guaranteed (planned)

| Guarantee | Milestone | Issue |
|---|---|---|
| Per-mapping provenance (`source`, `reason` on each `frameworks.*` entry) | v3.0.0 | [#260](https://github.com/Galvnyz/CheckID/issues/260) |
| Structured remediation object (`{powershell, portal, graph, cli, notes}`) | v3.0.0 | [#261](https://github.com/Galvnyz/CheckID/issues/261) |
| `contentSource` provenance flag (`human-authored`, `llm-drafted-reviewed`, etc.) | v3.1.0 | [#270](https://github.com/Galvnyz/CheckID/issues/270) |
| All `references[]` URLs return HTTP 200 (link-rot CI) | v3.1.0 | [#275](https://github.com/Galvnyz/CheckID/issues/275) |
| ≥95% rationale + impact for Critical/High severity | v3.2.0 | [#281](https://github.com/Galvnyz/CheckID/issues/281) |
| `blastRadius` derived field (severity × disruptionScope) | v3.2.0 | [#280](https://github.com/Galvnyz/CheckID/issues/280) |
| Per-check `lastReviewed` timestamp + 12-month review cadence | Backlog | [#288](https://github.com/Galvnyz/CheckID/issues/288) |

---

## What this means for consumers

If you build on `registry.json` (M365-Assess, M365-Remediate, StrykerScan, or other downstream tools):

### Safe to assume

- Every check has `checkId`, `name`, `category`, `collector`.
- Every check has at least one entry in `frameworks`.
- Every check has `impactRating.severity` set to a known enum value.
- Every check has `remediation` as a non-empty string.
- The `schemaVersion` in `registry.json` equals the `ModuleVersion` in `CheckID.psd1`.

### Code defensively for

- `rationale`, `impact`, `references` may be absent or empty on ~74% of checks today. When rendering, degrade gracefully (e.g., "Rationale not yet authored — see references").
- Framework membership can change between releases. Don't pin to a specific framework count; pin to a tagged release.

### Don't assume yet

- **Don't** parse `remediation` as structured PowerShell vs portal — it's free-form until v3.0.0.
- **Don't** infer mapping provenance — first-class in v3.0.0.
- **Don't** trust `references[]` URLs without checking them — link-rot CI lands in v3.1.0.

### Pin to a tag

The registry is regenerated frequently. For reproducible consumer behavior, pin to a tagged release (e.g., `v2.23.0`) and bump deliberately.

---

## Reporting drift

If you find something this doc says is guaranteed but the registry doesn't meet, file an issue with:
- The exact `checkId` (or "registry-wide" if structural)
- Expected vs observed value
- Which CI step should have caught it

Unenforced guarantees are treated as bugs.

---

_Last reviewed 2026-04-25 (v2.23.0). Revisit on each minor version bump._
