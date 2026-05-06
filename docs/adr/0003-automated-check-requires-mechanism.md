# 0003 — `hasAutomatedCheck: true` must document a mechanism

- **Status:** Proposed
- **Date:** 2026-05-06
- **Deciders:** maintainers
- **Tags:** schema, validation, data-quality, framework-completeness

## Context

`hasAutomatedCheck` is a single boolean on every registry entry. The schema requires only that `collector` is set to a known enum value when it is `true`. It does **not** require any documentation of *how* the check is automated.

Concretely (counts taken from `data/registry.json` on 2026-05-06):

- 1,101 of 1,105 checks declare `hasAutomatedCheck: true`.
- 4 declare it `false`.
- Only **62** have a `remediation.powershell` block.
- Only **1** has a `remediation.graph` block.

That leaves ~1,038 entries claiming automation with no on-record mechanism. The gap matters because:

- It violates the project rule recorded in user memory ("Framework data completeness — if we claim a framework is supported, carry real data; no logical/derived mappings or consumer-side workarounds"). The same principle applies to automation claims: if we claim a check is automated, the registry should carry the evidence, not push the consumer to find out.
- `docs/plans/399-sspr-research.md` §1.4 documents two concrete cases where the boolean was wrong. ENTRA-SSPR-001 pre-PR #397 claimed automation for a setting with no supported Graph endpoint. ENTRA-SSPR-002 currently does the same: claims `true`, has only `portal` + `notes` under `remediation`, and the underlying SSPR enablement toggle has no supported Graph endpoint as of 2026-05-04 (Microsoft Q&A confirms; only the undocumented `main.iam.ad.ext.azure.com` internal endpoint exists).
- The schema already recognizes that the upstream framework's automation stance can diverge from ours — `cisRecommendationStructured.cisAuditPolicy` is a separate enum (`Manual` | `Automated`) for that reason. So the field's semantics intentionally permit divergence; what's missing is evidence supporting our side of the divergence.

## Decision

When `hasAutomatedCheck: true`, the entry's `remediation` object **must** include at least one documented automation mechanism:

- `remediation.graph` — Microsoft Graph API endpoint and the property/path being read, OR
- `remediation.powershell` — PowerShell cmdlet (and module) that surfaces the value, OR
- `remediation.azureCli` / `remediation.azureRest` — for AZ-namespace checks where the source-of-truth is an Azure ARM/Resource Manager API rather than Graph.

The exact JSON shape of each mechanism block is a follow-up schema design (see Implementation Notes); this ADR commits to the rule, not the field names.

The rule is enforced by `data/registry.schema.json` via a JSON Schema conditional:

```jsonc
"allOf": [
  {
    "if":   { "properties": { "hasAutomatedCheck": { "const": true } }, "required": ["hasAutomatedCheck"] },
    "then": { "properties": { "remediation": { "anyOf": [
              { "required": ["graph"] },
              { "required": ["powershell"] },
              { "required": ["azureCli"] },
              { "required": ["azureRest"] }
            ] } } }
  }
]
```

`hasAutomatedCheck: false` entries are unconstrained on `remediation` mechanism — they may have `portal` only, which is the documented expectation.

**Transition (option (ii) from the discovery report):** the schema rule does not land until the audit lands. Sequence:

1. **Audit phase.** A one-time audit script enumerates every `hasAutomatedCheck: true` entry without an automation mechanism (~1,038 today). For each, the entry is either:
   - confirmed automated by Galvnyz/M365-Assess (or the relevant collector repo) and given a `remediation.graph` / `remediation.powershell` / etc. block populated from the collector's actual implementation, OR
   - confirmed *not* automated (no supported endpoint, no collector code) and flipped to `hasAutomatedCheck: false`.
   The audit ships in tranches per service area to keep PRs reviewable. Each tranche cites this ADR.
2. **Rule landing.** Once the audit reaches zero entries with the mismatch, the schema conditional above lands as one PR. CI flips green; future drift is impossible at the schema level.

We do **not** ship a `legacyAutomationClaim: true` grandfathering shim. A grandfather field ossifies the gap and creates a permanent two-tier registry. The audit is finite and the rule is the value; we pay the audit cost up front.

## Consequences

**Intended:**

- The registry's `hasAutomatedCheck: true` claim becomes load-bearing — downstream consumers (M365-Assess, M365-Remediate, StrykerScan) can trust it as a precondition for collector availability.
- ENTRA-SSPR-002 and any other entry in the same false-claim class get correctly classified as part of the audit. ADR-0005 governs *what* they get reclassified as; this ADR governs *that* the reclassification must happen.
- The "framework data completeness" memory rule extends naturally to automation claims: parity between what the registry says it supports and what is actually carried.

**Accepted costs:**

- The audit is large: ~1,038 entries spanning M365 + Azure + Windows. It is the dominant cost of this rule. Mitigations: (a) batch by service prefix (`ENTRA-*`, `EXCH-*`, `DEFENDER-*`, `AZ-*`, `WIN-*`) so each PR is bounded; (b) cross-reference Galvnyz/M365-Assess collector code and Galvnyz/StrykerScan for AZ-namespace as the primary source for the mechanism block content; (c) accept that some entries flip to `hasAutomatedCheck: false` rather than getting a mechanism block — that's the right outcome when no automation exists.
- Schema landing is gated on audit completion. If the audit stalls, the rule does not land. This is a deliberate forcing function; the alternative (ship rule + accept CI red) creates worse incentives.
- Upstream framework drift: when Microsoft ships a new Graph endpoint for something previously manual (e.g., the long-promised SSPR Graph surface), the entry should flip from `false` back to `true` with a freshly populated `remediation.graph` block. ADR-0005 references this reverse direction.

**Out of scope:**

- The exact field shape of `remediation.graph` / `remediation.powershell` / `remediation.azureCli` / `remediation.azureRest`. Each block needs a sub-schema (endpoint URL pattern, property path, expected values). That's a follow-up RFC — referenced here as a known gap, but not committed to in this ADR.
- Validating the *correctness* of a populated mechanism block (i.e., does the Graph endpoint actually return the property claimed?). That's runtime validation, not schema validation. Out of scope.
- Reconciling `hasAutomatedCheck` against the upstream `cisRecommendationStructured.cisAuditPolicy` field. They're allowed to diverge by design (per the field's description). This ADR does not change that.

## Alternatives considered

- **Ship the schema rule now + CI red until audit completes.** Rejected: ~1,038 failures on day one, no signal value, blocks unrelated PRs.
- **Ship a `legacyAutomationClaim` grandfathering shim** (option (i) in the planning discussion). Rejected: ossifies the gap and creates two-tier semantics. The audit is finite; pay the cost once.
- **Lower the bar to a `remediation.notes` mechanism statement in prose.** Rejected: prose isn't testable, doesn't help downstream collectors, and recreates the same opacity at one indirection's remove.

## Implementation notes

- The audit script lives at `scripts/Audit-AutomationClaims.py` (new) and produces a tranche-by-tranche worklist keyed by service prefix.
- The follow-up RFC defining `remediation.graph` / `remediation.powershell` / etc. sub-schemas should land before the first audit tranche so reviewers know what shape to fill in.
- This ADR's `Status: Proposed → Accepted` flip happens with the schema-landing PR (the final step of the transition), not with the audit-script PR.

## References

- `docs/plans/399-sspr-research.md` §1.4 (false-automation claims) and §1.5 (Graph API surface inventory)
- `data/registry.schema.json` — current `hasAutomatedCheck` and `remediation` definitions
- ADR-0005 — coverage gaps without supported Graph API (governs the `false`-flip half of the audit)
