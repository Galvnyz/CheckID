# 0005 — Coverage gaps without supported Graph API

- **Status:** Proposed
- **Date:** 2026-05-06
- **Deciders:** maintainers
- **Tags:** data-quality, framework-completeness, policy

## Context

Some compliance-relevant settings have no supported Microsoft Graph endpoint as of 2026-05-04. Two concrete examples documented in `docs/plans/399-sspr-research.md` §1.5:

| Setting | Graph endpoint? |
| --- | --- |
| SSPR enablement toggle (None / Selected / All) — both for All users and for Admin users | **No supported endpoint.** Only `https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies` (undocumented, internal). Microsoft Q&A confirms no v1.0 or beta surface; APIs "supposedly coming under `/authentication/methods`" with no announced ETA. |
| `Number of methods required to reset` (legacy SSPR strength) | **No supported endpoint.** Same internal-only situation. |

This creates a tension with two existing commitments:

- The CIS M365 v6.0.1 benchmark includes recommendations (e.g., §5.2.4.1 — All-users SSPR enablement) that are compliance-relevant and that consumers expect CheckID to surface mappings for.
- The "framework data completeness" memory rule forbids claiming framework support without carrying real data, and forbids consumer-side workarounds.

PR #397 navigated this for ENTRA-SSPR-001 by removing the CIS 5.2.4.1 mapping entirely and rebadging the check to MFA Registration Campaign semantics (which *does* have a Graph endpoint). The decision left CIS 5.2.4.1 uncovered, with the comment that "a future ENTRA-SSPR-002 will measure actual SSPR enablement." But the existing ENTRA-SSPR-002 measures admin-account SSPR (a different control) and itself claims `hasAutomatedCheck: true` despite having no supported Graph endpoint — recreating the original false-claim pattern at one indirection's remove.

So the policy question is: when a control is compliance-relevant but has no supported automation surface, what does CheckID do?

Three plausible answers, each documented in the research §Phase 2 Decisions C and D:

- (a) Skip the control entirely — leave a coverage gap, no registry entry. Downstream consumers see nothing and infer no opinion.
- (b) File the control with `hasAutomatedCheck: true` and hope it eventually becomes true. This is the current ENTRA-SSPR-002 behavior. It is the failure mode this ADR exists to prevent.
- (c) File the control with `hasAutomatedCheck: false`, full framework mappings populated, portal-only `remediation`. The control is visible to consumers as in-scope; the boolean correctly signals that automation is not currently possible; the moment Microsoft ships the endpoint, the entry flips to `true` with a `remediation.graph` block (per ADR-0003).

## Decision

**When a compliance-relevant control has no supported automation surface, file it as `hasAutomatedCheck: false` with full framework mappings and portal-only `remediation`. Do not skip; do not falsely claim automation.**

Specifically:

- The entry is a first-class registry entry: full SCF anchoring, full framework mappings (including the CIS / NIST / ISO / etc. controls it represents), full portal `remediation` so a human operator can verify the setting manually.
- `hasAutomatedCheck` is `false`. `collector` may be omitted (the schema does not require it when `hasAutomatedCheck` is `false`).
- A `remediation.notes` field documents *why* automation is not currently available — e.g., "No supported Graph endpoint as of 2026-05-04. Microsoft Q&A: [link]. Re-evaluate when Microsoft ships `/authentication/methods` SSPR APIs."
- When Microsoft (or the relevant vendor) ships a supported endpoint, the entry flips to `hasAutomatedCheck: true` with a `remediation.graph` (or equivalent) block populated per ADR-0003. The flip is a routine data update, not a schema change.

**This rule applies to:**

- New entries being filed (any service area).
- Existing entries being audited under ADR-0003 that turn out to claim automation falsely.

**This rule resolves the concrete cases from the research:**

- **ENTRA-SSPR-002** (Decision C in the research): flip from `hasAutomatedCheck: true` to `false`. Keep the framework mappings; populate `remediation.notes` documenting the no-supported-endpoint state.
- **CIS M365 v6 §5.2.4.1 coverage gap** (Decision D in the research): file a new `ENTRA-SSPR-003` (or whatever ID falls next; ADR makes no claim on the specific identifier) representing All-users SSPR enablement, with `hasAutomatedCheck: false` and the CIS 5.2.4.1 mapping restored. This is option D4 in the research, selected because options D1 (repurpose existing ID) and D2 (file new ID with false-automation claim) violate either ID stability or this ADR's rule, and D3 (leave gap) violates "framework data completeness".

## Consequences

**Intended:**

- The framework-data-completeness rule extends cleanly: we map what consumers expect us to map (the CIS recommendation exists; we represent it), and we accurately signal what we can and cannot automate (`hasAutomatedCheck: false`).
- ENTRA-SSPR-002 stops being a documented false-claim case. Future audits (per ADR-0003) have a clear policy for the residual entries that fall into the same category.
- CIS M365 v6.0.1 coverage on §5.2.4.1 returns to the registry, removing the gap PR #397 introduced.
- Consumers gain a meaningful distinction: a registry without an entry for control X means CheckID has no opinion on X; a registry entry with `hasAutomatedCheck: false` means CheckID asserts X is in-scope but currently requires manual verification.

**Accepted costs:**

- The count of `hasAutomatedCheck: false` entries grows from 4 toward something larger as ADR-0003's audit lands. That's the correct outcome — current 4-of-1,105 figure is itself evidence the boolean has been wrong for years — but it does change what the README and badges report. Consider updating any consumer-facing claim that conflates "1,105 checks" with "1,105 automated checks".
- Manual-only entries are less useful to automated assessment tools (M365-Assess, StrykerScan) than automated ones. Mitigation: the framework mappings are still useful for compliance-matrix generation (`Export-ComplianceMatrix.ps1`); the manual portal path is still useful for human operators. Half a loaf with honest labelling is better than a whole loaf that lies.
- Two-stage data update when Microsoft ships an endpoint: the entry gets a `hasAutomatedCheck: true` flip *and* a populated `remediation.graph` block, both in the same PR. This is normal data maintenance, not a recurring tax.

**Out of scope:**

- Reciprocal handling for the inverse case (an endpoint exists but CheckID hasn't built a collector for it yet). That falls under ADR-0003's audit: such entries should currently be `hasAutomatedCheck: false` until the collector lands; the rule is the same.
- Tracking which Microsoft endpoints are forthcoming (e.g., the long-promised `/authentication/methods` SSPR APIs). That belongs in an external watchlist or in `REFERENCES.md`, not in the registry.

## Alternatives considered

- **Skip uncovered controls (option D3 / "leave the gap").** Rejected: violates "framework data completeness" and creates silent compliance-matrix holes that surprise consumers.
- **Repurpose ENTRA-SSPR-002 to cover CIS 5.2.4.1 (option D1).** Rejected: the IDs are public contracts; renaming what an ID measures is a breaking change for downstream consumers regardless of the pre/post-PR version delta.
- **Require a `remediation.graph` block on `hasAutomatedCheck: true` and stop there (rely on ADR-0003 alone).** ADR-0003 is necessary but not sufficient: it tells us *when to flip the boolean to false*, but not *what to do with the underlying compliance mapping*. Without this ADR, ADR-0003 would push maintainers toward the easier path of skipping uncoverable controls entirely. This ADR makes the right answer (file as manual) the documented answer.

## References

- `docs/plans/399-sspr-research.md` §1.5 (Graph API surface inventory) and §Phase 2 Decisions C and D
- ADR-0003 — `hasAutomatedCheck: true` must document a mechanism (the rule that triggers reclassification)
- PR #397 — ENTRA-SSPR-001 rebadge (the change that left CIS 5.2.4.1 uncovered)
