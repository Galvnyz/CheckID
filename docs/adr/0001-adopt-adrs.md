# 0001 — Adopt Architecture Decision Records

- **Status:** Accepted
- **Date:** 2026-05-06
- **Deciders:** maintainers
- **Tags:** meta, process

## Context

CheckID has been making architectural commitments — schema rules, source-of-truth precedence between SCF / SecFrame / manual overrides, framework-mapping derivation policy, deprecation timelines for back-compat shims — across many PRs without a single durable record of *why* each rule exists.

The two existing documentation surfaces serve different purposes:

- `docs/plans/` holds sprint plans and design exploration (e.g., `2026-04-07-v2.2-v2.3-sprint.md`, `399-sspr-research.md`). Plans describe *what we'll do* and become stale once the work ships.
- `docs/audits/` holds point-in-time inventories of how a portal area is currently configured. Audits describe *what exists* and need re-running when reality drifts.

Neither captures *what rule we have agreed to follow going forward*. As a result:

- New maintainers and downstream consumers have to reverse-engineer policy from commit history, which is incomplete (PR titles describe data changes, not the rules motivating them).
- Recurring debates ("should `hasAutomatedCheck: true` require evidence?", "is `framework-overrides.json` a permanent surface or a gap-fill?") get re-litigated each sprint.
- The discovery report at `docs/plans/399-sspr-research.md` surfaces six decision points that are partly architectural and partly tactical; without a place for the architectural half to live, those decisions either get rolled into a sprint plan (and lost) or never get written down.

## Decision

Adopt **Architecture Decision Records** in `docs/adr/`, using a MADR-light format.

**Location:** `docs/adr/`, sibling of `plans/` and `audits/`.

**Index:** `docs/adr/README.md` lists every ADR by number, title, and current status. New ADRs append a row.

**Filename:** `NNNN-short-kebab-title.md`. Four-digit zero-padded number, allocated in monotonically increasing order. Numbers are immutable once allocated — superseded ADRs keep their number.

**Frontmatter:** every ADR opens with the same metadata block:

```
- Status: Proposed | Accepted | Superseded by NNNN | Deprecated
- Date: YYYY-MM-DD
- Deciders: <names or roles>
- Tags: <freeform comma-separated>
```

**Required sections** (in order):

1. **Context** — What's the situation that prompted this? Include enough detail (numbers, file paths, prior incidents) that a reader six months from now can judge whether the context still holds.
2. **Decision** — The rule we're committing to. Stated as a rule, not a recommendation. Specific enough to be testable.
3. **Consequences** — Both intended (what becomes easier, what's now enforced) and accepted costs (what becomes harder, what migration is required, who needs to do what).

**Optional sections:** Alternatives Considered, Out of Scope, References, Implementation Notes. Use them when they help future readers; don't pad.

**Lifecycle:**

- An ADR is filed at `Status: Proposed` when the rule is agreed in principle but not yet enforced in code/data.
- It flips to `Status: Accepted` when the implementing PR(s) merge. The merging PR cites the ADR number in its commit message.
- A superseding ADR (a new file with a new number) flips the predecessor to `Status: Superseded by NNNN`. The predecessor stays in the index — never deleted, never renumbered.
- ADRs that become obsolete without replacement get `Status: Deprecated` with a note on why.

## Consequences

**Intended:**

- One findable answer per architectural rule. PR reviewers can ask "which ADR does this contradict?" instead of relitigating each time.
- Non-architectural follow-ups (the data fixes, the schema-validation script, the secframe sync) get cleaner PRs because the rule lives elsewhere.
- The discovery report's six decision points (`docs/plans/399-sspr-research.md` §Phase 2) split cleanly: the durable rules become ADRs 0002–0005; the sprint scope/sequencing stays in a plan.

**Accepted costs:**

- Small ongoing maintenance: every architecturally significant PR needs to either cite an existing ADR or file a new one. Reviewers should ask for this.
- Risk of ADR sprawl if every minor decision gets one. Default: only file an ADR when the rule will be cited by future PRs or constrains data shape across the registry. A schema field rename, a CI matrix tweak, or a doc reorg does not need one.

**Out of scope:**

- Migrating prior decisions (SCF as source of truth, registry build pipeline, schema v3.0 breaking change) into retroactive ADRs. Those decisions are documented in `docs/architecture.md`, `docs/SCHEMA-MIGRATION-3.0.md`, and `docs/CheckId-Guide.md` and don't need duplication. New ADRs cover decisions made *after* this one.

## References

- MADR (the format this is based on): https://adr.github.io/madr/
- The discovery report that motivated formalizing this: `docs/plans/399-sspr-research.md`
