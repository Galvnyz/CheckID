# Architecture Decision Records

This directory captures durable architectural and policy decisions for CheckID — the rules that outlive any single sprint or PR.

ADRs are not the same as plans (`docs/plans/`) or audits (`docs/audits/`):

- **Plans** describe *what we'll do this sprint* — task lists with checkboxes, throwaway after the work ships.
- **Audits** describe *what currently exists* — point-in-time inventories of patterns, gaps, and findings.
- **ADRs** describe *what rule we have agreed to* — durable choices that constrain future PRs (schema rules, source-of-truth precedence, validation policies, naming policies). When an ADR is superseded, the old one stays in place with a `Status: Superseded by NNNN` line so the history is intact.

Format and lifecycle are defined in [0001-adopt-adrs.md](0001-adopt-adrs.md).

## Index

| #    | Title                                                                                | Status   |
| ---- | ------------------------------------------------------------------------------------ | -------- |
| 0001 | [Adopt Architecture Decision Records](0001-adopt-adrs.md)                            | Proposed |
| 0002 | [Portal-path navigation parents are a constrained vocabulary](0002-portal-path-vocabulary.md) | Proposed |
| 0003 | [`hasAutomatedCheck: true` must document a mechanism](0003-automated-check-requires-mechanism.md) | Proposed |
| 0004 | [Source-of-truth precedence for portal paths](0004-portal-path-source-of-truth.md)   | Proposed |
| 0005 | [Coverage gaps without supported Graph API](0005-coverage-gaps-without-graph-api.md) | Proposed |

## Conventions

- Filename: `NNNN-short-kebab-title.md` (zero-padded four-digit number).
- Numbers are immutable once allocated. Never renumber. Superseded ADRs keep their number.
- Status transitions: `Proposed` → `Accepted` (merged + implementation in flight or done) → optionally `Superseded by NNNN` or `Deprecated`.
- New ADRs are filed at `Proposed` and only flip to `Accepted` when the implementing PR(s) merge — citing the ADR number in the commit message.
