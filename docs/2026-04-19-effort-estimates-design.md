# Design: Effort Estimation Field for CheckID Registry

**Date:** 2026-04-19
**Status:** Approved
**Schema version:** v2.0.0 → v2.1.0

## Context

CheckID checks vary enormously in implementation complexity. Some are a single config toggle; others (DMARC enforcement, MFA rollout, Conditional Access) require multi-phase rollouts spanning weeks with real risk of disrupting users or mail flow if rushed. Today the registry has no way to communicate this — consumers see severity and weighting but nothing about rollout complexity or disruption risk.

This design adds a first-class `effort` object to every check entry. It is not a bolt-on annotation; it is a core differentiator that informs security admins planning remediation timelines and provides downstream tooling (M365-Assess, M365-Remediate) with structured rollout guidance.

Execution is multi-sprint and research-first. Each sprint has a manual validation gate before data is committed.

## Problem Statement

A DMARC check and a "disable legacy auth" config check may share the same severity rating, yet one takes an afternoon and the other requires a phased organizational rollout over 6+ weeks. Without effort metadata:

- Admins cannot prioritize remediation realistically
- Tooling cannot surface rollout warnings for high-disruption changes
- CheckID provides no differentiation over raw framework mapping tools

## Design

### The `effort` Object

Every check entry in `registry.json` gains an `effort` top-level field:

```json
"effort": {
  "complexity": 3,
  "isPhased": true,
  "phaseCount": 3,
  "disruptionRisk": true,
  "disruptionScope": "user-facing"
}
```

| Field | Type | Values | Meaning |
|---|---|---|---|
| `complexity` | integer | 1–5 | 1 = single config toggle; 5 = multi-team, multi-phase project |
| `isPhased` | boolean | — | True when sequential stages are required (cannot be done atomically) |
| `phaseCount` | integer | 1–n | Number of sequential phases; always 1 when `isPhased` is false |
| `disruptionRisk` | boolean | — | True when the change risks disrupting users, services, or admins |
| `disruptionScope` | enum | `user-facing \| admin-only \| service` | Who is affected; omitted when `disruptionRisk` is false |

### Complexity Scale

| Score | Meaning | Examples |
|---|---|---|
| 1 | Toggle a setting, no user impact | Disable anonymous calendar sharing |
| 2 | Config change, limited blast radius | Enable audit log retention |
| 3 | Multi-step config, some coordination | DKIM signing setup |
| 4 | Org-wide policy change, staged rollout advisable | Block legacy authentication |
| 5 | Multi-team project, mandatory phasing | DMARC enforcement, MFA for all users |

### Derivation Logic

`Build-Registry.py` derives `effort` from existing check fields so no check is ever blank. The derivation is intentionally conservative — it under-flags rather than over-flags, because an incorrect `isPhased: true` confuses admins more than a missed flag.

**Complexity base (from severity):**

| Severity | Base Score |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |
| Informational | 1 |

**Adjustments:**

| Signal | Delta |
|---|---|
| `hasAutomatedCheck: false` | +1 (manual verification adds effort) |
| `licensing.minimum === "E5"` | +1 (E5 controls architecturally more complex) |
| `scf.relativeWeighting >= 8` | +1 (high-weight controls tend to be structural) |
| `category === "CONFIG"` | −1 (toggle-style changes) |

Floor: 1, Ceiling: 5.

**isPhased detection (conservative):**

- Collector is `DNS` (SPF/DKIM/DMARC always require phased deployment)
- Check name contains `enforcement`, `quarantine`, `reject`, or `block`
- Derived `complexity >= 4`

**disruptionRisk + disruptionScope:**

| Condition | Risk | Scope |
|---|---|---|
| severity High/Critical + auth collector (Entra, CAEvaluator) | true | `user-facing` |
| severity High/Critical + email/DNS collector (ExchangeOnline, DNS) | true | `service` |
| severity High/Critical + audit/admin category | true | `admin-only` |
| severity High/Critical + Azure collector (AzAssess) | true | `service` |
| severity Medium/Low | false | null |

### Override Mechanism

Manual corrections live in `data/effort-overrides.json`, keyed by `checkId`. The build script merges overrides on top of derived values. The `_rationale` field is a build-time-only annotation stripped from registry output — it serves as inline research documentation.

```json
{
  "overrides": {
    "DNS-DMARC-001": {
      "complexity": 5,
      "isPhased": true,
      "phaseCount": 3,
      "disruptionRisk": true,
      "disruptionScope": "service",
      "_rationale": "DMARC requires monitor→quarantine→reject with recommended 2-week dwell time between phases. Premature enforcement causes legitimate mail to be rejected."
    }
  }
}
```

## Phased Research & Rollout Plan

### Sprint 1 — Foundation (this PR)
- Schema v2.1.0 with `effort` block
- Derivation logic in `Build-Registry.py`
- `data/effort-overrides.json` with 8 seed entries for known-complex checks
- Research gate: 8 known-complex checks validated ✓

### Sprint 2 — Critical/High Severity (~250 checks)
- Human review of all Critical/High check effort scores
- Author overrides with `_rationale` for corrections
- Refine derivation rules from observed patterns
- Research gate: spot-check 20 random Medium checks

### Sprint 3 — Medium + Known-Complex Deep Dives (~350 checks)
- Extend to Medium severity
- Deep research on top 20–30 known-complex checks — documents phase rationale for future structured `phases` array
- Research gate: override rate should trend down sprint-over-sprint

### Sprint 4 — Low/Informational + Full QA (~200 checks)
- Complete remaining checks
- Cross-reference against M365-Assess remediation flows
- Tag v2.1.0 release

## Future: Structured Phases (v2.2.0)

When tooling has a concrete use case, `phaseCount` can be replaced with a structured array:

```json
"phases": [
  {"name": "monitor", "dwellDays": 14},
  {"name": "quarantine", "dwellDays": 7},
  {"name": "reject"}
]
```

The `_rationale` annotations written during Sprint 3 deep-dives directly seed this work.

## Verification

- All 1,092 checks have a valid `effort` object in `registry.json` output ✓
- Schema version bumped to 2.1.0 ✓
- 8 known-complex checks pass Sprint 1 research gate ✓
- No downstream consumer breakage — `effort` is additive only
- Override rate tracked per sprint as derivation quality metric
