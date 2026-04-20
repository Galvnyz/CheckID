# Design: Effort Estimation Field for CheckID Registry

**Date:** 2026-04-19
**Status:** Complete (v2.9.0)
**Schema version:** v2.0.0 → v2.1.0

## Context

CheckID checks vary enormously in implementation complexity. Some are a single config toggle; others (DMARC enforcement, MFA rollout, Conditional Access) require multi-phase rollouts spanning weeks with real risk of disrupting users or mail flow if rushed. Today the registry has no way to communicate this — consumers see severity and weighting but nothing about rollout complexity or disruption risk.

This design adds a first-class `effort` object to every check entry. It is not a bolt-on annotation; it is a core differentiator that informs security admins planning remediation timelines and provides downstream tooling (M365-Assess, M365-Remediate) with structured rollout guidance.

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

### Derivation Logic (Final — as Shipped)

`Build-Registry.py` derives `effort` from existing check fields so no check is ever blank. The derivation is intentionally conservative — it under-flags rather than over-flags, because an incorrect `isPhased: true` confuses admins more than a missed flag.

**Null severity handling:** 65 AZ-prefixed checks have no `impactRating.severity`. These default to `"Medium"` in the derivation, giving a complexity base of 2. This is intentional — it produces a conservative, non-zero effort estimate rather than an error or a hard-coded fallback that might mislead.

**Complexity base (from severity):**

| Severity | Base Score |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |
| Informational | 1 |
| null / missing | 2 (Medium default) |

**Adjustments:**

| Signal | Delta |
|---|---|
| `hasAutomatedCheck: false` | +1 (manual verification adds effort) |
| `licensing.minimum === "E5"` | +1 (E5 controls architecturally more complex) |
| `scf.relativeWeighting >= 8` | +1 (high-weight controls tend to be structural) |
| `category === "CONFIG"` | −1 (toggle-style changes) |

Floor: 1, Ceiling: 5.

**isPhased detection (conservative — final keyword set):**

- Collector is `DNS` (SPF/DKIM/DMARC always require phased deployment)
- Check name contains any of: `enforcement`, `quarantine`, `reject`
- Derived `complexity >= 4`

> **Design decision (Sprint 4):** `"block"` was removed from the keyword list. Windows GPO check names routinely use "Block" as a setting value (e.g., "Enabled: Block All", "Block untrusted fonts"), not as a deployment phase verb. This caused ~20 WIN-CONFIG and WIN-FIREWALL checks to be incorrectly flagged as phased. The one legitimate case — CA-LEGACYAUTH-001 ("Block Legacy Authentication") — is handled via an explicit override.

`phaseCount` defaults to 3 when phased (monitor → quarantine/warn → enforce), 1 otherwise. Overrides correct known checks.

**disruptionRisk + disruptionScope (final rules):**

| Condition | Risk | Scope |
|---|---|---|
| severity High/Critical + `_USER_FACING_COLLECTORS` | true | `user-facing` |
| severity **Medium** + `_USER_FACING_COLLECTORS` | true | `user-facing` |
| severity High/Critical + email/DNS collector (ExchangeOnline, DNS) | true | `service` |
| severity High/Critical + audit/admin category | true | `admin-only` |
| severity High/Critical + Azure collector (AzAssess) | true | `service` |
| severity Medium/Low + non-user-facing | false | null |

`_USER_FACING_COLLECTORS` (final set): `{"Entra", "CAEvaluator", "SharePoint", "Teams", "Forms", "PowerBI", "Intune"}`

> **Design decision (Sprint 3):** The original rules only flagged user-facing disruption for High/Critical severity + auth collectors (Entra, CAEvaluator). This missed a class of real risk: a Medium-severity SharePoint external-sharing policy, a Teams meeting setting, or an Intune enrollment restriction can disrupt thousands of users even without being rated High. The collector set was expanded (`_AUTH_COLLECTORS` → `_USER_FACING_COLLECTORS`) and Medium severity was added as a trigger for user-facing collectors specifically. Non-user-facing Medium checks remain `disruptionRisk: false`.

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

### AZ Check Post-Processing

AZ-prefixed checks (CIS Azure / Windows Server 2025) bypass `derive_frameworks()` — their framework mappings are loaded directly from source JSON, not derived by the build script. As a result, CMMC `profiles` (L1/L2/L3 level tags) are not populated during the main derivation pass.

A second pass in `main()` handles this:

```python
for check in checks:
    fw = check.get("frameworks", {})
    if "cmmc" in fw and "profiles" not in fw["cmmc"]:
        p = derive_cmmc_profiles(fw["cmmc"].get("controlId", ""))
        if p:
            fw["cmmc"]["profiles"] = p
```

This same pattern applies to any future check source that loads frameworks externally.

## Sprint Outcomes

| Sprint | Scope | Overrides Added | Key Rule Changes |
|---|---|---|---|
| 1 | Foundation: schema, derivation logic, seed overrides | 10 | Initial rules established |
| 2 | Critical/High severity (~250 checks) | 18 | Expanded `disruptionScope` to include AzAssess/service scope |
| 3 | Medium severity + known-complex deep dives | 15 | `_AUTH_COLLECTORS` → `_USER_FACING_COLLECTORS` (expanded); Medium severity added as user-facing disruption trigger |
| 4 | Low/Informational + full QA; false-positive cleanup | 5 | Removed `"block"` from `_PHASED_NAME_KEYWORDS`; restored CA-LEGACYAUTH-001 via override |
| **Total** | **All 1,092 checks** | **48** | — |

**Final registry stats (v2.9.0):**

| Metric | Count |
|---|---|
| Total checks | 1,092 |
| `isPhased: true` | 80 |
| `disruptionRisk: true` | 776 |
| Checks with manual overrides | 48 |
| Override rate | 4.4% |

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
- Schema validation passes (`registry.schema.json` v2.1.0) ✓
- 30 known-complex checks validated manually against expected values (Sprint 1 gate) ✓
- Override rate tracked per sprint: 10 → 28 → 43 → 48 (rate declining relative to sprint scope = derivation improving) ✓
- No downstream consumer breakage — `effort` is additive only ✓
- False-positive `isPhased` count reduced from ~20 to 0 by Sprint 4 rule correction ✓
