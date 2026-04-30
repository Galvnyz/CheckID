# Token + Session Security — Domain Audit (v3.4.0)

**Status:** Fifth domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#331](https://github.com/Galvnyz/CheckID/issues/331).
**Source priorities:** Microsoft Learn primary (Continuous Access Evaluation, Token Protection sign-in session binding, Conditional Access session controls, Configurable token lifetime, Revoke user access in Microsoft Entra ID), MSRC + Microsoft Threat Intelligence (AiTM tradecraft + token theft mitigation), CISA AA23-XXX adversary advisories, MITRE ATT&CK T1539/T1550.001/T1556.

## Summary

CheckID has **8 M365-scope token/session-related checks** plus 1 cross-tier check that lives in the Azure namespace but governs Entra ID (`AZ-IDENTITY-039` Token Protection consideration). This audit catalogs **22 canonical token + session security patterns** across 5 sub-domains (CAE coverage, sign-in frequency + session controls, Token Protection, refresh token + revocation, anti-patterns) and maps them against the registry. **9 coverage gaps** to file as `feat:` issues, **3 narrative-refresh candidates**, and one notable boundary issue: `AZ-IDENTITY-039` covers Token Protection in the AZ namespace but the same control governs M365 — should it be `ENTRA-TOKEN-PROTECTION-001` instead?

This audit completes the AiTM defense layer started in #327 (CA spike). The CA audit's threat-pattern map mapped specific AiTM kit tradecraft (EvilProxy, Tycoon 2FA, Storm-1167) to the CA controls that disrupt them. This audit goes deeper into the runtime mechanics: *what tokens exist, how long do they live, when can they be revoked, can they be replayed.*

## Existing CheckID inventory (8 M365-scope + 1 cross-tier)

| CheckId | Severity | Pattern category | Notes |
|---|---|---|---|
| `CA-INTUNE-001` | Medium | Sign-in frequency | Intune enrollment ("Every time") |
| `CA-SESSION-001` | Medium | Persistent browser | Without device compliance — anti-pattern |
| `CA-SIGNIN-FREQ-001` | Medium | Sign-in frequency | Admin tier |
| `ENTRA-CA-SESSIONFREQ-001` | Medium | Sign-in frequency | General CA-level session frequency |
| `ENTRA-SESSION-001` | Medium | Sign-in UX | "Remain signed in?" hidden |
| `ENTRA-SESSIONAUTH-001` | High | Legacy auth blocking (token integrity) | Crosses with `CA-LEGACYAUTH-001` |
| `SPO-SESSION-001` | Medium | Idle session timeout | SharePoint, unmanaged devices |
| `AZ-IDENTITY-039` | High | Token Protection | **In AZ namespace but governs Entra** |

## 1. Continuous Access Evaluation coverage

### 1.1 CAE strict enforcement enabled

**Intent:** CAE is enabled in strict-enforcement mode tenant-wide for CAE-aware applications, so token revocation events (user disabled, password change, risky user, location change, MFA registration) propagate within minutes instead of waiting for the access token's lifetime to expire (default 1 hour).
**Detection:** Per-CA-policy `sessionControls.continuousAccessEvaluation.mode` = `strictEnforcement`. Tenant-wide CAE is on by default in modern Entra ID; the strictEnforcement choice is per-policy.
**Pitfalls:** "Strict enforcement" affects user-visible experience during MS service degradation. The `disableResilienceDefaults` setting interacts: when `false` (the default), tokens stay valid through a 1-hour outage; when `true`, CAE is more aggressive about revoking on signal — more secure, more user-visible.
**Authoritative sources:** Microsoft Learn — Continuous Access Evaluation, Strict enforcement mode.
**Threats defeated:** Reduces window for stolen-token reuse; T1539, T1550.001.
**Coverage:** **Gap.** File `feat: ENTRA-CAE-STRICT-001`. *Cross-domain with #327 §2.4.*

### 1.2 CAE-aware applications inventory

**Intent:** Tenant has identified which apps are CAE-aware (Exchange Online, SharePoint Online, Teams via Microsoft Graph, Office) and confirmed CAE is honored in those flows.
**Detection:** No direct API; document via tenant-side runbook. Sign-in log analysis can confirm CAE event delivery.
**Pitfalls:** CAE-awareness varies by app + SDK version; new apps don't automatically opt in.
**Coverage:** **Gap, partially out of scope.** Document but don't file a CheckID — runtime telemetry rather than config state.

### 1.3 Resilience defaults decision documented

**Intent:** The choice between `disableResilienceDefaults: false` (default — tolerates 1-hour outage) and `true` (more aggressive revocation) is intentional, not accidental.
**Detection:** Per-CA-policy `sessionControls.disableResilienceDefaults`. Read null as default-enabled (i.e., resilience defaults active = less aggressive).
**Pitfalls:** `null` is the Microsoft default state; explicit `false` is the same effective behavior. `true` is the "lean toward security over availability" choice.
**Coverage:** **Gap.** File `feat: ENTRA-CAE-RESILIENCE-001` — flag tenants where the value is mixed across CA policies (inconsistent posture).

## 2. Sign-in frequency + session controls

### 2.1 Sign-in frequency on admin tier

**Intent:** Admin sessions reauthenticate at intervals (1-12 hours per role tier) rather than persisting for the default 90-day refresh-token validity.
**Detection:** Per-CA-policy targeting admin roles, `sessionControls.signInFrequency`:
- `isEnabled` = `true`
- `frequencyInterval` = `timeBased`
- `type` = `hours` or `days` with reasonable value
- `value` ≤ 4 (Tier 0), ≤ 12 (Tier 1), ≤ 24 (Tier 2)

**Pitfalls:** Per-policy frequency interacts with default refresh token lifetime; lower-of-two applies. Multiple CA policies with conflicting values → most-restrictive wins, but the curator may not realize which policy is winning (#327 §4.10).
**Coverage:** ✅ `CA-SIGNIN-FREQ-001` (admin tier), ✅ `ENTRA-CA-SESSIONFREQ-001` (general). **Possible duplication review** — verify these aren't the same control surface.

### 2.2 Sign-in frequency tied to risk

**Intent:** Sign-in frequency reduced (or set to "every time") when sign-in risk is medium or high.
**Detection:** CA policy with both `conditions.signInRiskLevels` populated and `sessionControls.signInFrequency.frequencyInterval` = `everyTime`. This is a powerful pairing that revokes "trust this session" status whenever risk signal triggers.
**Pitfalls:** Requires P2 license for risk signal availability. UX impact when risk signal noisily triggers.
**Coverage:** **Gap.** File `feat: ENTRA-SIGNIN-FREQ-RISK-001`.

### 2.3 Persistent browser session disabled for sensitive scenarios

**Intent:** Browser sessions don't persist across browser closes for admin tier or high-risk apps (token deleted on browser close).
**Detection:** Per-CA-policy `sessionControls.persistentBrowser`:
- `isEnabled` = `true`
- `mode` = `never`
- Scoped to admin or sensitive app

**Pitfalls:** Persistent browser must pair with sign-in frequency for full intent; persistent + no frequency means once-authenticated-always-authenticated for the app session. Standalone persistent-browser-disabled doesn't bound replay window.
**Coverage:** ✅ `CA-SESSION-001` (anti-pattern detection: persistent allowed without device compliance). Pair with sign-in frequency narrative.

### 2.4 SharePoint Online idle session timeout

**Intent:** SPO sessions on unmanaged devices time out after 3 hours of inactivity, bounding cookie-theft replay window.
**Detection:** SharePoint Online tenant config — `Get-SPOTenant.IdleSessionSignOutEnabled` = `$true`, `IdleSessionSignOutDuration` ≤ 180 minutes.
**Coverage:** ✅ `SPO-SESSION-001`. **Narrative refresh recommended** — should explicitly tie to AiTM cookie-theft tradecraft.

### 2.5 "Remain signed in?" prompt hidden

**Intent:** The end-user-facing "Stay signed in?" prompt is hidden tenant-wide so persistent-token decisions are governed by CA policy, not user clicks.
**Detection:** `/policies/companyBranding.signInPageText` and related settings, plus CA policies' persistent-browser settings — combination determines whether the prompt appears.
**Coverage:** ✅ `ENTRA-SESSION-001`.

## 3. Token Protection (sign-in session binding)

### 3.1 Token Protection enforced for Windows clients

**Intent:** Refresh and access tokens are cryptographically bound to the device they were issued on, breaking AiTM token-replay attacks where an attacker captures the post-authentication cookie.
**Detection:** CA policy with `sessionControls.secureSignInSession.isEnabled` = `true`, targeting Windows clients accessing CAE-aware apps (Exchange, SharePoint, Teams via Edge). Modern Graph schema; the property may surface differently across rollout phases.
**Pitfalls:** Phased rollout — `mode` = `monitor` is logging only, not enforcement. Coverage limited to specific app integrations (Exchange, SharePoint, Teams via Edge); Mac/Linux not covered. Some apps will log warnings during phased rollout.
**Authoritative sources:** Microsoft Learn — Token Protection (sign-in session binding) deployment. MSRC — AiTM phishing patterns.
**Threats defeated:** AiTM token theft (EvilProxy, Tycoon 2FA, Storm-1167); T1539 (Steal Web Session Cookie); T1550.001 (Application Access Token).
**Coverage:** ✅ `AZ-IDENTITY-039` (in AZ namespace). **Boundary issue noted** — Token Protection is an Entra control. Suggest re-targeting or adding `ENTRA-TOKEN-PROTECTION-001` in the Entra namespace; cross-link AZ namespace remains for Azure-portal Token Protection scenarios.

### 3.2 Token Protection in monitor-only mode flagged

**Intent:** A tenant configured Token Protection in `mode: monitor` for >30 days indicates intent to enforce never followed through.
**Detection:** Per-CA-policy `secureSignInSession.mode` = `monitor` AND policy `modifiedDateTime` > 30 days.
**Coverage:** **Gap.** File `feat: ENTRA-TOKEN-PROTECTION-MONITOR-STALE-001` (low priority — depends on adoption).

### 3.3 Edge as the gating client for Token Protection

**Intent:** Token Protection requires Microsoft Edge or compatible token-aware browser. Tenants relying on TP need a separate CA policy ensuring sensitive app access uses Edge.
**Detection:** Cross-reference: TP-enforcing CA policy + browser-restriction CA policy.
**Pitfalls:** Browser restriction is hard to enforce gracefully — tradeoff with non-Edge user experience.
**Coverage:** **Gap (cross-domain).** Crosses with #327; suggest a single CheckID `feat: ENTRA-TOKEN-PROTECTION-EDGE-001`.

## 4. Refresh token + revocation

### 4.1 Refresh token validity reviewed

**Intent:** Refresh token defaults (90 days for normal users, configurable per-app) are reviewed against tenant risk tolerance. High-risk workloads may want shorter validity.
**Detection:** `/policies/tokenLifetimePolicies` (legacy) — modern recommendation is to govern via CA `signInFrequency` rather than token-lifetime policies. Most modern tenants have `tokenLifetimePolicies` empty. Detection: confirm migration from token lifetime policies to CA session controls.
**Pitfalls:** `tokenLifetimePolicies` is legacy (deprecated 2021); shouldn't be used in modern tenants. Presence of policies may indicate stale config.
**Coverage:** **Gap.** File `feat: ENTRA-TOKEN-LIFETIME-LEGACY-001` — flag tenants still using deprecated path.

### 4.2 Revocation triggered on sensitive lifecycle events

**Intent:** Sensitive lifecycle events (password change, role assignment change, MFA registration, risky user signal, user disabled) trigger refresh token revocation tenant-wide.
**Detection:** Most are CAE-driven (covered by 1.1) — strict enforcement mode triggers revocation on these events. Configuration per-policy `signInFrequency.frequencyInterval` = `everyTime` for risk-driven enforcement is one path.
**Pitfalls:** Without CAE strict, password change doesn't immediately revoke; user can continue with old refresh token until natural expiry.
**Coverage:** Folds into 1.1 + 2.2.

### 4.3 Account lockout response: post-incident token revocation runbook

**Intent:** SOC has a documented runbook for revoking all tokens for a compromised account (`Revoke-MgUserSignInSession`, `revokeRefreshTokenAsync`).
**Detection:** Procedural — out of automatable scope. Document as "best-effort detection: confirm runbook exists in tenant ownership log."
**Coverage:** **Gap, out of scope.** Document but don't file as a CheckID.

### 4.4 Service principal credential rotation

**Intent:** Service principal client secrets / certificates are rotated periodically and inventory is reviewed.
**Detection:** `/applications/{id}/passwordCredentials` and `keyCredentials` — flag credentials with `endDateTime` > 2 years out, OR credentials > 1 year old.
**Pitfalls:** Some service principals legitimately need long-lived credentials (industrial integrations).
**Coverage:** **Gap (cross-domain).** Crosses with #328 §2.6 (SP with privileged role) — single CheckID `feat: ENTRA-SP-CREDENTIAL-ROTATION-001`.

## 5. Anti-patterns (deliberate detection)

### 5.1 Persistent browser allowed across all apps

**Intent:** Persistent browser sessions for all apps means token theft on any device = long-lived access until natural expiry.
**Coverage:** ✅ `CA-SESSION-001` (specific to no-device-compliance scenario). Folds in.

### 5.2 No sign-in frequency policy on admin roles

**Intent:** Admin tier without sign-in frequency relies on default 90-day refresh-token validity — too lax.
**Coverage:** ✅ `CA-SIGNIN-FREQ-001`.

### 5.3 Sign-in frequency too lax (>30 days)

**Intent:** Even with frequency set, values >30 days defeat the bounded-replay-window intent.
**Detection:** Threshold check on per-policy `signInFrequency.value` AND `type`.
**Coverage:** **Gap.** File `feat: ENTRA-SIGNIN-FREQ-LAX-001`.

### 5.4 CAE disabled "for compatibility"

**Intent:** Tenants that have disabled CAE entirely (rare; usually due to legacy app compatibility) lose the post-event revocation propagation.
**Detection:** Per-CA-policy `continuousAccessEvaluation.mode` = `disabled`.
**Coverage:** Folds into 1.1 detection logic.

### 5.5 Stale refresh tokens for offboarded users

**Intent:** Offboarded users (disabled in directory) shouldn't have valid refresh tokens. CAE strict + `signInActivity` queries surface stragglers.
**Detection:** `users?$filter=accountEnabled eq false`, then check `signInActivity.lastSignInDateTime` against the tokens-likely-valid window.
**Pitfalls:** Detection is best-effort; only available when audit logs retained sufficiently.
**Coverage:** **Gap, low priority.** File `feat: ENTRA-TOKEN-OFFBOARD-STRAGGLER-001`.

### 5.6 Token Lifetime Policy modifications (deprecated)

**Intent:** Tenants modifying `tokenLifetimePolicies` are using a deprecated path. Modern enforcement is CA `signInFrequency`.
**Coverage:** Folds into 4.1.

### 5.7 Mixed `disableResilienceDefaults` across CA policies

**Intent:** Inconsistent CAE resilience posture across multiple CA policies signals undocumented policy drift.
**Coverage:** Folds into 1.3.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| CAE coverage | 3 | 0 | 0 | 2 (1.1 strict, 1.3 resilience; 1.2 documented out-of-scope) |
| Sign-in frequency + session | 5 | 4 | 1 (2.4) | 1 (2.2 risk-tied freq) |
| Token Protection | 3 | 1 | 0 | 2 (3.2 stale monitor, 3.3 Edge gating) — plus 1 boundary issue (3.1 namespace) |
| Refresh token + revocation | 4 | 0 | 0 | 2 (4.1 legacy, 4.4 SP rotation cross-spike); 4.2 + 4.3 fold or out-of-scope |
| Anti-patterns | 7 | 2 | 0 | 2 (5.3 lax freq, 5.5 offboard straggler) — others fold |
| **Total** | **22** | **7** | **1 + boundary** | **9 to file** |

(Plus 2 cross-spike CheckID consolidations: TP-Edge with #327, SP rotation with #328.)

## AiTM kill-chain layered defense

This audit completes the AiTM defense matrix from #327. AiTM phishing kits operate in stages; defense requires layered controls across several domains.

| AiTM stage | Tradecraft | Layer that breaks it | Audit |
|---|---|---|---|
| Initial credential capture | Reverse-proxy phishing kit intercepts password + MFA challenge | Phishing-resistant MFA | #327 §1.3, #330 §1.1, §1.2 |
| MFA bypass | Kit captures the user's MFA approval and forwards | Phishing-resistant strength | #330 §1.1 |
| **Token theft** | **Kit captures the post-authentication session cookie** | **Token Protection** | **#331 §3.1** |
| **Session reuse** | **Token replayed from attacker infrastructure** | **CAE strict enforcement, sign-in frequency** | **#331 §1.1, §2.1, §2.2** |
| Privileged escalation post-compromise | Attacker activates PIM role with stolen session | Auth context for PIM activation | #328 §1.7 |

Tenants lacking any of {phishing-resistant MFA, Token Protection, CAE strict, admin sign-in frequency} are incompletely defended against modern AiTM. The completed-control matrix gives downstream consumers a single signal: *"is this tenant defended at the post-authentication layer."*

## Detection method appendix

### Primary endpoints

```
GET /identity/conditionalAccess/policies                          → CA inventory; session controls per policy
GET /policies/tokenLifetimePolicies                               → legacy; should be empty in modern tenants
GET /policies/tokenIssuancePolicies                               → federation token issuance
GET /applications/{id}                                             → SP credentials, keyCredentials, passwordCredentials
GET /servicePrincipals/{id}                                        → SP delegated permission grants, app role assignments
GET /users?$filter=accountEnabled eq false                         → offboarded user inventory
GET /users/{id}/signInActivity                                     → recent sign-in for token-validity inference
```

### Companion (Exchange + SharePoint side)

| Surface | Used for |
|---|---|
| `Get-SPOTenant` (SPO PowerShell) | `IdleSessionSignOutEnabled`, `IdleSessionSignOutDuration` for 2.4 |
| `Get-OrganizationConfig` (Exchange Online PowerShell) | Mailbox session settings (some), legacy auth state |
| Microsoft Entra audit logs | CAE event delivery, signal propagation timing |
| Microsoft Defender XDR | Sign-in anomaly correlations (post-token-theft signals) |

### Edge cases

1. **CAE state shape evolves.** Older `disableResilienceDefaults: null` means default-enabled (resilient = less aggressive); explicit `false` is the same effective behavior; `true` = strict-leaning. Read null carefully.
2. **Token Protection rollout phases.** `secureSignInSession.isEnabled=true` is the GA setting. During phased rollout the tenant may have it in monitor-only via a workload-specific policy. Check `mode` if exposed.
3. **Sign-in frequency interaction.** Parent CA + child CA both setting frequency causes the lower of the two to apply. Multiple policies with conflicting values produce surprising effective behavior.
4. **`signInFrequency.frequencyInterval` enum.** `timeBased` (numeric value + type) vs `everyTime` (no value, force re-auth on every access). `everyTime` paired with `signInRiskLevels` is the modern risk-tied pattern.
5. **`tokenLifetimePolicies` deprecation.** Microsoft deprecated this path 2021; modern tenants should have it empty. Presence indicates stale legacy config OR very specific edge-case requirements.
6. **CAE-aware app registration vs CAE strict.** A tenant may have CAE strict ON but its critical apps may not be CAE-aware (legacy custom apps). Detection should call out the application-by-application gap.
7. **Service principal credentials.** Long-lived secrets/certs are common in industrial integrations. Detection should distinguish user-account vs SP context — different rotation expectations.
8. **Refresh token revocation semantics.** `Revoke-MgUserSignInSession` revokes refresh tokens but not access tokens (those expire naturally within 1 hour). For full revocation, also require CAE strict.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 9):**

1. `feat: ENTRA-CAE-STRICT-001` — CAE strict enforcement (1.1) — *cross-domain with #327 §2.4*
2. `feat: ENTRA-CAE-RESILIENCE-001` — `disableResilienceDefaults` consistency (1.3)
3. `feat: ENTRA-SIGNIN-FREQ-RISK-001` — sign-in frequency tied to risk (2.2)
4. `feat: ENTRA-TOKEN-PROTECTION-MONITOR-STALE-001` — Token Protection in monitor-only > 30 days (3.2)
5. `feat: ENTRA-TOKEN-PROTECTION-EDGE-001` — Edge required for TP-enforced sensitive apps (3.3)
6. `feat: ENTRA-TOKEN-LIFETIME-LEGACY-001` — legacy `tokenLifetimePolicies` populated (4.1)
7. `feat: ENTRA-SP-CREDENTIAL-ROTATION-001` — SP credentials > 2-year lifetime or > 1-year age (4.4) — *single CheckID with #328 §2.6*
8. `feat: ENTRA-SIGNIN-FREQ-LAX-001` — sign-in frequency value > 30 days (5.3)
9. `feat: ENTRA-TOKEN-OFFBOARD-STRAGGLER-001` — offboarded users with potentially valid tokens (5.5) — *low priority*

**Boundary issue (`chore:` issue, 1):**

- `chore: relocate AZ-IDENTITY-039 to ENTRA-TOKEN-PROTECTION-001` — Token Protection is an Entra control; the AZ-namespace placement is a misclassification. Either relocate or add a sibling `ENTRA-TOKEN-PROTECTION-001` and deprecate the AZ-namespace check.

**Narrative refresh (`chore:` issues, 1):**

- `chore: refresh SPO-SESSION-001 narrative` — explicitly tie idle-session-timeout to AiTM cookie-theft tradecraft

## Out of scope (handled by sibling spikes)

- Authentication strength policies — #330
- CA policy structure (which policies, what conditions) — #327
- Browser-side defenses (Edge Token Protection client-side) — Edge product, not M365 config
- Sign-in log analytics for token-theft detection — runtime telemetry, future track
- Workload identity tokens beyond credentials — #328 §2.6, #327 §2.9
