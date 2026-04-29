# MFA Enforcement — Domain Audit (v3.4.0)

**Status:** Third domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#329](https://github.com/Galvnyz/CheckID/issues/329).
**Source priorities:** Microsoft Learn primary (Multi-factor authentication overview, Authentication methods, Plan a phishing-resistant passwordless deployment, Microsoft-managed Conditional Access policies), MSRC blog (AiTM tradecraft + which MFA methods defeat it), CIS M365 v6 §5.2.2.x, CISA SCuBA `MS.AAD.3.x`, NIST 800-63B (AAL2/AAL3), Essential Eight ML2/ML3 P7.

## Summary

CheckID has **29 MFA-related checks** spanning Entra ID (M365) and Azure: 13 in Azure (`AZ-IDENTITY-*`, `AZ-COMPUTE-*`, `AZ-VM-*`), 16 in M365 (`CA-MFA-*` / `CA-PHISHRES-*`, `ENTRA-MFA-*`, `ENTRA-AUTHMETHOD-*`, `ENTRA-PIM-008`, `ENTRA-PERUSER-001`, `ENTRA-SECDEFAULT-*`, `ENTRA-ADMIN-004`). The challenge isn't "is MFA enabled" — it's **"is MFA *effectively* enforced for the right population using the right methods, given the multiple overlapping mechanisms (per-user legacy, Security Defaults, CA, MS-managed, authentication strength)."**

This audit catalogs **38 canonical patterns** across 5 sub-domains and produces a **mechanism reconciliation guide** (the central deliverable of this spike): given the multi-mechanism overlap, what determines effective MFA for any given user. **9 coverage gaps** to file as `feat:` issues, **4 narrative-refresh candidates**, plus a flagged **Azure-vs-M365 audit boundary** since several Azure checks duplicate M365-side intent (e.g., `AZ-IDENTITY-030` vs `CA-MFA-ALL-001`).

## Existing CheckID inventory (M365-Entra subset, 16 checks)

| CheckId | Severity | Pattern category | Notes |
|---|---|---|---|
| `CA-MFA-ALL-001` | High | All-users MFA via CA | CIS §5.2.2.2 |
| `CA-MFA-ADMIN-001` | High | Admin MFA via CA | CIS §5.2.2.1 |
| `CA-PHISHRES-001` | High | Phishing-resistant for admin | CIS §5.2.2.5 |
| `ENTRA-ADMIN-004` | Critical | GA phishing-resistant MFA | Crosses with `CA-PHISHRES-001` |
| `ENTRA-AUTHMETHOD-001` | Medium | Weak methods disabled | |
| `ENTRA-AUTHMETHOD-002` | Medium | Email OTP disabled | |
| `ENTRA-AUTHMETHOD-003` | Low | Authenticator anti-fatigue (number matching, location, app context) | |
| `ENTRA-AUTHMETHOD-004` | Medium | System-preferred MFA | |
| `ENTRA-AUTHMETHOD-005` | Medium | Auth methods migration complete | |
| `ENTRA-AUTHMETHOD-006` | Medium | Suspicious-activity reporting on MFA prompts | |
| `ENTRA-AUTHMETHOD-007` | Low | TAP enabled | |
| `ENTRA-AUTHMETHOD-008` | Medium | TAP single-use | |
| `ENTRA-MFA-001` | High | Users are MFA-capable | |
| `ENTRA-MFA-002` | High | Users without MFA registered (%) | |
| `ENTRA-PERUSER-001` | Medium | Per-user MFA disabled | |
| `ENTRA-PIM-008` | High | MFA on Tier-0 PIM activation | (covered in #328) |
| `ENTRA-SECDEFAULT-001` | High | Security Defaults state | |
| `ENTRA-SECDEFAULT-002` | High | Security Defaults coverage gap analysis | |

**Azure-side (out of M365 scope but listed for reconciliation):** `AZ-IDENTITY-022`, `AZ-IDENTITY-028`, `AZ-IDENTITY-029`, `AZ-IDENTITY-030`, `AZ-IDENTITY-031`, `AZ-IDENTITY-035`, `AZ-IDENTITY-036`, `AZ-IDENTITY-037`, `AZ-IDENTITY-038`, `AZ-COMPUTE-001`, `AZ-VM-011`. Several of these target the same Entra ID configuration as M365 checks — duplication review recommended (chore item below).

## Mechanism reconciliation guide (the central deliverable)

A modern Entra tenant can have MFA enforced through **five mechanisms simultaneously**. Effective enforcement for any given user is the *most-restrictive* outcome across the mechanisms that apply to that user. This is the reasoning every downstream consumer must reproduce to answer "is user X actually protected by MFA."

| Mechanism | Where configured | Applies when | Trumped by |
|---|---|---|---|
| **Security Defaults** | `/policies/identitySecurityDefaultsEnforcementPolicy` | Always-on; tenant-wide; can't customize | Any CA policy (Security Defaults turns OFF when CA is configured) |
| **Per-user MFA (legacy)** | Per-user `strongAuthenticationRequirements` (legacy MSOL) | Account has `Enforced` or `Enabled` state | Modern auth methods policy migration disables this path |
| **CA policy (legacy `requireMfa`)** | CA policy `grantControls.builtInControls=["mfa"]` | User+app+conditions match an enabled CA policy | Authentication strength reference on the same CA replaces it |
| **CA policy (authentication strength)** | CA policy `grantControls.authenticationStrength.id` | Same as above; modern path | Lowest-of-strengths if multiple CA policies apply with different strengths |
| **Microsoft-managed CA policy** | CA policy with `templateId` set | Microsoft-rolled policy auto-enabled (e.g., admin MFA mandate Aug 2024) | Custom CA policy with stricter grant control |

### Decision tree: "is user X enforced with MFA?"

1. Resolve user's role membership and group membership (transitive).
2. Enumerate CA policies that apply to (user, target app) — match `users.includeUsers/Groups/Roles`, `applications.includeApplications`, `conditions.*`, accounting for `excludeUsers/Groups/Roles`.
3. For each applicable CA policy, determine effective grant control:
   - If `state=disabled` or `enabledForReportingButNotEnforced` → policy is not enforcing.
   - If `grantControls.authenticationStrength.id` set → resolve to allowed methods at `/policies/authenticationStrengthPolicies/<id>`. This is what the user must satisfy.
   - Else if `grantControls.builtInControls` contains `"mfa"` → user must satisfy *any* MFA method enabled tenant-wide.
4. If no enforcing CA policy applies AND Security Defaults is enabled → user is MFA-required by Security Defaults baseline.
5. If user has per-user MFA `Enforced` AND auth methods policy migration is incomplete → user is MFA-required (legacy path).
6. Otherwise: user is **not effectively enforced** with MFA.

The decision tree's *correctness* depends on knowing the auth methods policy migration state (`/policies/authenticationMethodsPolicy/policyMigrationState`) — this is why `ENTRA-AUTHMETHOD-005` is a foundational check.

## 1. Enforcement mechanism inventory patterns

### 1.1 Per-user MFA legacy state

**Intent:** All accounts in the legacy per-user MFA `Enforced`/`Enabled` state should be migrated to CA-driven MFA. Continued legacy state masks effective enforcement and creates UX inconsistency.
**Detection:** MSOL/Graph beta legacy endpoint surfaces per-user MFA state. Modern path: count users where the migration state is "Migration Complete" should equal user population.
**Pitfalls:** Microsoft is deprecating the per-user MFA endpoint; reporting may shift over time.
**Authoritative sources:** Microsoft Learn — Migrate from per-user MFA to Conditional Access.
**Coverage:** ✅ `ENTRA-PERUSER-001`. **Narrative refresh recommended** — should explicitly tie to migration state and be paired with `ENTRA-AUTHMETHOD-005`.

### 1.2 Security Defaults state

**Intent:** Small tenants without P1 should have Security Defaults enabled (baseline MFA + admin MFA + legacy auth block). Tenants with CA configured should have Security Defaults *disabled* (Microsoft auto-disables but verify).
**Detection:** `/policies/identitySecurityDefaultsEnforcementPolicy.isEnabled`.
**Pitfalls:** Security Defaults state interacts with CA — having both is impossible per Microsoft enforcement, but transitional states between them are observable.
**Authoritative sources:** Microsoft Learn — Security Defaults.
**Coverage:** ✅ `ENTRA-SECDEFAULT-001` (presence) + `ENTRA-SECDEFAULT-002` (CA gap-coverage analysis). **Narrative refresh recommended** — should explicitly state when Security Defaults is the *correct* answer (no P1, no CA strategy yet).

### 1.3 CA-driven MFA presence (baseline)

**Intent:** Regardless of mechanism, every authenticated user has *some* MFA enforcement path.
**Detection:** Cross-reference: Security Defaults enabled OR ≥1 enabled CA policy targeting all users with MFA grant.
**Pitfalls:** Cross-mechanism reasoning is the hard part — see decision tree above.
**Coverage:** ✅ `CA-MFA-ALL-001`. **Narrative refresh recommended** — current rationale doesn't address the multi-mechanism reconciliation.

### 1.4 Microsoft-managed CA policies state

**Intent:** Microsoft has begun auto-rolling CA policies onto tenants (admin MFA mandate Aug 2024, with more coming). These should be enabled and not duplicated by custom policies that disagree.
**Detection:** CA policies with `templateId` set; verify `state=enabled`. Check for custom policies that have similar conditions but lack the templateId reference (potential conflict).
**Authoritative sources:** Microsoft Learn — Microsoft-managed Conditional Access policies.
**Coverage:** **Gap.** File `feat: ENTRA-MSMANAGED-MFA-001`. *Crosses with #327's `CA-MSMANAGED-MFA-MANDATE-001`.* Should be one CheckID; coordinate.

### 1.5 Hybrid mechanism overlap detection

**Intent:** When multiple mechanisms are simultaneously active (e.g., Security Defaults + CA, OR per-user MFA + CA), surface as anti-pattern with reconciliation guidance.
**Detection:** Reconciliation cross-check across `ENTRA-SECDEFAULT-001`, CA policy enumeration, and per-user MFA migration state.
**Coverage:** ✅ partial via `ENTRA-SECDEFAULT-002` + `ENTRA-PERUSER-001` independently. **Gap:** no aggregating "multi-mechanism conflict" check. File `feat: ENTRA-MFA-MECHANISM-OVERLAP-001`.

## 2. Coverage breadth patterns

### 2.1 All-users baseline MFA

**Intent:** Every member user passes through MFA on authentication.
**Detection:** See decision tree above; per user resolved.
**Coverage:** ✅ `CA-MFA-ALL-001`, `ENTRA-MFA-001` (capable), `ENTRA-MFA-002` (registered %).

### 2.2 Admin tier MFA stricter than baseline

**Intent:** Admins use stricter authentication strength than all-users baseline.
**Detection:** CA policy targeting admin roles with `authenticationStrength` reference more restrictive than the all-users policy's strength.
**Coverage:** ✅ `CA-MFA-ADMIN-001` for presence. **Gap:** no check that admin strength is *stricter than* all-users strength. File `feat: ENTRA-MFA-ADMIN-STRICTER-001`.

### 2.3 Phishing-resistant for admin

**Intent:** Admin tier specifically uses phishing-resistant methods (FIDO2, WHfB, CBA, passkeys).
**Detection:** CA admin policy uses an authentication strength whose `allowedCombinations` is restricted to phishing-resistant.
**Coverage:** ✅ `CA-PHISHRES-001`, `ENTRA-ADMIN-004`. **Possible duplication** — both check related ground.

### 2.4 Guest user MFA

**Intent:** B2B guests authenticate with MFA on first sign-in to your tenant.
**Detection:** CA policy targeting `users.includeUsers=["GuestsOrExternalUsers"]` with MFA grant; or cross-tenant access policy `inboundTrust.isMfaAccepted=true` only when partner tenant verified to enforce MFA.
**Coverage:** **Gap (cross-domain).** Coordinate with #327's `CA-GUEST-MFA-001` and #333 (external collaboration). One CheckID, not three.

### 2.5 Service account / break-glass exclusion review

**Intent:** Documented exclusions exist and are minimal; unaccounted exclusions are flagged.
**Detection:** Cross-reference CA policies' `users.excludeUsers/Groups`; verify each excluded principal is documented.
**Coverage:** ✅ partial via `CA-EXCLUSION-001` (privileged admins excluded). **Gap:** general "all CA exclusions reviewed" check. Lower priority — file `feat: ENTRA-MFA-EXCLUSION-INVENTORY-001` if v3.4.0 budget allows.

### 2.6 Workload identity MFA / authentication context

**Intent:** Service principals accessing sensitive resources gated through CA + auth context.
**Coverage:** **Gap (cross-domain).** Crosses with #327 §2.9 `CA-WORKLOAD-001`.

## 3. Method strength patterns

### 3.1 Phishing-resistant adoption rate

**Intent:** Tenant has measurable adoption of FIDO2 / CBA / WHfB beyond a token presence check — actively measure registration % across users.
**Detection:** `/reports/authenticationMethods/usersRegisteredByFeature` aggregates registration by method. Phishing-resistant adoption % = (users registered for FIDO2 OR CBA OR WHfB) / total user count.
**Pitfalls:** "Adoption" without enforcement is hollow — must pair with CA policy that *requires* phishing-resistant for sensitive scenarios.
**Coverage:** **Gap.** File `feat: ENTRA-MFA-PHISHRES-ADOPTION-001`.

### 3.2 Authenticator with number matching enabled

**Intent:** Microsoft Authenticator push notifications require number matching (defeats MFA fatigue / push bombing).
**Detection:** `/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator.featureSettings.numberMatchingRequiredState.state` = `enabled`.
**Pitfalls:** Microsoft enforces number matching by default since Feb 2023; legacy tenants may still have it explicitly disabled.
**Authoritative sources:** Microsoft Learn — Microsoft Authenticator authentication method (number matching, additional context).
**Coverage:** ✅ `ENTRA-AUTHMETHOD-003` (anti-fatigue / number matching).

### 3.3 SMS / Voice retired (or restricted to legacy users)

**Intent:** SMS and voice as MFA methods are deprecated in modern best practice for admin tier; for end users, scoped to legacy migration only.
**Detection:** `authenticationMethodsPolicy/authenticationMethodConfigurations/Sms.state` and `Voice.state` = `disabled` OR scoped via `excludeTargets` for admin roles.
**Pitfalls:** SMS removal can lock users out — phased rollout via `excludeTargets` typical.
**Authoritative sources:** NIST 800-63B (deprecates SMS for AAL2+); Microsoft — phasing out SMS for admin tiers.
**Coverage:** ✅ partial via `ENTRA-AUTHMETHOD-001` (weak methods disabled). **Narrative refresh** — should explicitly call out SMS / Voice as the weak methods, not generic "weak."

### 3.4 Hardware OATH token usage

**Intent:** Hardware OATH tokens enabled where business needs require offline MFA.
**Detection:** `authenticationMethodsPolicy/authenticationMethodConfigurations/HardwareOath.state` and target groups.
**Coverage:** **Gap, low priority.** File `feat: ENTRA-AUTHMETHOD-OATH-001` only if v3.4.0 budget allows.

### 3.5 Authentication strength policies in use

**Intent:** Tenants on modern path use `authenticationStrength` references in CA, not legacy `builtInControls=["mfa"]`.
**Detection:** Inventory enabled CA policies; calculate % using authentication strength vs legacy MFA grant.
**Coverage:** **Gap.** File `feat: ENTRA-MFA-STRENGTH-ADOPTION-001`. *Pairs with #327 §4.9 `CA-LEGACY-MFA-GRANT-001` — same surface, different framing. Reuse single CheckID.*

## 4. Registration coverage patterns

### 4.1 Users MFA-capable

**Intent:** All licensed members are reachable for MFA challenges (have a phone, email, or registered method).
**Detection:** `/reports/authenticationMethods/userRegistrationDetails`; flag users with `isMfaCapable=false`.
**Coverage:** ✅ `ENTRA-MFA-001`.

### 4.2 Users with strong methods registered

**Intent:** Beyond capable, users actively have strong methods registered (Authenticator, FIDO2, WHfB, TAP).
**Detection:** `userRegistrationDetails.methodsRegistered` includes ≥1 strong method.
**Coverage:** ✅ partial via `ENTRA-MFA-002` (% with method registered). **Gap:** distinction between "any method" and "strong method." File `feat: ENTRA-MFA-STRONG-REGISTERED-001`.

### 4.3 Registration campaign configured

**Intent:** Authentication methods registration campaign is configured to nudge users with weak/no method to register strong methods.
**Detection:** `/policies/authenticationMethodsPolicy/registrationEnforcement.authenticationMethodsRegistrationCampaign.state=enabled`, with target groups, target methods.
**Coverage:** **Gap.** File `feat: ENTRA-AUTHMETHOD-CAMPAIGN-001`.

### 4.4 Temporary Access Pass availability

**Intent:** TAP enabled with appropriate length + lifetime for onboarding scenarios (FIDO2 enrollment, password reset bootstrap).
**Detection:** `authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass.state=enabled`; `defaultLifetimeInMinutes` reasonable; `isUsableOnce=true` for single-use scenarios.
**Coverage:** ✅ `ENTRA-AUTHMETHOD-007` (presence) + `ENTRA-AUTHMETHOD-008` (single-use). **Cross-spike** — TAP detail belongs in #330.

### 4.5 Authentication methods policy migration completed

**Intent:** Legacy MFA settings page is deprecated; tenant should be on the converged authentication methods policy with migration state = "Migration Complete."
**Detection:** `/policies/authenticationMethodsPolicy/policyMigrationState=migrationComplete`.
**Pitfalls:** "preMigration" or "migrationInProgress" states leave the tenant in inconsistent enforcement — different mechanism wins for different users.
**Authoritative sources:** Microsoft Learn — Migrate MFA and SSPR to authentication methods policy.
**Coverage:** ✅ `ENTRA-AUTHMETHOD-005`.

## 5. Anti-patterns (deliberate detection)

### 5.1 Per-user MFA + CA both active

**Intent:** Hybrid enforcement causes UX inconsistency and unpredictable effective state.
**Detection:** Any user with per-user MFA `Enforced`/`Enabled` AND tenant has CA policies. Should be surfaced even if CA policy doesn't apply to that user.
**Coverage:** ✅ partial via `ENTRA-PERUSER-001`. **Narrative refresh** — should explicitly call this hybrid state out.

### 5.2 Phone-based methods as the only registered method for admin

**Intent:** Admin tier should not have only SMS/voice/phone-call as registered methods. Phishing-resistant required for admin per modern guidance.
**Detection:** Per Tier-0 admin: registered methods set; flag if intersect with phishing-resistant methods is empty.
**Coverage:** **Gap.** File `feat: ENTRA-MFA-ADMIN-WEAK-METHOD-001`.

### 5.3 Disabled methods that legacy CA policy still requires

**Intent:** A CA policy with `builtInControls=["mfa"]` references the auth methods that are tenant-enabled. If you disable SMS but a legacy CA policy expected it as the user's only registered method, that user is now blocked.
**Detection:** Cross-reference: CA policies requiring MFA × users without registered enabled methods.
**Pitfalls:** Effectively the same query as 4.1 (users not MFA-capable).
**Coverage:** ✅ partial via `ENTRA-MFA-001` and method-state checks. **Narrative refresh** — recommend pairing.

### 5.4 "Allow Skip MFA registration" still permitted

**Intent:** No grace period or skip option for MFA registration.
**Detection:** `authenticationMethodsPolicy/registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays` should be 0 or low.
**Coverage:** Folds into 4.3 `ENTRA-AUTHMETHOD-CAMPAIGN-001` body.

### 5.5 MFA via SMS for admin roles

**Intent:** NIST + Microsoft deprecate SMS for AAL2+ on admin tier specifically.
**Coverage:** Folds into 5.2 `ENTRA-MFA-ADMIN-WEAK-METHOD-001`.

### 5.6 Trust home-tenant MFA without verification

**Intent:** Cross-tenant `inboundTrust.isMfaAccepted=true` is acceptable only when the partner tenant is verified to enforce MFA.
**Coverage:** **Gap (cross-domain).** Crosses with #333 (external collaboration spike).

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| Mechanism inventory | 5 | 4 | 2 (1.1, 1.2 refresh; 1.3 refresh) | 2 (1.4 MS-managed, 1.5 overlap detection) |
| Coverage breadth | 6 | 3 | 0 | 3 (2.2 admin-stricter, 2.4 guest-cross-domain, 2.5 exclusion-inventory low-pri) |
| Method strength | 5 | 2 | 1 (3.3 SMS/Voice refresh) | 3 (3.1 adoption rate, 3.4 OATH low-pri, 3.5 strength-adoption cross-spike) |
| Registration coverage | 5 | 3 | 0 | 2 (4.2 strong-registered, 4.3 campaign) |
| Anti-patterns | 6 | 2 | 2 (5.1, 5.3 refresh) | 1 (5.2 admin-weak-method) — others fold or cross-spike |
| **Total** | **27** | **14** | **5** | **9 to file** |

(Plus 5 cross-spike patterns folded into #327, #328, #330, #333 — not double-counted here.)

## Threat-pattern map

| Compromise pattern | What enables it | MFA control that breaks it |
|---|---|---|
| Password spray on legacy auth | Per-user MFA legacy + legacy auth not blocked | Block legacy auth (#327 §1.4); migrate to CA-driven MFA |
| Push-bombing / MFA fatigue | Microsoft Authenticator without number matching | Number matching enabled (3.2) + suspicious activity reporting (`ENTRA-AUTHMETHOD-006`) |
| Adversary-in-the-Middle (AiTM) phishing | SMS / push MFA for admin | Phishing-resistant required for admin (2.3, #327 §1.3) |
| MFA registration spoofing (attacker registers method first) | No registration campaign + no TAP | TAP for legitimate onboarding (4.4) + registration campaign (4.3) |
| Hybrid-mechanism enforcement gap | Per-user MFA + CA simultaneously, weak method survives | Mechanism overlap detection (1.5) + migration completion (4.5) |
| Cross-tenant trust abuse | `inboundTrust.isMfaAccepted=true` with unverified partner | Partner verification (5.6, #333) |

## Detection method appendix

### Primary endpoints

```
GET /policies/authenticationMethodsPolicy                            → tenant-wide methods enablement
GET /policies/authenticationMethodsPolicy/policyMigrationState       → migration progress (preMigration|migrationInProgress|migrationComplete)
GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/<method>
                                                                     → per-method state (Fido2, MicrosoftAuthenticator, X509Certificate, TemporaryAccessPass, Sms, Voice, Email, HardwareOath, SoftwareOath)
GET /reports/authenticationMethods/userRegistrationDetails          → per-user registration distribution
GET /reports/authenticationMethods/usersRegisteredByFeature         → aggregate registration metrics
GET /policies/authenticationStrengthPolicies                        → built-in + custom strengths (allowedCombinations)
GET /identity/conditionalAccess/policies                            → CA policy inventory (cross-link with #327)
GET /policies/identitySecurityDefaultsEnforcementPolicy             → Security Defaults state
```

### Edge cases

1. **Per-user MFA endpoint deprecation.** Microsoft is sunsetting the legacy MSOL per-user MFA path. The state is best read from auth methods policy migration state (1.1, 4.5) rather than per-user attribute.
2. **`policyMigrationState` is the gating signal for everything else.** Until migration is complete, multiple mechanisms simultaneously affect any user; effective state is opaque. This is why `ENTRA-AUTHMETHOD-005` is foundational — it determines whether the rest of the auth-methods picture is actually meaningful.
3. **Authentication strength resolution by name is not authoritative.** A custom strength named "phishing-resistant" might allow SMS in `allowedCombinations`. Always resolve to `allowedCombinations`.
4. **Microsoft-managed strength IDs are stable.** `phishingResistantMfa` is the built-in strength ID; rely on it for consistency.
5. **`registrationEnforcement.authenticationMethodsRegistrationCampaign`** has both `state` and per-method subobjects. State must be `enabled` AND `includeTargets` non-empty AND target methods include strong ones to be meaningful.
6. **Security Defaults disabled !== "intentional"** — Microsoft auto-disables when CA is configured. Verify intent: if no CA exists *and* Security Defaults is disabled, that's a real gap (no MFA at all).
7. **`ENTRA-AUTHMETHOD-005` and `ENTRA-PERUSER-001` interaction.** If migration is complete but per-user MFA Enforced still appears on accounts, the per-user state is stale-cosmetic but doesn't enforce. If migration is *not* complete, per-user MFA is still the active path.
8. **Microsoft built-in vs custom auth strengths** — built-ins are upgraded by Microsoft; custom strengths drift if not maintained.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 9):**

1. `feat: ENTRA-MSMANAGED-MFA-001` — MS-managed CA policy state (1.4) — *single CheckID with #327's `CA-MSMANAGED-MFA-MANDATE-001`*
2. `feat: ENTRA-MFA-MECHANISM-OVERLAP-001` — multi-mechanism overlap aggregator (1.5)
3. `feat: ENTRA-MFA-ADMIN-STRICTER-001` — admin auth strength stricter than all-users (2.2)
4. `feat: ENTRA-MFA-EXCLUSION-INVENTORY-001` — full CA exclusion review (2.5) — *low priority*
5. `feat: ENTRA-MFA-PHISHRES-ADOPTION-001` — phishing-resistant adoption rate (3.1)
6. `feat: ENTRA-AUTHMETHOD-OATH-001` — hardware OATH state (3.4) — *low priority*
7. `feat: ENTRA-MFA-STRENGTH-ADOPTION-001` — auth strength vs legacy `requireMfa` adoption (3.5) — *single CheckID with #327's `CA-LEGACY-MFA-GRANT-001`*
8. `feat: ENTRA-MFA-STRONG-REGISTERED-001` — users with strong methods registered % (4.2)
9. `feat: ENTRA-AUTHMETHOD-CAMPAIGN-001` — registration campaign configured (4.3)
10. `feat: ENTRA-MFA-ADMIN-WEAK-METHOD-001` — admin with only weak methods (5.2, 5.5)

**Cross-spike (single CheckID, document overlap):**

- `CA-GUEST-MFA-001` (#327 §3.1) covers 2.4 — guest MFA enforcement
- `CA-WORKLOAD-001` (#327 §2.9) covers 2.6 — workload identity MFA / auth context

**Narrative refresh (`chore:` issues, 5):**

- `chore: refresh ENTRA-PERUSER-001 narrative` — explicitly tie to migration state; call out hybrid anti-pattern
- `chore: refresh ENTRA-SECDEFAULT-001 narrative` — clarify when SD is the correct answer
- `chore: refresh CA-MFA-ALL-001 narrative` — multi-mechanism reconciliation context (already flagged in #327)
- `chore: refresh ENTRA-AUTHMETHOD-001 narrative` — explicitly name SMS/Voice as the weak methods
- `chore: refresh ENTRA-MFA-001 / -002 narrative` — pair with auth-strength state for stronger signal

**Azure-vs-M365 audit boundary (`chore:` issue):**

- `chore: reconcile AZ-IDENTITY-* MFA checks vs M365 equivalents` — `AZ-IDENTITY-030` (MFA all users) and `CA-MFA-ALL-001` may target the same Entra ID config; review for duplication or scope-distinction.

## Out of scope (handled by sibling spikes)

- Authentication methods policy itself, deeper per-method config — spike #330
- Token / session security — spike #331
- Workload identity MFA / federated credentials — #327 + #328
- Cross-tenant MFA trust — #333
- AiTM phishing-resistant defense matrix — handled in #327 §AiTM defense matrix
