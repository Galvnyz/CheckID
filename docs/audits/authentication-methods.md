# Authentication Methods Policy — Domain Audit (v3.4.0)

**Status:** Fourth domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#330](https://github.com/Galvnyz/CheckID/issues/330).
**Source priorities:** Microsoft Learn primary (Authentication methods policy reference, FIDO2/CBA/TAP/Authenticator deployment guides, Migrate MFA and SSPR to authentication methods policy), CISA Phishing-Resistant MFA Implementation Guidance (Oct 2022), NIST 800-63B (AAL2/AAL3 and authenticator definitions), Essential Eight ML2/ML3 P7.

## Summary

CheckID has **8 `ENTRA-AUTHMETHOD-*` checks** plus 2 cross-domain checks (`ENTRA-MFA-001`, `ENTRA-MFA-002`) and 1 broader check (`ENTRA-PERUSER-001`). This audit catalogs **25 canonical authentication methods patterns** across 5 sub-domains (strong methods deployed, onboarding readiness, weak/legacy method state, configuration nuance, anti-patterns) and maps them against the registry. **8 coverage gaps** to file as `feat:` issues, **2 narrative-refresh candidates**, and one structural gap: no per-tenant method-strength scorecard that can answer *"of all your users, what fraction are registered for phishing-resistant methods at all."*

This audit sits one layer below the MFA enforcement audit (#329). #329 covered "is MFA enforced via which mechanism for which user"; this audit covers "what methods are configured tenant-wide, and which actually meet the phishing-resistant bar."

## Existing CheckID inventory (8 ENTRA-AUTHMETHOD-* + 3 cross-domain)

| CheckId | Severity | Pattern category | Notes |
|---|---|---|---|
| `ENTRA-AUTHMETHOD-001` | Medium | Weak methods state | SMS, voice |
| `ENTRA-AUTHMETHOD-002` | Medium | Weak methods state | Email OTP |
| `ENTRA-AUTHMETHOD-003` | Low | Authenticator anti-fatigue | Number matching, additional context |
| `ENTRA-AUTHMETHOD-004` | Medium | Method strength steering | System-preferred MFA |
| `ENTRA-AUTHMETHOD-005` | Medium | Migration completeness | Legacy → converged policy |
| `ENTRA-AUTHMETHOD-006` | Medium | Anomaly reporting | Suspicious activity reporting on MFA |
| `ENTRA-AUTHMETHOD-007` | Low | Onboarding readiness | TAP enabled |
| `ENTRA-AUTHMETHOD-008` | Medium | Onboarding readiness | TAP single-use |
| `ENTRA-MFA-001` | High | Method registration | Users MFA-capable |
| `ENTRA-MFA-002` | High | Method registration | % registered |
| `ENTRA-PERUSER-001` | Medium | Migration completeness | Per-user MFA disabled (overlaps `-005`) |

## 1. Strong methods deployed

### 1.1 FIDO2 enabled with attestation enforcement

**Intent:** FIDO2 security keys are enabled at the tenant level AND attestation is enforced (counterfeit / unverified keys are rejected).
**Detection:** `GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2`:
- `state` = `enabled`
- `isAttestationEnforced` = `true`
- `keyRestrictions.aaGuids` populated with allowed authenticator GUIDs (or `enforcementType` = `block` to forbid known-vulnerable models)
- `includeTargets` covers the user population

**Pitfalls:** State enabled without attestation enforced means any FIDO2-claiming device passes; counterfeit keys with weak crypto can pose as legitimate FIDO2 authenticators. AAGUID restriction is the modern best practice.
**Authoritative sources:** Microsoft Learn — FIDO2 security key authentication, AAGUID-based key restrictions. CISA Phishing-Resistant MFA guidance.
**Threats defeated:** AiTM phishing (kit can't relay FIDO2 challenge); T1556 (Modify Authentication Process).
**Coverage:** **Gap.** File `feat: ENTRA-AUTHMETHOD-FIDO2-ATTESTATION-001`.

### 1.2 Certificate-Based Authentication (CBA) enabled and configured

**Intent:** CBA enabled as a phishing-resistant method, with proper user-binding policy and authentication-strength-class assignment.
**Detection:** `authenticationMethodConfigurations/X509Certificate`:
- `state` = `enabled`
- `certificateUserBindings` populated (e.g., bind on UPN, EmailAddress, or onPremisesUserPrincipalName)
- `authenticationModeConfiguration.x509CertificateAuthenticationDefaultMode` = `x509CertificateMultiFactor` (single-factor cert auth is an anti-pattern for admin tier)
- Issuer trust configured via the tenant's certificate-based auth issuer hints

**Pitfalls:** `singleFactorAuthentication` mode means cert presentation alone authenticates without password — fine for some scenarios, anti-pattern for admin. CRL/OCSP revocation checking must be working tenant-wide (a separate concern).
**Authoritative sources:** Microsoft Learn — Certificate-based authentication overview, How to configure issuer hints.
**Coverage:** **Gap.** File `feat: ENTRA-AUTHMETHOD-CBA-001`.

### 1.3 Microsoft Authenticator with number matching + context

**Intent:** Authenticator push notifications require the user to enter a 2-digit number shown by the sign-in surface (defeats blind approval / MFA fatigue) AND show additional context (geographic location, app name).
**Detection:** `authenticationMethodConfigurations/MicrosoftAuthenticator.featureSettings`:
- `numberMatchingRequiredState.state` = `enabled`
- `displayLocationInformationRequiredState.state` = `enabled`
- `displayAppInformationRequiredState.state` = `enabled`

**Pitfalls:** Microsoft now enforces number matching by default tenant-wide (since Feb 2023), but legacy tenants may still have it explicitly disabled. Display context is independent and not always default-on.
**Authoritative sources:** Microsoft Learn — Microsoft Authenticator authentication method, Number matching reference.
**Threats defeated:** MFA fatigue / push bombing (Lapsus$ tradecraft, Storm-X actor playbooks).
**Coverage:** ✅ `ENTRA-AUTHMETHOD-003`. **Narrative refresh recommended** — should explicitly call out push bombing tradecraft and the additional-context settings.

### 1.4 Windows Hello for Business deployment

**Intent:** WHfB cloud trust is enabled and deployed on managed Windows endpoints, providing phishing-resistant biometric/PIN authentication tied to TPM.
**Detection:** Cross-references — Intune device configuration profile (`/deviceManagement/deviceConfigurations` filtering `windowsIdentityProtectionConfiguration`), plus authentication methods policy entry for WHfB if exposed there. WHfB deployment is largely Intune/MDM scope so this is a cross-domain check.
**Pitfalls:** Deployment is multi-step (cloud trust setup, Intune profile, AD CA for cloud-only or on-prem trust models). Detection should focus on Intune profile presence + tenant-wide auth methods policy state.
**Authoritative sources:** Microsoft Learn — Windows Hello for Business cloud trust deployment.
**Coverage:** **Gap (cross-domain).** Crosses with #334 (Intune spike). Suggest single CheckID `feat: ENTRA-AUTHMETHOD-WHFB-001` filed here, owned across both audits.

### 1.5 Passkey support enabled

**Intent:** Passkeys (FIDO2 platform credentials) are supported in Microsoft Authenticator and recommended for end-user phishing-resistant scenarios.
**Detection:** Authenticator's `featureSettings` controlling passkey support (`isSoftwareOathEnabled` and related). Microsoft is rolling out device-bound passkeys in Authenticator over 2024-2026; specific policy properties evolve.
**Pitfalls:** Passkey + FIDO2 + Authenticator + WHfB are all phishing-resistant methods that overlap; a tenant may have multiple paths. Detection should answer "is at least one phishing-resistant method available to all users."
**Authoritative sources:** Microsoft Learn — Passkeys in Microsoft Authenticator.
**Coverage:** **Gap.** File `feat: ENTRA-AUTHMETHOD-PASSKEY-001`.

## 2. Onboarding readiness

### 2.1 Temporary Access Pass enabled with appropriate config

**Intent:** TAP is enabled for the time-limited bootstrap scenarios that gate secure passwordless onboarding, FIDO2 registration, and credential recovery.
**Detection:** `authenticationMethodConfigurations/TemporaryAccessPass`:
- `state` = `enabled`
- `defaultLifetimeInMinutes` ≤ 480 (8 hours; CIS recommends ≤ 60 minutes for highest sensitivity)
- `defaultLength` ≥ 8
- `includeTargets` populated for relevant population (typically `all_users` or admin onboarding group)

**Coverage:** ✅ `ENTRA-AUTHMETHOD-007` for presence.

### 2.2 TAP single-use only

**Intent:** TAPs are single-use — once consumed, they're invalidated regardless of remaining lifetime. Multi-use TAPs are intercepted-then-replayed risk.
**Detection:** `TemporaryAccessPass.isUsableOnce` = `true`.
**Coverage:** ✅ `ENTRA-AUTHMETHOD-008`.

### 2.3 Self-service password reset enabled with strong methods

**Intent:** SSPR is enabled with phishing-resistant methods (Authenticator, FIDO2, security questions DEPRECATED) so users can recover credentials without admin intervention but without weakening the auth posture.
**Detection:** `/policies/authorizationPolicy.allowedToUseSSPR` = `true`. SSPR registration policy at `/policies/authenticationMethodsPolicy/registrationEnforcement.authenticationMethodsRegistrationCampaign`. Plus per-method enabled state.
**Pitfalls:** SSPR with only phone-based methods is weak; should require Authenticator or FIDO2.
**Authoritative sources:** Microsoft Learn — SSPR deployment, Migrate SSPR to authentication methods policy.
**Coverage:** **Gap.** File `feat: ENTRA-AUTHMETHOD-SSPR-001`.

### 2.4 Registration campaign enabled

**Intent:** Authentication Methods registration campaign nudges users without strong methods to register Microsoft Authenticator (or other MS-recommended methods) on next sign-in.
**Detection:** `registrationEnforcement.authenticationMethodsRegistrationCampaign`:
- `state` = `enabled`
- `includeTargets` populated (`all_users` or specific groups)
- `excludeTargets` reasonable (typically excludes service accounts, break-glass)
- `snoozeDurationInDays` ≤ 14 (longer = users dismissing forever)

**Coverage:** **Gap.** File `feat: ENTRA-AUTHMETHOD-CAMPAIGN-001`.

### 2.5 Authentication methods policy migration completed

**Intent:** Tenant has completed migration from legacy MFA settings page + legacy SSPR settings to the converged authentication methods policy.
**Detection:** `/policies/authenticationMethodsPolicy/policyMigrationState` = `migrationComplete`.
**Pitfalls:** `preMigration` or `migrationInProgress` states leave the tenant with multiple effective enforcement paths simultaneously. This is a critical foundational signal — every other check on the auth methods policy is meaningful only after migration completes.
**Coverage:** ✅ `ENTRA-AUTHMETHOD-005`. **Narrative refresh recommended** — should explicitly call this out as the foundational gating signal for the rest.

## 3. Weak / legacy method state

### 3.1 SMS / Voice text either disabled or restricted to legacy users

**Intent:** SMS and voice as primary methods are disabled tenant-wide, OR scoped via `excludeTargets` to specific legacy migration groups for a documented sunset window.
**Detection:** `Sms.state` and `Voice.state` should be `disabled`, or `excludeTargets` should exclude admin roles.
**Pitfalls:** SMS removal can lock users out — phased rollout via `excludeTargets` is typical. The right gate is "SMS not the only method available to admin tier."
**Authoritative sources:** NIST 800-63B (deprecates SMS for AAL2+); Microsoft — phasing out SMS for admin tiers.
**Coverage:** ✅ `ENTRA-AUTHMETHOD-001` (presence). **Narrative refresh recommended** — explicit SMS / Voice naming.

### 3.2 Email OTP for guests only

**Intent:** Email OTP is acceptable for B2B guests on first sign-in but inappropriate for resident user accounts.
**Detection:** `Email.state` = `enabled` AND `includeTargets` scoped to guest user objects only OR `state` = `disabled` (no email OTP at all).
**Coverage:** ✅ `ENTRA-AUTHMETHOD-002`. **Narrative refresh recommended** — current rationale doesn't distinguish the guest-acceptable case from the resident-anti-pattern case.

### 3.3 Hardware OATH token state

**Intent:** Hardware OATH tokens are enabled where business needs require offline MFA (e.g., air-gapped environments, regulated industries with hardware-token mandates).
**Detection:** `HardwareOath.state` and per-target group configuration.
**Pitfalls:** OATH is single-factor in mathematical strength; combining with password is required to satisfy AAL2.
**Coverage:** **Gap, low priority.** File `feat: ENTRA-AUTHMETHOD-OATH-001` only if industry use cases warrant.

### 3.4 Software OATH token disabled where not needed

**Intent:** Software OATH (TOTP via third-party authenticator apps) is disabled in favor of Microsoft Authenticator — the latter has number matching, additional context, and Microsoft-managed feature parity.
**Detection:** `MicrosoftAuthenticator.isSoftwareOathEnabled` = `false`. Or evaluate whether enabled software OATH is scoped appropriately.
**Pitfalls:** Disabling can break users on legacy TOTP apps (Google Authenticator, Authy); transition path needed.
**Coverage:** **Gap.** File `feat: ENTRA-AUTHMETHOD-SWOATH-001` (low priority).

## 4. Configuration nuance

### 4.1 System-preferred MFA enabled

**Intent:** When a user has multiple MFA methods registered, Entra automatically prompts the strongest available method first.
**Detection:** `MicrosoftAuthenticator.featureSettings.systemCredentialPreferences.state` = `enabled` (modern path) or per-method preference flags.
**Coverage:** ✅ `ENTRA-AUTHMETHOD-004`.

### 4.2 Suspicious activity reporting enabled

**Intent:** Users can flag unsolicited MFA prompts as fraud → emits Entra ID Protection risk events.
**Detection:** `MicrosoftAuthenticator.featureSettings.reportSuspiciousActivitySettings`:
- `state` = `enabled`
- `includeTarget.targetType` = `group` and target populated (or `all_users`)

**Coverage:** ✅ `ENTRA-AUTHMETHOD-006`.

### 4.3 Per-method target user/group scoping

**Intent:** Each method's `includeTargets` is reviewed for appropriateness — e.g., FIDO2 enabled for all users is too broad if hardware key distribution isn't universal.
**Detection:** Per-method `includeTargets` enumeration; cross-reference with deployment intent (curator-supplied).
**Pitfalls:** Detection inherently requires curator input — there's no Microsoft-published "right" target list.
**Coverage:** **Out of scope** — too org-specific. Document as not-coverable.

## 5. Anti-patterns (deliberate detection)

### 5.1 Migration not completed

**Intent:** Tenant in `preMigration` or `migrationInProgress` for >90 days indicates stalled migration → ongoing inconsistent enforcement.
**Detection:** `policyMigrationState` ≠ `migrationComplete` AND `tenant creation date` > 6 months ago (heuristic).
**Coverage:** Folds into ✅ `ENTRA-AUTHMETHOD-005` — narrative should call out the stalled-migration anti-pattern.

### 5.2 SMS as fallback method for admin

**Intent:** Admin tier should not have SMS in their registered methods set as a *fallback* (FIDO2/CBA primary, SMS fallback) — fallback to SMS defeats phishing resistance.
**Detection:** Per Tier-0 admin: `userRegistrationDetails.methodsRegistered` includes SMS. Cross-reference with #328 PIM admin tier.
**Coverage:** **Gap (cross-domain).** Crosses with #328 §5.2 and #329 §5.2 — single CheckID `feat: ENTRA-AUTHMETHOD-ADMIN-WEAK-METHOD-001`.

### 5.3 FIDO2 enabled but no attestation enforcement

**Intent:** Already covered as 1.1 — restated as anti-pattern.
**Coverage:** Folds into 1.1 `ENTRA-AUTHMETHOD-FIDO2-ATTESTATION-001`.

### 5.4 CBA enabled with single-factor mode

**Intent:** Already covered as 1.2 anti-pattern variant — restated.
**Coverage:** Folds into 1.2 `ENTRA-AUTHMETHOD-CBA-001`.

### 5.5 TAP with overly long lifetime

**Intent:** TAP `defaultLifetimeInMinutes` > 480 (8 hours) leaves an extended window for interception.
**Detection:** Threshold check on TAP config.
**Coverage:** **Gap.** File `feat: ENTRA-AUTHMETHOD-TAP-LIFETIME-001` (low priority).

### 5.6 No method registered for a high-privilege user

**Intent:** Any Tier-0 admin with no strong-method registration is a single-factor account.
**Detection:** Cross-reference Tier-0 role assignees against `userRegistrationDetails`.
**Coverage:** Folds into #328 (PIM spike) §4.2 `ENTRA-EMERG-MFA-REGISTERED-001` — same control surface.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| Strong methods deployed | 5 | 1 | 1 (1.3) | 4 (1.1 FIDO2, 1.2 CBA, 1.4 WHfB cross-domain, 1.5 Passkey) |
| Onboarding readiness | 5 | 3 | 1 (2.5) | 2 (2.3 SSPR, 2.4 campaign) |
| Weak / legacy method state | 4 | 2 | 2 (3.1, 3.2) | 2 (3.3 OATH low-pri, 3.4 SW-OATH low-pri) |
| Configuration nuance | 3 | 2 | 0 | 0 (4.3 out of scope) |
| Anti-patterns | 6 | 0 | 0 | 1 unique (5.5 TAP lifetime) — others fold or cross-spike |
| **Total** | **23** | **8** | **4** | **8 to file** |

(Plus 3 cross-spike consolidations folded into #328, #329.)

## Threat-pattern map

| Compromise pattern | What enables it | Auth methods control that breaks it |
|---|---|---|
| AiTM phishing (EvilProxy, Tycoon 2FA, Storm-1167) | SMS/push/Authenticator-without-NM as the registered method | Phishing-resistant method available + system-preferred steering (1.1, 1.3, 4.1) |
| MFA fatigue / push bombing (Lapsus$, Storm-X) | Authenticator without number matching | Number matching + additional context (1.3) |
| SIM swap → SMS interception | SMS as enabled method | SMS disabled or scoped (3.1) |
| Email account compromise → OTP interception | Email OTP for resident users | Email OTP scoped to guests only (3.2) |
| Counterfeit FIDO2 key with weak crypto | FIDO2 enabled without attestation | Attestation enforced + AAGUID restrictions (1.1) |
| TAP interception | Multi-use TAP, long lifetime, no rotation | Single-use TAP + ≤8h lifetime (2.1, 2.2, 5.5) |
| Stalled migration → inconsistent enforcement | `policyMigrationState ≠ migrationComplete` | Migration completion (2.5) |
| MFA registration spoofing (attacker registers method first) | No registration campaign + no TAP for admin onboarding | Registration campaign + TAP available (2.4, 2.1) |

## Detection method appendix

### Primary endpoint

```
GET /policies/authenticationMethodsPolicy
GET /policies/authenticationMethodsPolicy/policyMigrationState
GET /policies/authenticationMethodsPolicy/registrationEnforcement
GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations
GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/{method-id}
```

Methods enumerated under `authenticationMethodConfigurations`:
- `Fido2`
- `MicrosoftAuthenticator`
- `X509Certificate`
- `TemporaryAccessPass`
- `Sms`
- `Voice`
- `Email`
- `HardwareOath`
- `SoftwareOath`

### Companion endpoints

| Endpoint | Used for |
|---|---|
| `/reports/authenticationMethods/userRegistrationDetails` | Per-user method registration status |
| `/reports/authenticationMethods/usersRegisteredByFeature` | Aggregate registration by method |
| `/reports/authenticationMethods/userRegistrationFeatureSummary` | Tenant-wide MFA-capable + SSPR-capable counts |
| `/policies/authorizationPolicy` | SSPR allowed (`allowedToUseSSPR`) |
| `/policies/identitySecurityDefaultsEnforcementPolicy` | Security Defaults state (interacts with method enablement) |
| `/identity/conditionalAccess/policies` | CA policies that *enforce* methods (cross-link with #327) |
| `/policies/authenticationStrengthPolicies` | Authentication strength definitions consuming these methods |

### Edge cases

1. **Microsoft-managed defaults.** Several properties (number matching, system-preferred MFA) are Microsoft-managed-defaulted-enabled in modern tenants. Reading `state` = `default` vs `enabled` requires reading the Microsoft current default at the same moment.
2. **`includeTargets` and `excludeTargets` interaction.** A method can be enabled tenant-wide but excluded from specific groups. Effective enabled-for-user resolution requires resolving group membership against include/exclude.
3. **`policyMigrationState` is the foundational gate.** Until `migrationComplete`, multiple effective enforcement paths exist and per-method state is partially decorative.
4. **Authenticator featureSettings nesting.** Number matching, additional context, suspicious activity reporting, system-preferred each have their own `state` + `includeTarget`. Easy to miss one when checking `featureSettings`.
5. **TAP `isUsableOnce` is independent of `defaultLength`.** A short single-use TAP and a long multi-use TAP are different exposure profiles.
6. **CBA modes.** `x509CertificateSingleFactor` vs `x509CertificateMultiFactor` is the AAL distinction. CBA in single-factor mode is acceptable in some scenarios (smartcard-on-device) but anti-pattern for admin tier.
7. **FIDO2 attestation enforcement default.** Microsoft-managed default for new tenants is `true`, but legacy tenants may still have it `false` if explicitly set. Distinguish "Microsoft default" from "explicitly disabled."
8. **Cross-tenant FIDO2 (B2B).** Guest users from federated tenants may register FIDO2 in their home tenant; your tenant's attestation rules don't apply to home-tenant credentials. This is a federation concern, not directly actionable here.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 8):**

1. `feat: ENTRA-AUTHMETHOD-FIDO2-ATTESTATION-001` — FIDO2 enabled with attestation + AAGUID restrictions (1.1, 5.3)
2. `feat: ENTRA-AUTHMETHOD-CBA-001` — CBA enabled with multi-factor mode + user binding (1.2, 5.4)
3. `feat: ENTRA-AUTHMETHOD-WHFB-001` — WHfB cloud trust deployment (1.4) — *cross-domain with #334*
4. `feat: ENTRA-AUTHMETHOD-PASSKEY-001` — Passkey support enabled (1.5)
5. `feat: ENTRA-AUTHMETHOD-SSPR-001` — SSPR enabled with strong methods (2.3)
6. `feat: ENTRA-AUTHMETHOD-CAMPAIGN-001` — Registration campaign configured (2.4)
7. `feat: ENTRA-AUTHMETHOD-OATH-001` — Hardware OATH state (3.3) — *low priority*
8. `feat: ENTRA-AUTHMETHOD-SWOATH-001` — Software OATH disabled (3.4) — *low priority*
9. `feat: ENTRA-AUTHMETHOD-TAP-LIFETIME-001` — TAP overlong lifetime (5.5) — *low priority*

**Cross-spike (single CheckID, document overlap):**

- `ENTRA-AUTHMETHOD-ADMIN-WEAK-METHOD-001` — admin with only weak methods (5.2). Single CheckID with #328 §4.2, #329 §5.2.
- `ENTRA-EMERG-MFA-REGISTERED-001` — break-glass with registered MFA (5.6). Already proposed in #328 §4.2.

**Narrative refresh (`chore:` issues, 4):**

- `chore: refresh ENTRA-AUTHMETHOD-001 narrative` — explicit SMS / Voice naming + AiTM context
- `chore: refresh ENTRA-AUTHMETHOD-002 narrative` — distinguish guest-acceptable from resident-anti-pattern
- `chore: refresh ENTRA-AUTHMETHOD-003 narrative` — call out push bombing tradecraft + additional-context settings
- `chore: refresh ENTRA-AUTHMETHOD-005 narrative` — explicitly call out as foundational gating signal for the rest

## Out of scope (handled by sibling spikes)

- Identity Provider federation choices (PassThru / PHS / federation) — separate concern
- Workload identity authentication methods (federated credentials, certificates) — #327 §2.9, #328 §2.6
- Sign-in policy enforcement (CA-driven MFA) — #327
- Multi-mechanism reconciliation (SD vs CA vs per-user MFA) — #329
- Token / session security after authentication — #331
