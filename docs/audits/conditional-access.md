# Conditional Access — Domain Audit (v3.4.0)

**Status:** First domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#327](https://github.com/Galvnyz/CheckID/issues/327).
**Source priorities:** Microsoft Learn primary, MSRC + Microsoft Threat Intelligence for threat patterns, CIS M365 v6 / CISA SCuBA / NIST 800-53 / Essential Eight for control framing.

## Summary

CheckID currently has **26 Conditional Access checks** across the `CA-*` and `ENTRA-CA-*` namespaces. This audit catalogs **42 canonical CA patterns** drawn from authoritative Microsoft guidance and community baselines, maps them against the registry, identifies **17 coverage gaps** to file as `feat:` issues, and flags **6 existing checks** for narrative refresh.

The most acute gaps cluster around (1) **modern controls** Microsoft has rolled out since 2024 — Token Protection, authentication strength policies, Microsoft-managed CA policies, authentication context — and (2) **anti-pattern detection** — exclusion-group misuse, ineffective `requireMfa` after authentication-strength deprecation, hidden-effective-policy reasoning across overlapping rules.

## Existing CheckID inventory (26 checks)

| CheckId | Severity | Pattern category | CIS M365 v6 | CISA SCuBA |
|---|---|---|---|---|
| `CA-DEVICE-001` | High | Device compliance | 5.2.2.9 | MS.AAD.3.6v1 |
| `CA-DEVICE-002` | Medium | Device compliance | 5.2.2.10 | MS.AAD.3.7v1 |
| `CA-DEVICECODE-001` | High | Device-code flow | 5.2.2.12 | — |
| `CA-EXCLUSION-001` | High | Anti-pattern (admin exclusion) | 5.1.2.1 | MS.AAD.3.1v1; MS.AAD.3.2v2 |
| `CA-FALLBACK-001` | High | Anti-pattern (empty include set) | — | — |
| `CA-INTUNE-001` | Medium | Sign-in frequency | 5.2.2.11 | MS.AAD.3.8v1 |
| `CA-LEGACYAUTH-001` | High | Legacy auth block | 5.2.2.3 | MS.AAD.1.1v1 |
| `CA-MFA-ADMIN-001` | High | Foundational MFA (admin) | 5.2.2.1 | MS.AAD.3.1v1 |
| `CA-MFA-ALL-001` | High | Foundational MFA (all users) | 5.2.2.2 | MS.AAD.3.2v2; MS.AAD.3.3v2 |
| `CA-NAMEDLOC-001` | High | Named-location quality | — | — |
| `CA-NAMEDLOC-002` | Medium | Anti-pattern (stale named-location ref) | — | — |
| `CA-PHISHRES-001` | High | Phishing-resistant MFA (admin) | 5.2.2.5 | MS.AAD.3.1v1 |
| `CA-REMOTEDEVICE-001` | High | Device compliance (remote access) | — | — |
| `CA-REPORTONLY-001` | Medium | Anti-pattern (report-only persistence) | — | — |
| `CA-RISKPOLICY-001` | Medium | Anti-pattern (risk-policy combination) | — | — |
| `CA-ROLECOVERAGE-001` | High | Coverage gap (Tier-0 roles missing) | — | — |
| `CA-SESSION-001` | Medium | Session controls (persistent browser) | — | — |
| `CA-SIGNIN-FREQ-001` | Medium | Session controls (admin sign-in freq) | 5.2.2.4 | MS.AAD.7.6v1 |
| `CA-SIGNINRISK-001` | High | Identity Protection (sign-in risk) | 5.2.2.7 | MS.AAD.2.3v1 |
| `CA-SIGNINRISK-002` | High | Identity Protection (sign-in risk block) | 5.2.2.8 | MS.AAD.2.3v1 |
| `CA-STALEREF-001` | Medium | Anti-pattern (stale group ref) | — | — |
| `CA-USERRISK-001` | High | Identity Protection (user risk) | 5.2.2.6 | MS.AAD.2.1v1 |
| `ENTRA-CA-001` | High | Legacy auth block (duplicate of CA-LEGACYAUTH-001?) | 5.2.2.3 | MS.AAD.1.1v1 |
| `ENTRA-CA-002` | Medium | Meta (CA policy count) | — | — |
| `ENTRA-CA-003` | Medium | Meta (enabled-policy count) | — | — |
| `ENTRA-CA-SESSIONFREQ-001` | Medium | Session sign-in freq | — | — |

**Immediate consolidation issue:** `CA-LEGACYAUTH-001` and `ENTRA-CA-001` cover the same control (block legacy auth) with the same CIS + SCuBA mappings. One should be deprecated and aliased; flagged for follow-up `chore:` issue.

## 1. Foundational coverage patterns

The "do you have a baseline" tier — these are what every tenant should have running before tuning anything more sophisticated.

### 1.1 Baseline MFA for all users

**Intent:** Every authenticated session passes through MFA, with break-glass accounts as the only documented exception.
**Detection:** At least one CA policy with state=`enabled`, `users.includeUsers=["All"]` (or equivalently scoped via groups), `applications.includeApplications=["All"]`, and a grant control that effectively requires MFA — modern: `authenticationStrength` set to a strength meeting MFA criteria; legacy: `builtInControls` includes `mfa`. Break-glass accounts present in `users.excludeUsers`.
**Pitfalls:** Per-user MFA legacy state still active masks effective enforcement; Security Defaults appears as MFA but blocks customization; Microsoft-managed policy with `templateId` set may shadow custom policy intent.
**Authoritative sources:** Microsoft Learn — Plan a Conditional Access deployment; Plan an MFA deployment. CIS M365 v6 §5.2.2.2. CISA SCuBA MS.AAD.3.2v2 / MS.AAD.3.3v2. NIST 800-53 IA-2(1).
**Threats defeated:** T1078.004 (Cloud Accounts) — credential-only phishing, password spray.
**Coverage:** ✅ `CA-MFA-ALL-001`. **Narrative refresh recommended** — current rationale doesn't address Microsoft-managed policy interaction or per-user MFA legacy reconciliation.

### 1.2 Stricter MFA for privileged roles

**Intent:** Admin tier authenticates with phishing-resistant MFA, separate from the all-users baseline.
**Detection:** CA policy targeting `users.includeRoles` covering at minimum: Global Admin, Privileged Role Admin, Privileged Authentication Admin, Conditional Access Admin, Security Admin, Application Admin, Cloud Application Admin, Helpdesk Admin, Authentication Admin, Authentication Policy Admin, User Admin, SharePoint Admin, Exchange Admin, Compliance Admin, Compliance Data Admin, Security Reader, Security Operator, Reports Reader, Hybrid Identity Admin, Intune Admin, Teams Administrator. Grant control: `authenticationStrength` reference to a phishing-resistant strength (Microsoft-managed `phishingResistantMfa` or custom).
**Pitfalls:** Role list missing recent additions (e.g., new built-in roles added between MS releases); custom roles with admin-equivalent permissions not covered; PIM eligible roles vs active roles — CA evaluates active membership only.
**Authoritative sources:** Microsoft Learn — Authentication strength overview; Recommend Conditional Access policy: Require MFA for admins. MSRC — Microsoft-managed Conditional Access policies (admin MFA mandate). CIS §5.2.2.1. SCuBA MS.AAD.3.1v1.
**Threats defeated:** T1078.004; T1098 (Account Manipulation by privileged compromise).
**Coverage:** ✅ `CA-MFA-ADMIN-001` for MFA presence. **Gap:** no check ensures the role list is **complete** (missing roles = missing coverage). File `feat: CA-ROLECOMPLETE-001`.

### 1.3 Phishing-resistant MFA for admin tier

**Intent:** Admin tier specifically must use phishing-resistant methods (FIDO2, Windows Hello for Business, certificate-based authentication, passkeys); push-MFA / SMS / Authenticator-without-number-matching does not satisfy the bar.
**Detection:** CA policy targeting admin roles (as in 1.2) with `grantControls.authenticationStrength.id` matching a strength whose `allowedCombinations` is restricted to phishing-resistant methods. Microsoft built-in: `phishingResistantMfa` strength id.
**Pitfalls:** Custom authentication strength named "phishing-resistant" that allows e.g. SMS in `allowedCombinations`; legacy `builtInControls: ["mfa"]` grant which does NOT satisfy phishing-resistant intent.
**Authoritative sources:** Microsoft Learn — Phishing-resistant authentication strength. CISA — Implementing Phishing-Resistant MFA (Oct 2022). Essential Eight P7 ML2/ML3.
**Threats defeated:** AiTM phishing kits (EvilProxy, Tycoon 2FA, Storm-1167); T1556 (Modify Authentication Process); T1539 (Steal Web Session Cookie) when paired with Token Protection.
**Coverage:** ✅ `CA-PHISHRES-001`. **Narrative refresh recommended** — should explicitly cite AiTM kits and document custom-strength misconfiguration as a pitfall.

### 1.4 Block legacy authentication

**Intent:** Basic authentication, IMAP, POP, SMTP AUTH, and other non-OAuth flows are universally blocked.
**Detection:** CA policy with `state=enabled`, `conditions.clientAppTypes` includes `exchangeActiveSync` and `other` (or just `other` in the client-app filter on the new policy shape), `grantControls.builtInControls=["block"]`, and broad user/app inclusion.
**Pitfalls:** Tenant has Exchange Online basic auth disabled at the protocol level (Microsoft EOL'd basic auth Oct 2022) so the CA policy is partially redundant, but still needed for SharePoint legacy clients and edge protocols; `clientAppTypes` set incorrectly (`all` is the deprecated default — must explicitly include legacy-app types).
**Authoritative sources:** Microsoft Learn — Block legacy authentication; Deprecation of Basic authentication in Exchange Online. CIS §5.2.2.3. SCuBA MS.AAD.1.1v1.
**Threats defeated:** Password spray against legacy protocols; T1110.003 (Password Spraying); T1078 (Valid Accounts).
**Coverage:** ✅ `CA-LEGACYAUTH-001` AND ✅ `ENTRA-CA-001` — **duplicate coverage**, see consolidation note above.

### 1.5 Sign-in risk policy (Identity Protection)

**Intent:** High and medium sign-in risk events trigger MFA challenge or block. Powered by Microsoft Entra ID Protection.
**Detection:** CA policy with `conditions.signInRiskLevels` containing `high` (and ideally `medium`), grant control either MFA challenge (`authenticationStrength`) or block.
**Pitfalls:** Identity Protection requires P2 license — un-licensed tenants render the policy non-functional even when configured. Combining sign-in risk with user risk in the same policy is documented anti-pattern (different remediation flows expected).
**Authoritative sources:** Microsoft Learn — Sign-in risk policy. SCuBA MS.AAD.2.3v1. CIS §5.2.2.7 / 5.2.2.8.
**Threats defeated:** Anomalous sign-in patterns (impossible travel, atypical location); T1078.
**Coverage:** ✅ `CA-SIGNINRISK-001` (presence) + ✅ `CA-SIGNINRISK-002` (block-on-medium-and-high).

### 1.6 User risk policy (Identity Protection)

**Intent:** High user risk (compromised credential indicator) requires password reset before further access.
**Detection:** CA policy with `conditions.userRiskLevels=["high"]`, grant control requiring password change or block.
**Pitfalls:** P2 licensing dependency; password change requires SSPR enabled to succeed.
**Authoritative sources:** Microsoft Learn — User risk policy. SCuBA MS.AAD.2.1v1. CIS §5.2.2.6.
**Threats defeated:** Credential leak detection from MS threat intel feeds; T1078, T1110.
**Coverage:** ✅ `CA-USERRISK-001`.

### 1.7 Device compliance requirement

**Intent:** Sensitive resource access requires a managed, compliant device (Intune-evaluated) or Hybrid Entra Joined.
**Detection:** CA policy with `grantControls.builtInControls` containing `compliantDevice` or `domainJoinedDevice` (or both), targeting all users + all apps, or scoped to high-risk apps.
**Pitfalls:** Compliance evaluation requires Intune managed policy assignment; tenants without Intune get no enforcement signal regardless of CA configuration.
**Authoritative sources:** Microsoft Learn — Require compliant device. CIS §5.2.2.9 / 5.2.2.10. SCuBA MS.AAD.3.6v1 / MS.AAD.3.7v1.
**Threats defeated:** T1078 from unmanaged endpoints; T1539 cookie theft from compromised personal devices.
**Coverage:** ✅ `CA-DEVICE-001`, ✅ `CA-DEVICE-002`, ✅ `CA-REMOTEDEVICE-001`.

### 1.8 Block device-code flow

**Intent:** OAuth device code grant flow is restricted to documented use cases (PowerShell admin scenarios, IoT) and blocked for end users.
**Detection:** CA policy filtering `authenticationFlows.transferMethods` containing `deviceCodeFlow` and grant control `block`, with appropriate exception scope.
**Pitfalls:** Used by legitimate admin tooling — fully blocking can break operational scripts; need named exception groups.
**Authoritative sources:** Microsoft Learn — Authentication flows in Conditional Access. CIS §5.2.2.12.
**Threats defeated:** Device-code phishing (Storm-2372 / Midnight Blizzard tradecraft documented in MS Threat Intelligence reports).
**Coverage:** ✅ `CA-DEVICECODE-001`.

## 2. Surface-area coverage patterns

The "have you applied controls everywhere they're needed" tier.

### 2.1 Mobile platform application protection

**Intent:** Mobile (iOS/Android) access requires App Protection Policy (MAM) enforcement on Office apps.
**Detection:** CA policy with `conditions.platforms.includePlatforms` = iOS+Android, `grantControls.builtInControls` containing `approvedApplication` or `compliantApplication`. Or grant `requireAppProtectionPolicy`.
**Pitfalls:** Both `approvedApplication` and `requireAppProtectionPolicy` exist; latter is the modern path.
**Authoritative sources:** Microsoft Learn — Configure Conditional Access for Intune App Protection.
**Threats defeated:** Data exfil from unmanaged BYOD; T1530 (Data from Cloud Storage).
**Coverage:** **Gap.** File `feat: CA-MOBILE-MAM-001`.

### 2.2 Sign-in frequency tied to risk + role

**Intent:** Sign-in frequency reduced for admin tier and high-risk apps to bound token lifetime.
**Detection:** CA policy with `sessionControls.signInFrequency.value` set, `type=hours` or `days`, scoped appropriately.
**Pitfalls:** Per-policy frequency override interacts with default; lower-of-two applies.
**Authoritative sources:** Microsoft Learn — Configure sign-in frequency. CIS §5.2.2.4. SCuBA MS.AAD.7.6v1.
**Coverage:** ✅ `CA-SIGNIN-FREQ-001` and `ENTRA-CA-SESSIONFREQ-001` — **possible overlap**, audit during narrative refresh.

### 2.3 Persistent browser session disabled for sensitive scenarios

**Intent:** Browser sessions don't persist across browser closes for admin or high-risk app access.
**Detection:** CA policy with `sessionControls.persistentBrowser.mode=never`, `isEnabled=true`, scoped to admin or sensitive app.
**Pitfalls:** Persistent browser must be paired with sign-in frequency for the full intent; standalone is insufficient.
**Authoritative sources:** Microsoft Learn — Persistent browser session.
**Coverage:** ✅ `CA-SESSION-001`.

### 2.4 Continuous Access Evaluation enabled

**Intent:** CAE delivers near-real-time policy enforcement (token revocation on user disable, password change, location change, risky user). Default-enabled in modern tenants but the `disableResilienceDefaults` setting interacts.
**Detection:** Tenant CAE state at `/identity/conditionalAccess/policies` plus per-policy `sessionControls.continuousAccessEvaluation.mode` (modern shape) — `strictEnforcement` is the secure setting.
**Pitfalls:** Resilience defaults `disableResilienceDefaults: false` means a 1-hour outage allows stale tokens; `true` is more secure but may cause user-visible interruption during MS service degradation.
**Authoritative sources:** Microsoft Learn — Continuous Access Evaluation; Strict enforcement.
**Threats defeated:** Reduces window for stolen-token reuse; T1539, T1550.001.
**Coverage:** **Gap.** File `feat: CA-CAE-001`.

### 2.5 Token Protection (sign-in session binding)

**Intent:** Refresh and access tokens are cryptographically bound to the device they were issued on, breaking AiTM token-replay attacks.
**Detection:** CA policy with `sessionControls.secureSignInSession.isEnabled=true` (preview/GA per current Graph schema), targeting Windows clients accessing Exchange / SharePoint.
**Pitfalls:** Phased rollout — `mode=monitor` is logging only, not enforcement; coverage limited to specific apps (Exchange, SharePoint, Teams via Edge), Mac/Linux not covered.
**Authoritative sources:** Microsoft Learn — Token Protection (sign-in session binding) deployment. MSRC — AiTM phishing patterns.
**Threats defeated:** AiTM token theft (EvilProxy, Tycoon 2FA, Storm-1167); T1539, T1550.001.
**Coverage:** **Gap.** File `feat: CA-TOKEN-PROTECTION-001`.

### 2.6 Authentication context for sensitive resources

**Intent:** Specific sensitive operations (PIM activation, sensitive SharePoint sites, sensitive Teams channels) require step-up to a stricter CA policy.
**Detection:** Auth context definitions at `/identity/conditionalAccess/authenticationContextClassReferences`, referenced by sensitive resources, and a CA policy `conditions.authenticationContexts.includeAuthenticationContextClassReferences` matching.
**Pitfalls:** Auth context defined but not actually referenced by any resource = dead config.
**Authoritative sources:** Microsoft Learn — Conditional Access authentication context.
**Threats defeated:** T1078.004 with elevation paths; sensitive-resource scoping.
**Coverage:** **Gap.** File `feat: CA-AUTHCONTEXT-001`.

### 2.7 Application-specific policies (high-risk apps)

**Intent:** High-risk apps (Microsoft Graph PowerShell, Microsoft Azure Management, Office 365 Management API) get stricter controls than baseline.
**Detection:** CA policy targeting specific `applications.includeApplications` IDs (e.g., `00000003-0000-0000-c000-000000000000` for Graph) with strict grant controls.
**Pitfalls:** Microsoft service principals are first-party; blocking them breaks tenant operation.
**Authoritative sources:** Microsoft Learn — Application IDs of commonly used Microsoft applications.
**Coverage:** **Gap.** File `feat: CA-APPSPECIFIC-001`.

### 2.8 Network location filtering

**Intent:** Trusted IPs/countries reduce friction; untrusted regions trigger block or step-up.
**Detection:** CA policy with `conditions.locations.includeLocations` or `excludeLocations` referencing namedLocations.
**Pitfalls:** IP-based locations are spoofable via VPN; relying on IP location alone is weak. Country-based requires Microsoft IP geolocation which has accuracy limits.
**Authoritative sources:** Microsoft Learn — Conditional Access named locations.
**Coverage:** ✅ `CA-NAMEDLOC-001` (location quality), ✅ `CA-NAMEDLOC-002` (stale ref).

### 2.9 Workload identity protection

**Intent:** Service principals + managed identities accessing sensitive resources are governed by CA, not just user policies.
**Detection:** CA policy with `conditions.clientApplications.includeServicePrincipals` populated and grant controls applied. Requires Workload Identities Premium license.
**Pitfalls:** Default tenant has no workload-identity CA — common gap. License gates capability.
**Authoritative sources:** Microsoft Learn — Conditional Access for workload identities.
**Threats defeated:** T1098.001 (Additional Cloud Credentials); T1078.004 via service principal abuse.
**Coverage:** **Gap.** File `feat: CA-WORKLOAD-001`.

## 3. External / guest collaboration patterns

### 3.1 Guest user MFA enforcement

**Intent:** B2B guests authenticate with MFA on first sign-in to your tenant; MFA claims from home tenant trusted only when cross-tenant policy says so.
**Detection:** CA policy with `users.includeUsers=["GuestsOrExternalUsers"]` AND grant control requires MFA. Plus cross-tenant access policy `inboundTrust.isMfaAccepted` setting.
**Pitfalls:** Trusting home-tenant MFA without verifying that home tenant actually enforces it = false sense of coverage.
**Authoritative sources:** Microsoft Learn — Conditional Access for B2B users; Cross-tenant access settings.
**Threats defeated:** Compromised partner-tenant credentials gaining access without MFA; T1199 (Trusted Relationship).
**Coverage:** **Gap.** File `feat: CA-GUEST-MFA-001`.

### 3.2 Tenant restrictions v2 (outbound managed-device protection)

**Intent:** Managed devices can only authenticate to your tenant + explicitly allowed external tenants; prevents users from signing in to personal accounts from corporate devices.
**Detection:** Cross-tenant access default `automaticUserConsentSettings`, plus per-tenant entries with `tenantRestrictions.usersAndGroups` rules.
**Pitfalls:** Tenant Restrictions v2 requires Microsoft Edge or Tenant Restrictions client agent for enforcement; un-instrumented clients bypass.
**Authoritative sources:** Microsoft Learn — Tenant restrictions v2.
**Coverage:** **Gap.** File `feat: CA-TENANT-RESTRICTIONS-001`.

### 3.3 B2B Direct Connect partner gating

**Intent:** Shared channels (Teams) and B2B Direct Connect are only with explicitly approved partner tenants.
**Detection:** Cross-tenant policy `partners[].b2bDirectConnectInbound` populated; tenant default outbound off.
**Pitfalls:** Default-deny posture is correct but requires explicit allow per partner.
**Authoritative sources:** Microsoft Learn — Configure cross-tenant access for B2B Direct Connect.
**Coverage:** **Gap.** File `feat: CA-B2B-DIRECT-001` (note: overlaps with planned external collaboration spike #333).

## 4. Anti-patterns (deliberate detection)

### 4.1 Privileged admins in CA exclusion lists

**Intent:** Admin accounts cannot be excluded from CA — break-glass is the only legitimate exclusion.
**Detection:** CA policies' `users.excludeUsers` or `users.excludeGroups` resolved → checked for privileged role membership (current OR PIM-eligible).
**Pitfalls:** Exclusion of a group whose membership later changes; PIM eligibility expansion.
**Coverage:** ✅ `CA-EXCLUSION-001`.

### 4.2 Empty include set (policy applies to nobody)

**Intent:** A CA policy with no valid include user/group/role/app is a no-op.
**Detection:** Resolve all `users.includeUsers/Groups/Roles` and `applications.includeApplications` against directory; if all references invalid OR all groups have zero members, policy is dead.
**Pitfalls:** Group with members but soft-deleted users still counts as members in Graph.
**Coverage:** ✅ `CA-FALLBACK-001`.

### 4.3 Stale group / named-location references

**Intent:** CA conditions referencing deleted entities have undefined behavior — Entra silently elides them, often inverting policy intent.
**Detection:** Resolve all GUID references in conditions; flag any 404.
**Coverage:** ✅ `CA-STALEREF-001` (groups), ✅ `CA-NAMEDLOC-002` (named locations).

### 4.4 Report-only policies persisting indefinitely

**Intent:** Report-only is for testing; long-lived report-only policies indicate forgotten testing or hesitation to enforce.
**Detection:** Policies with `state=enabledForReportingButNotEnforced` and `modifiedDateTime` > 30 days ago.
**Coverage:** ✅ `CA-REPORTONLY-001`.

### 4.5 Disabled policies still in inventory

**Intent:** Disabled policies are clutter at best, intent-confusion at worst (curators may think coverage exists when it doesn't).
**Detection:** Policies with `state=disabled` for > 90 days.
**Pitfalls:** Some intentional disabled holds (waiting for partner change) — needs annotation/exemption mechanism.
**Coverage:** **Gap.** File `feat: CA-DISABLED-STALE-001`.

### 4.6 Risk-policy combination anti-pattern

**Intent:** Combining sign-in risk + user risk in one policy mixes remediation flows; should be separate policies.
**Detection:** Single CA policy with both `signInRiskLevels` and `userRiskLevels` set.
**Coverage:** ✅ `CA-RISKPOLICY-001`.

### 4.7 Break-glass excluded but not properly hardened

**Intent:** Break-glass accounts ARE excluded from lockout-prone CA, but should still have MFA registered and continuous monitoring (modern guidance — not the legacy "exclude from all MFA" pattern).
**Detection:** Identify break-glass exclusions; verify MFA registration on those accounts; verify sign-in alerting is configured.
**Pitfalls:** Distinction between "excluded from this lockout-risk policy" (correct) vs "excluded from all MFA" (legacy, no longer recommended).
**Authoritative sources:** Microsoft Learn — Manage emergency access accounts.
**Coverage:** **Gap.** File `feat: CA-BREAKGLASS-HARDENED-001`.

### 4.8 Microsoft-managed policy disabled or duplicated

**Intent:** Microsoft-managed CA policies (auto-rolled-out, marked with `templateId`) shouldn't be disabled. Custom policies that duplicate the same intent without MS-managed reference create reconciliation overhead.
**Detection:** Policies with `templateId` set + `state=disabled`; policies whose conditions exactly match an MS-managed template but lack the templateId.
**Coverage:** **Gap.** File `feat: CA-MSMANAGED-001`.

### 4.9 Legacy `requireMfa` after authentication-strength deprecation

**Intent:** Modern CA uses `authenticationStrength` references; the legacy `builtInControls: ["mfa"]` is being deprecated. Tenants on the legacy form get less granular MFA enforcement.
**Detection:** CA policies using `builtInControls: ["mfa"]` without `authenticationStrength` set.
**Pitfalls:** Microsoft auto-migrates some scenarios but not all; manual tenant-by-tenant remediation often needed.
**Authoritative sources:** Microsoft Learn — Authentication strength overview (migration section).
**Coverage:** **Gap.** File `feat: CA-LEGACY-MFA-GRANT-001`.

### 4.10 Hidden effective policy (overlapping rules with conflicting grant controls)

**Intent:** When two CA policies cover the same user + app + condition with different grant controls, Entra applies the most-restrictive — but the curator may not realize which policy is winning.
**Detection:** Cross-policy overlap analysis: for each (user, app) pair, list applicable policies and their grant controls; surface conflicts where intent is unclear.
**Pitfalls:** Computationally expensive on large tenants; needs heuristic prioritization.
**Coverage:** **Gap.** File `feat: CA-EFFECTIVE-POLICY-001` (potentially deferred — implementation complexity).

## 5. Modern (2024-2026) patterns

### 5.1 Authentication strength policies in active use

**Intent:** Move from `builtInControls: ["mfa"]` to `authenticationStrength` for granular method enforcement.
**Detection:** % of MFA-enforcing CA policies using `authenticationStrength` vs legacy `builtInControls`.
**Coverage:** **Gap** (paired with 4.9 above).

### 5.2 Microsoft-managed policies (admin MFA mandate)

**Intent:** Microsoft auto-rolled the admin MFA mandate (initially Aug 2024); tenants must keep these policies enabled or document why not.
**Detection:** Policies with `templateId` matching MS-managed templates; verify `state=enabled`.
**Coverage:** **Gap.** File `feat: CA-MSMANAGED-MFA-MANDATE-001`.

### 5.3 Phishing-resistant for admin (Microsoft default rollout)

**Intent:** Microsoft is staging phishing-resistant requirement for admin tier across tenants; check the rollout state.
**Detection:** Microsoft-managed policy presence + state.
**Coverage:** Partially covered by `CA-PHISHRES-001` for custom policy; **gap** for MS-managed policy detection.

### 5.4 Passkey enablement for end users

**Intent:** Passkeys (FIDO2 platform credentials, including in Microsoft Authenticator) are the modern phishing-resistant default for non-admin users too.
**Detection:** Authentication methods policy state for FIDO2 + Passkeys (out of CA scope, into auth methods spike #330) plus CA policy that requires phishing-resistant strength for sensitive applications.
**Coverage:** Crosses with #330 spike.

### 5.5 Authentication context for PIM-activated roles

**Intent:** PIM activation triggers a CA evaluation against an auth context, enforcing stricter MFA at the moment of role activation.
**Detection:** PIM role policies referencing auth context IDs that match CA policies' `conditions.authenticationContexts`.
**Coverage:** **Gap.** Crosses with PIM spike #328.

### 5.6 Insider risk integration via Adaptive Protection

**Intent:** Microsoft Purview Adaptive Protection signals (insider risk levels) feed into CA policies for elevated-risk users.
**Detection:** CA policy with `conditions.insiderRiskLevels` populated.
**Coverage:** **Gap.** Crosses with Purview spike #335.

## Coverage matrix summary

| Pattern category | Total | Covered | Gaps | Refresh |
|---|---:|---:|---:|---:|
| Foundational | 8 | 8 | 1 (`CA-ROLECOMPLETE-001`) | 2 (`CA-MFA-ALL-001`, `CA-PHISHRES-001`) |
| Surface-area | 9 | 5 | 4 (`CA-MOBILE-MAM-001`, `CA-CAE-001`, `CA-TOKEN-PROTECTION-001`, `CA-AUTHCONTEXT-001`, `CA-APPSPECIFIC-001`, `CA-WORKLOAD-001`) | 0 |
| External / guest | 3 | 0 | 3 (`CA-GUEST-MFA-001`, `CA-TENANT-RESTRICTIONS-001`, `CA-B2B-DIRECT-001`) | 0 |
| Anti-patterns | 10 | 6 | 4 (`CA-DISABLED-STALE-001`, `CA-BREAKGLASS-HARDENED-001`, `CA-MSMANAGED-001`, `CA-LEGACY-MFA-GRANT-001`, `CA-EFFECTIVE-POLICY-001`) | 0 |
| Modern (2024-2026) | 6 | 0 (mostly cross-domain) | 2 (`CA-MSMANAGED-MFA-MANDATE-001`) | 0 |
| Consolidation | — | — | 1 (`ENTRA-CA-001` ↔ `CA-LEGACYAUTH-001` deduplication) | 0 |
| **Total** | **42** | **19** | **17 to file** | **6 to refresh** |

(Three "Modern" patterns cross into other domain spikes — `Passkey`, `PIM auth context`, `Insider risk` — and will be addressed when those spikes resolve.)

## AiTM defense matrix

Which CA controls actually defeat which Adversary-in-the-Middle phishing tradecraft.

| AiTM stage | Tradecraft | CA control that breaks it |
|---|---|---|
| Initial credential capture | Reverse-proxy phishing kit (EvilProxy, Tycoon 2FA, Storm-1167) intercepts password + MFA challenge | Phishing-resistant MFA (1.3) — kit can't relay FIDO2 / WHfB / CBA challenge |
| MFA bypass | Kit captures the user's MFA approval and forwards | Phishing-resistant MFA (1.3); Authentication strength policy with allowed-combinations restricted (5.1) |
| Token theft | Kit captures the post-authentication session cookie | Token Protection (2.5) — token bound to original device, can't be replayed |
| Session reuse | Token replayed from attacker infrastructure | Continuous Access Evaluation (2.4) revokes on risk signal; sign-in frequency (2.2) bounds replay window |
| Privileged escalation post-compromise | Attacker activates PIM role with stolen session | Authentication context for PIM activation (5.5) forces step-up at activation time |

A tenant lacking any of {phishing-resistant MFA, Token Protection, CAE} is incompletely defended against modern AiTM. The CA panel breakdown that surfaces this layered status is one of the most valuable cross-pattern insights for downstream consumers.

## Detection method appendix

### Primary endpoint

```
GET /identity/conditionalAccess/policies
```

Returns the full inventory of CA policies. Each policy:
- `id`, `displayName`, `state` (`enabled` | `disabled` | `enabledForReportingButNotEnforced`)
- `templateId` (set if Microsoft-managed)
- `conditions` block: `users`, `applications`, `clientApplications`, `clientAppTypes`, `platforms`, `locations`, `signInRiskLevels`, `userRiskLevels`, `insiderRiskLevels`, `authenticationContexts`, `authenticationFlows`, `times`, `deviceStates`, `devices`
- `grantControls`: `operator`, `builtInControls[]`, `customAuthenticationFactors[]`, `termsOfUse[]`, `authenticationStrength`
- `sessionControls`: `applicationEnforcedRestrictions`, `cloudAppSecurity`, `signInFrequency`, `persistentBrowser`, `disableResilienceDefaults`, `secureSignInSession` (Token Protection), `continuousAccessEvaluation`

### Companion endpoints

| Endpoint | Used for |
|---|---|
| `/policies/authenticationStrengthPolicies` | Resolve `grantControls.authenticationStrength.id` to allowedCombinations |
| `/policies/authenticationMethodsPolicy` | Determine whether referenced methods are enabled tenant-wide |
| `/policies/crossTenantAccessPolicy/default` + `/partners` | External access reconciliation (3.1, 3.2, 3.3) |
| `/identity/conditionalAccess/namedLocations` | Resolve location references; detect stale (4.3) |
| `/identity/conditionalAccess/templates` | Compare custom policies against MS-managed templates |
| `/identity/conditionalAccess/authenticationContextClassReferences` | Auth context inventory (2.6, 5.5) |
| `/policies/identitySecurityDefaultsEnforcementPolicy` | Security Defaults state (interacts with all CA) |
| `/directoryRoles` + `/roleManagement/directory/roleAssignments` | Resolve admin role membership for 1.2, 4.1, 4.7 |
| `/identityProtection/riskyUsers` (P2) | User risk policy validation (1.6) |

### Edge cases

1. **State enumeration:** modern Graph returns `enabled` / `disabled` / `enabledForReportingButNotEnforced`. Older callers may see legacy values; normalize.
2. **`grantControls.operator`:** can be `OR` or `AND`. An `AND` operator with `["mfa", "compliantDevice"]` means both required — different intent than `OR`.
3. **`includeUsers: ["All"]` semantics:** distinct from `includeUsers: ["GuestsOrExternalUsers"]`; "All" means literally all (including guests).
4. **Microsoft-managed policy quirks:** `templateId` set means changes to the policy are restricted; some properties become read-only.
5. **Authentication strength resolution:** `grantControls.authenticationStrength.id` is a strength ID; you must resolve to `/policies/authenticationStrengthPolicies/{id}` to know what methods are allowed. A custom strength named "phishing-resistant" might allow SMS — name is not authoritative.
6. **Session control nullability:** absent properties default to "not applied" — a missing `signInFrequency` is not the same as `signInFrequency.value=0`. Handle nulls explicitly.
7. **CAE state shape:** older `disableResilienceDefaults: null` means default-enabled; explicit `false` means resilience defaults active. Reading null as "off" is a common bug.
8. **Token Protection rollout:** `secureSignInSession.isEnabled=true` is the GA setting. During phased rollout the tenant may have it in monitor-only via a workload-specific policy.

## Spawned issues to file

Per the umbrella's methodology, this audit's output spawns:

**Gap CheckIDs (`feat:` issues, 17 total):**

1. `feat: CA-ROLECOMPLETE-001` — admin role list completeness (1.2)
2. `feat: CA-MOBILE-MAM-001` — mobile App Protection Policy enforcement (2.1)
3. `feat: CA-CAE-001` — Continuous Access Evaluation strict enforcement (2.4)
4. `feat: CA-TOKEN-PROTECTION-001` — Token Protection sign-in session binding (2.5)
5. `feat: CA-AUTHCONTEXT-001` — authentication context coverage (2.6)
6. `feat: CA-APPSPECIFIC-001` — high-risk app stricter policies (2.7)
7. `feat: CA-WORKLOAD-001` — workload identity CA (2.9)
8. `feat: CA-GUEST-MFA-001` — guest MFA enforcement (3.1)
9. `feat: CA-TENANT-RESTRICTIONS-001` — Tenant Restrictions v2 (3.2)
10. `feat: CA-B2B-DIRECT-001` — B2B Direct Connect partner gating (3.3) — *coordinate with #333*
11. `feat: CA-DISABLED-STALE-001` — long-disabled policies (4.5)
12. `feat: CA-BREAKGLASS-HARDENED-001` — break-glass MFA + monitoring (4.7)
13. `feat: CA-MSMANAGED-001` — Microsoft-managed policy disabled/duplicated (4.8)
14. `feat: CA-LEGACY-MFA-GRANT-001` — legacy `requireMfa` after auth-strength deprecation (4.9)
15. `feat: CA-EFFECTIVE-POLICY-001` — overlapping rules conflicting grant controls (4.10) — *implementation complexity, may defer*
16. `feat: CA-MSMANAGED-MFA-MANDATE-001` — MS admin MFA mandate state (5.2)
17. `chore: deprecate ENTRA-CA-001 in favor of CA-LEGACYAUTH-001` — duplicate consolidation

**Narrative refresh (`chore:` issues, 6 total):**

- `chore: refresh CA-MFA-ALL-001 narrative` — add Microsoft-managed policy interaction + per-user MFA legacy reconciliation
- `chore: refresh CA-PHISHRES-001 narrative` — explicitly cite AiTM kits, document custom-strength misconfiguration
- `chore: refresh CA-LEGACYAUTH-001 narrative` — note basic auth EOL and SharePoint legacy-protocol scope
- `chore: refresh CA-SESSION-001 narrative` — pair with sign-in frequency rationale
- `chore: refresh CA-SIGNIN-FREQ-001 narrative` — clarify per-policy override interaction
- `chore: refresh ENTRA-CA-002 / -003 narratives` — these are meta-checks; clarify they're heuristic indicators, not pattern checks

## Out of scope (handled by sibling spikes)

- Authentication methods policy state — spike #330
- Token / session security beyond CA controls — spike #331
- External collaboration identity-plane reconciliation — spike #333
- PIM auth context activation — spike #328
- Insider risk integration — spike #335
- Sign-in log analytics for policy-effectiveness validation — runtime telemetry, future track
