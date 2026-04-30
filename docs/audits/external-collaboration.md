# External / Guest Collaboration — Domain Audit (v3.4.0)

**Status:** Sixth domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#333](https://github.com/Galvnyz/CheckID/issues/333).
**Source priorities:** Microsoft Learn primary (Cross-tenant access overview, Configure cross-tenant access settings, B2B collaboration overview, Restrict guest access in Microsoft Entra ID, Tenant restrictions v2, Identity Governance access reviews for guests), MSRC (guest access compromise patterns), CIS M365 v6 §5.1.6.x, CISA SCuBA `MS.AAD.8.x`, NIST 800-53 AC-3/4/6/7.

## Summary

CheckID has **8 identity-plane external-collaboration checks** in the Entra namespace plus 3 in the Azure namespace that govern Entra (boundary issue), and **20+ workload-side checks** (SharePoint, Teams, Exchange, Forms, Power BI). This audit focuses on the **identity plane** — cross-tenant access settings, B2B collaboration, guest user controls, federation — and cross-references the workload-side checks for downstream audits (#337 SPO, #340 Teams, #339 mail flow, #336 Power Platform).

Catalogs **27 canonical patterns** across 4 sub-domains (cross-tenant access defaults, per-partner overrides, guest user controls, federation). **11 coverage gaps** to file as `feat:` issues, **3 narrative-refresh candidates**, and one **structural duplication issue** in the registry (`PBI-*` and `POWERBI-*` namespaces appear to cover the same Power BI guest/sharing controls — needs consolidation).

This audit also names a recurring **boundary issue**: 3 checks in the AZ namespace (`AZ-IDENTITY-015`, `AZ-IDENTITY-016`, `AZ-IDENTITY-041`) govern Entra ID configuration. The same pattern surfaced in #331 (Token Protection in `AZ-IDENTITY-039`). Suggest a tracking issue to systematically reconcile these.

## Existing CheckID inventory (identity plane, M365-scope)

### Entra namespace (8 checks)

| CheckId | Severity | Pattern category | Notes |
|---|---|---|---|
| `ENTRA-GUEST-001` | Low | Guest restriction level | "Most restrictive" |
| `ENTRA-GUEST-002` | Low | Guest invite restriction | Limited to Guest Inviter role |
| `ENTRA-GUEST-003` | Medium | Guest inventory | Tenant-wide count metric |
| `ENTRA-GUEST-004` | Medium | Domain allow/deny list | Collaboration invitations to allowed domains only |
| `ENTRA-GROUP-002` | Low | Dynamic guest group | For policy targeting |
| `ENTRA-PIM-002` | Medium | Guest access reviews | Identity Governance |

(Plus 2 cross-domain via `ENTRA-AUTHMETHOD-002` for guest email OTP and `CA-EXCLUSION-001` for guest CA targeting — covered in #330 and #327.)

### AZ namespace governing Entra (3 boundary checks)

| CheckId | Severity | Boundary observation |
|---|---|---|
| `AZ-IDENTITY-015` | High | Guest user access restrictions — Entra-side control in AZ namespace |
| `AZ-IDENTITY-016` | High | Guest invite restrictions — Entra-side control in AZ namespace |
| `AZ-IDENTITY-041` | High | Guest user reviews — Entra-side control in AZ namespace |

These are **essentially duplicates of `ENTRA-GUEST-001/002/-003`** in the AZ namespace. Filed as a consolidation chore (see "Spawned issues" below).

### Workload-side cross-references (20+ checks, deferred to per-workload spikes)

| Namespace | Checks | Deferred to |
|---|---|---|
| `SPO-*` (sharing) | 8 | #337 (SharePoint + OneDrive sharing audit) |
| `TEAMS-EXT*`, `TEAMS-GUEST-001`, `TEAMS-MEETING-*` | 6 | #340 (Teams external access + meeting policies) |
| `EXO-*` (external sharing, transport) | 3 | #339 (mail flow audit) — `EXO-TRANSPORT-002` already noted there |
| `FORMS-CONFIG-001/002/003` | 3 | No dedicated Forms spike — belongs in this domain or a future spike |
| `PBI-*` + `POWERBI-*` | 9 | #336 (Power Platform). **Duplication issue noted.** |
| `INTUNE-PORTSTORAGE-001` | 1 | #334 (Intune) |

## 1. Cross-tenant access defaults

### 1.1 Default outbound block + per-partner allow

**Intent:** Tenant default for outbound access is to block; explicit allow per partner tenant. Modern recommended posture per Microsoft Zero Trust + Tenant Restrictions v2 guidance.
**Detection:** `GET /policies/crossTenantAccessPolicy/default`:
- `b2bCollaborationOutbound.usersAndGroups.accessType` = `blocked`
- `b2bCollaborationOutbound.applications.accessType` = `blocked`
- Per-partner overrides in `/policies/crossTenantAccessPolicy/partners` open specific partner tenants

**Pitfalls:** Default-allow + per-partner-block (the inverse) appears similar but creates a "shadow B2B" risk where any new tenant gets default access. Default-allow is the legacy configuration; default-block is the modern recommendation.
**Authoritative sources:** Microsoft Learn — Cross-tenant access default configuration; Configure cross-tenant access settings.
**Threats defeated:** Shadow B2B usage; uncontrolled outbound data flow to partner tenants; T1199 (Trusted Relationship).
**Coverage:** **Gap.** File `feat: ENTRA-XTAS-OUTBOUND-DEFAULT-001`.

### 1.2 Default inbound MFA trust posture

**Intent:** Tenant default for inbound MFA trust is *don't trust home tenant MFA* unless the partner tenant is verified to enforce MFA. Trusting home-tenant MFA blindly = inheriting partner's posture.
**Detection:** `crossTenantAccessPolicy/default.inboundTrust.isMfaAccepted` = `false` by default; per-partner overrides set to `true` only after verifying the partner enforces MFA.
**Pitfalls:** Default `true` (trust home MFA) is convenient but dangerous if any partner tenant has weak MFA enforcement. Modern recommendation: default `false`, opt-in per verified partner.
**Authoritative sources:** Microsoft Learn — Configure inbound trust settings.
**Threats defeated:** Compromised partner-tenant credentials gaining access to your tenant without MFA; T1078.004; T1199.
**Coverage:** **Gap.** File `feat: ENTRA-XTAS-INBOUND-MFA-TRUST-001`.

### 1.3 Default inbound device compliance trust posture

**Intent:** Default for trusting home-tenant device-compliance claims is `false`; opt-in per partner only after verification.
**Detection:** `inboundTrust.isCompliantDeviceAccepted` = `false`, `isHybridAzureADJoinedDeviceAccepted` = `false` at default; verified partners get `true`.
**Pitfalls:** Same as 1.2 — trusting partner compliance signal without verifying partner's Intune posture inherits their risk.
**Coverage:** **Gap.** File `feat: ENTRA-XTAS-INBOUND-DEVICE-TRUST-001`.

### 1.4 Default outbound restrictions (own users connecting to partner tenants)

**Intent:** Own users authenticating to external tenants are restricted by default; specific partners explicitly allowed.
**Detection:** `b2bCollaborationOutbound.usersAndGroups.accessType` = `blocked`; per-partner allow.
**Coverage:** Folds into 1.1.

## 2. Per-partner overrides

### 2.1 Trusted partners enumerated with explicit settings

**Intent:** Every actively-collaborated-with partner tenant has an entry in `/policies/crossTenantAccessPolicy/partners` with explicit trust settings, not relying on tenant default.
**Detection:** Enumerate partners; verify each has `inheritFromTenantSettings: false` (custom settings explicit).
**Pitfalls:** Some partners legitimately use default settings; the gate is "documented partner list matches the configured partner list."
**Coverage:** **Gap.** File `feat: ENTRA-XTAS-PARTNER-INVENTORY-001`.

### 2.2 Untrusted-but-known partners explicitly blocked

**Intent:** Partners that have appeared in collaboration but shouldn't have access (e.g., one-time vendors that have completed engagement) are explicitly blocked, not silently default-allowed.
**Detection:** Partner entries with `b2bCollaborationInbound.usersAndGroups.accessType` = `blocked` or `b2bCollaborationOutbound.applications.accessType` = `blocked`.
**Coverage:** **Gap.** Folds into 2.1 — same enumeration check.

### 2.3 Tenant restrictions v2 enabled for outbound

**Intent:** Managed devices with the Tenant Restrictions v2 client agent (or Edge built-in) cannot authenticate to non-allow-listed tenants — defeats personal-account-on-corporate-device risk.
**Detection:** Tenant Restrictions v2 settings under `crossTenantAccessPolicy/default.tenantRestrictions`. Plus per-partner settings to allow specific external tenants.
**Pitfalls:** Tenant Restrictions v2 requires Microsoft Edge OR Tenant Restrictions client agent for enforcement; un-instrumented clients bypass it. Detection should call out the client-side enforcement dependency.
**Authoritative sources:** Microsoft Learn — Tenant restrictions v2 deployment.
**Threats defeated:** Data exfil via personal accounts authenticated from corporate devices; T1078 (Valid Accounts).
**Coverage:** **Gap.** File `feat: ENTRA-TENANT-RESTRICTIONS-V2-001`. *Cross-domain with #327 §3.2.*

### 2.4 Identity providers allowed for B2B

**Intent:** B2B inbound is explicit about which identity providers are accepted (Microsoft, Google, Facebook, SAML/WS-Fed federated, email OTP, fallback).
**Detection:** `/policies/b2bManagementPolicy.invitationsAllowedAndBlockedDomains` (domain allow/deny lists) plus identity-provider settings under `/identityProviders` (returns paged list).
**Pitfalls:** Email OTP for guests is acceptable per Microsoft; SAML federation requires cert + claims trust.
**Coverage:** ✅ partial via `ENTRA-GUEST-004` (allowed-domain list). **Gap on identity-provider whitelist** — file `feat: ENTRA-XTAS-IDP-WHITELIST-001`.

## 3. Guest user controls

### 3.1 Guest restriction level

**Intent:** Tenant guest restriction is set to "limited directory access" (most restrictive level), so guests cannot enumerate the directory or read more than the resources they're explicitly granted.
**Detection:** `/policies/authorizationPolicy.guestUserRoleId` = `2af84b1e-32c8-42b7-82bc-daa82404023b` (the most-restrictive role template ID).
**Authoritative sources:** Microsoft Learn — Restrict guest access permissions.
**Threats defeated:** Reconnaissance from compromised guest account; T1087 (Account Discovery), T1591 (Gather Victim Org Information).
**Coverage:** ✅ `ENTRA-GUEST-001`. **Narrative refresh recommended** — should explicitly cite the role template ID and the reconnaissance defeat.

### 3.2 Self-service guest invite restrictions

**Intent:** Only specific roles can invite guests (Guest Inviter, User Admin, Application Admin) — not all members. Self-service guest creation creates sponsor-less guests.
**Detection:** `/policies/authorizationPolicy.allowInvitesFrom`:
- Acceptable: `adminsAndGuestInviters`, `none`
- Anti-pattern: `everyone`, `adminsGuestInvitersAndAllMembers`

**Pitfalls:** "All members can invite" is the default in older tenants; needs explicit tightening.
**Coverage:** ✅ `ENTRA-GUEST-002`.

### 3.3 Guest expiry / sponsor required

**Intent:** Guests have a defined expiry / access review cadence; orphan guests don't accumulate. Identity Governance access reviews enforce.
**Detection:** Identity Governance access reviews configured on guest groups / on shared resources.
**Coverage:** ✅ `ENTRA-PIM-002` (general access reviews for guests). **Gap on per-resource review cadence:** File `feat: ENTRA-GUEST-EXPIRY-001` if needed (lower priority).

### 3.4 Guest user MFA enforced (cross-spike)

**Intent:** B2B guests authenticate with MFA on first sign-in; CA policy targeting `users.includeUsers=["GuestsOrExternalUsers"]`.
**Coverage:** **Cross-spike.** Single CheckID with #327 §3.1 `CA-GUEST-MFA-001`. This audit confirms the same control surface; #327 owns implementation.

### 3.5 Guest sign-in to disallowed apps blocked

**Intent:** Some apps shouldn't be accessible to guests (e.g., admin portals, internal-only resources). CA policies target `GuestsOrExternalUsers` with block-grant for specific apps.
**Detection:** CA policy with `users.includeUsers=["GuestsOrExternalUsers"]` AND specific high-risk app inclusion AND `grantControls.builtInControls=["block"]`.
**Coverage:** **Gap.** File `feat: ENTRA-GUEST-APP-BLOCK-001`.

### 3.6 Guest user inventory + stale detection

**Intent:** Stale guests (no recent sign-in, never accepted invitation) are reviewed and removed. Compliance + license waste.
**Detection:** `users?$filter=userType eq 'Guest'` + `signInActivity.lastSignInDateTime` and `externalUserState`.
**Coverage:** ✅ `ENTRA-GUEST-003` (count metric only). **Narrative refresh recommended** — should explicitly include stale-detection rationale, not just count.

## 4. Federation

### 4.1 Direct Federation partners enumerated and reviewed

**Intent:** Direct Federation entries (SAML/WS-Fed federated B2B partners) are inventoried and have current cert + claim mapping.
**Detection:** `/identity/identityProviders` enumeration; SAML/WS-Fed entries reviewed for stale certs.
**Pitfalls:** Stale Direct Federation entries with expired certs may cause silent auth failures or be exploitable if the issuer reuses identifiers.
**Coverage:** **Gap.** File `feat: ENTRA-FEDERATION-INVENTORY-001`.

### 4.2 Federated SAML/WS-Fed providers in use

**Intent:** Federation choices are intentional. Using SAML federation when modern OIDC is available adds complexity without value.
**Detection:** Same enumeration as 4.1; flag SAML/WS-Fed without documented justification.
**Coverage:** Folds into 4.1.

### 4.3 Own tenant federation choice (PassThru / PHS / federation)

**Intent:** Own tenant's authentication choice (Pass-through Authentication / Password Hash Sync / federation with on-prem AD FS) is documented and matches risk tolerance. Federation with on-prem ADFS adds an attack surface (ADFS server compromise = full tenant compromise — Solorigate / Storm-X tradecraft).
**Detection:** `/organization/{id}/onPremisesSyncEnabled`, `/domains/{id}.authenticationType`, federated domain enumeration.
**Pitfalls:** Tenants on legacy federation should evaluate migration to PHS or PTA + Seamless SSO.
**Authoritative sources:** Microsoft Learn — Choose the right authentication method, Authentication option deep dive; MSRC Solorigate after-action.
**Coverage:** **Gap (cross-domain).** File `feat: ENTRA-OWN-FEDERATION-001` (low priority — large-org configuration question).

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| Cross-tenant access defaults | 4 | 0 | 0 | 3 (1.4 folds into 1.1) |
| Per-partner overrides | 4 | 1 (2.4 partial) | 0 | 3 (2.1, 2.3, 2.4 IdP whitelist) |
| Guest user controls | 6 | 3 (3.1, 3.2, 3.3, 3.6) | 2 (3.1, 3.6) | 2 (3.5 app-block, 3.3 expiry low-pri) |
| Federation | 3 | 0 | 0 | 2 (4.1, 4.3 low-pri); 4.2 folds |
| **Total** | **17** | **4** | **2** | **10 to file** |

(Plus 1 cross-spike CheckID consolidation: `CA-GUEST-MFA-001` from #327; `ENTRA-TENANT-RESTRICTIONS-V2-001` cross with #327 §3.2.)

## Threat-pattern map

| Compromise pattern | Primary control |
|---|---|
| Shadow B2B / uncontrolled outbound data flow | Default outbound block + per-partner allow (1.1) |
| Compromised partner tenant cascading | Inbound MFA trust = false + verify per-partner (1.2) |
| Inheriting partner's weak device compliance | Inbound device-compliance trust = false (1.3) |
| Personal account on corporate device data exfil | Tenant Restrictions v2 enabled (2.3) |
| Guest reconnaissance of directory | Guest restriction level "most restrictive" (3.1) |
| Sponsor-less guest accumulation | Guest invite restricted to admin roles (3.2) |
| Stale guest accounts | Access reviews + stale-sign-in detection (3.3, 3.6) |
| Compromised guest accessing admin app | CA policy blocks guests from admin apps (3.5) |
| ADFS server compromise → full tenant access | Avoid federation with on-prem AD FS (4.3) |
| Stale Direct Federation entries with expired cert | Federation partner inventory + cert review (4.1) |

## Detection method appendix

### Primary endpoints

```
GET /policies/crossTenantAccessPolicy                                → root
GET /policies/crossTenantAccessPolicy/default                         → default partner settings
GET /policies/crossTenantAccessPolicy/partners                         → per-partner overrides (paged)
GET /policies/authorizationPolicy                                     → guestUserRoleId, allowInvitesFrom, defaultUserRolePermissions
GET /policies/b2bManagementPolicy                                     → domain allow/deny lists
GET /domains                                                           → federated domains
GET /identity/identityProviders                                        → SAML/WS-Fed/Google/Facebook providers
GET /users?$filter=userType eq 'Guest'                                → guest inventory
GET /users/{id}/signInActivity                                         → last sign-in for stale detection
```

### Cross-tenant + B2B nuance

| Property | Effective when |
|---|---|
| `inheritFromTenantSettings: true` | Partner uses tenant default (no custom override) |
| `inheritFromTenantSettings: false` | Partner has explicit custom settings; default is ignored for this partner |
| `inboundTrust.isMfaAccepted: null` | Microsoft default (currently `false` for new tenants) |
| `inboundTrust.isMfaAccepted: false` | Don't trust partner MFA — require own MFA in CA policy |
| `inboundTrust.isMfaAccepted: true` | Trust partner MFA — partner verification required |
| `b2bCollaborationOutbound.applications.accessType: "blocked"` | Outbound to this partner blocked (or default if 1.1 set this way) |

### Edge cases

1. **Default vs explicit overrides** — `inheritFromTenantSettings: true` means the partner uses tenant default. Reading null on individual properties may indicate "not set" OR "use default." Defensive parsing required.
2. **Trust-acceptance state has 3 values** — `null` (Microsoft current default), `false` (explicit don't-trust), `true` (explicit trust). Don't conflate `null` with `false`.
3. **Guest restriction role template IDs** — the most-restrictive role template ID is hardcoded by Microsoft (`2af84b1e-...`). Detection should verify this exact ID, not a friendly name.
4. **Identity Provider enumeration is paged** — large tenants with many SAML federation entries need pagination handling.
5. **Tenant Restrictions v2 client-side dependency** — the policy is configured tenant-side, but enforcement requires Edge or Tenant Restrictions client. Detection should note this as a documentation requirement, not just config presence.
6. **Federation partner cert lifecycles** — Direct Federation entries don't auto-expire; stale entries linger. Detection should compare cert expiry against current date.
7. **Soft-deleted vs accountEnabled=false** — "stale guest" detection has multiple states: soft-deleted (in deleted-items), accountEnabled=false, never accepted invitation, no recent sign-in. Each is a different cleanup path.
8. **`AZ-IDENTITY-015/016/041` namespace boundary** — these are Entra ID controls catalogued in the AZ namespace. Either consolidate with `ENTRA-GUEST-*` or document the separation rationale.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 10):**

1. `feat: ENTRA-XTAS-OUTBOUND-DEFAULT-001` — default outbound block + per-partner allow (1.1)
2. `feat: ENTRA-XTAS-INBOUND-MFA-TRUST-001` — default inbound MFA trust = false (1.2)
3. `feat: ENTRA-XTAS-INBOUND-DEVICE-TRUST-001` — default inbound device-compliance trust = false (1.3)
4. `feat: ENTRA-XTAS-PARTNER-INVENTORY-001` — partner enumeration with explicit settings (2.1, 2.2)
5. `feat: ENTRA-TENANT-RESTRICTIONS-V2-001` — Tenant Restrictions v2 (2.3) — *single CheckID with #327 §3.2*
6. `feat: ENTRA-XTAS-IDP-WHITELIST-001` — identity providers allowed for B2B (2.4)
7. `feat: ENTRA-GUEST-APP-BLOCK-001` — CA policy blocking guests from admin apps (3.5)
8. `feat: ENTRA-FEDERATION-INVENTORY-001` — Direct Federation partner inventory + cert review (4.1)
9. `feat: ENTRA-OWN-FEDERATION-001` — own tenant federation choice review (4.3) — *low priority*
10. `feat: ENTRA-GUEST-EXPIRY-001` — per-resource access review cadence (3.3) — *low priority*

**Cross-spike (single CheckID, document overlap):**

- `CA-GUEST-MFA-001` from #327 §3.1 covers 3.4 (guest MFA enforcement)
- `ENTRA-TENANT-RESTRICTIONS-V2-001` covers #327 §3.2 — same control surface

**Boundary issue (`chore:` issue):**

- `chore: reconcile AZ-IDENTITY-015/016/041 with ENTRA-GUEST-001/002/003` — these are duplicate Entra controls in the AZ namespace. Decide: consolidate into ENTRA-* (deprecate AZ-*) OR document the separation as intentional.

**Power BI duplication (`chore:` issue):**

- `chore: reconcile PBI-* and POWERBI-* namespaces` — `PBI-CONTENT-001` / `POWERBI-GUEST-003`, `PBI-GUEST-001` / `POWERBI-GUEST-001`, `PBI-INVITE-001` / `POWERBI-GUEST-002`, `PBI-SHARING-001` / `POWERBI-SHARING-004` appear to be near-duplicates. Consolidate to one namespace.

**Narrative refresh (`chore:` issues, 3):**

- `chore: refresh ENTRA-GUEST-001 narrative` — explicit role template ID + reconnaissance defeat
- `chore: refresh ENTRA-GUEST-003 narrative` — distinguish count metric from stale-detection rationale
- `chore: refresh ENTRA-GUEST-004 narrative` — pair with B2B identity provider whitelist (2.4)

## Out of scope (handled by sibling spikes / future)

- SharePoint sharing levels (tenant + site) — #337
- Teams external access + B2B Direct Connect for shared channels — #340
- Mail flow connectors and external forwarding — #339
- Power Platform / Power BI guest access — #336 (with the duplication chore above)
- Forms external response/collaboration — could fold into a future spike or stay under this domain
- Sign-in log analytics for guest sign-in patterns — runtime telemetry
- AD FS server hardening — out of M365 scope
