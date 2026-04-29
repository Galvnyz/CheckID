# Privileged Access — Domain Audit (v3.4.0)

**Status:** Second domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#328](https://github.com/Galvnyz/CheckID/issues/328).
**Source priorities:** Microsoft Learn primary (Privileged Identity Management, Securing Privileged Access reference, Enterprise Access Model), MSRC + Microsoft Threat Intelligence for compromise patterns, CIS M365 v6 §1.1 + §5.3, CISA SCuBA `MS.AAD.7.x`, NIST 800-53 AC-2/5/6.

## Summary

CheckID has **15 privileged-access checks** today: 4 in `ENTRA-ADMIN-*`, 10 in `ENTRA-PIM-*`, 1 in `ENTRA-PRIVREMOTE-*`. This audit catalogs **34 canonical privileged-access patterns** across five sub-domains (activation hygiene, assignment hygiene, tier separation, emergency access, anti-patterns) and maps them against the registry. **15 coverage gaps** to file, **3 narrative-refresh candidates**, and one structural gap: CheckID has no canonical Tier 0 role inventory (M365-Assess maintains its own — both consumers should pull from a CheckID source-of-truth `data/role-tiers.json`).

The most acute gaps cluster around (1) **assignment hygiene** — drift detection between PIM-managed and persistent active assignments, (2) **emergency-access modernization** — the post-2024 Microsoft guidance shift from "exclude break-glass from all MFA" to "require MFA + monitor closely," and (3) **role-assignable group lifecycle** — the PIM-for-groups pattern is increasingly common but barely covered.

## Existing CheckID inventory (15 checks)

| CheckId | Severity | Pattern category | Notes |
|---|---|---|---|
| `ENTRA-ADMIN-001` | Medium | Tier separation (admin count) | 2–4 Global Admins; CIS §1.1.3 |
| `ENTRA-ADMIN-002` | Low | Tier separation (admin center access) | |
| `ENTRA-ADMIN-003` | Critical | Emergency access (presence) | ≥2 break-glass accounts; CIS §1.1.2 |
| `ENTRA-ADMIN-004` | Critical | Activation hygiene (admin phishing-resistant) | Crosses with CA spike #327's `CA-PHISHRES-001` |
| `ENTRA-PIM-001` | High | Assignment hygiene (PIM use) | "PIM is being used at all" |
| `ENTRA-PIM-002` | Medium | Assignment hygiene (guest access reviews) | |
| `ENTRA-PIM-003` | High | Assignment hygiene (privileged role reviews) | |
| `ENTRA-PIM-004` | High | Activation hygiene (GA approval) | |
| `ENTRA-PIM-005` | High | Activation hygiene (Privileged Role Admin approval) | |
| `ENTRA-PIM-006` | Medium | Activation hygiene (Tier 0 duration cap) | ≤4 hours |
| `ENTRA-PIM-007` | Medium | Activation hygiene (justification required) | |
| `ENTRA-PIM-008` | High | Activation hygiene (MFA on activation) | |
| `ENTRA-PIM-009` | High | Anti-pattern (permanent eligible) | |
| `ENTRA-PIM-010` | Medium | Activation hygiene (admin notification) | |
| `ENTRA-PRIVREMOTE-001` | High | Privileged remote command flow | |

## 1. Activation hygiene patterns

### 1.1 Time-bound activation required (no permanent active for sensitive roles)

**Intent:** Tier-0 roles (Global Admin, Privileged Role Admin, Privileged Authentication Admin) cannot have permanent active assignments — every active grant has a finite lifetime.
**Detection:** `GET /policies/roleManagementPolicies` filtered to Tier-0 role scopes; check `Expiration_EndUser_Assignment` rule's `maximumDuration` is bounded; `GET /roleManagement/directory/roleAssignmentScheduleInstances` confirms no unbounded active assignments.
**Pitfalls:** Custom role-management policies per role can override defaults; some tenants set Tier-0-equivalent roles (e.g., Application Admin can self-elevate via Graph) that aren't on the canonical Tier-0 list.
**Authoritative sources:** Microsoft Learn — Configure PIM role settings; Securing privileged access (Tier model). NIST 800-53 AC-2(2).
**Threats defeated:** Standing-credential abuse; T1078.004 with persistent privilege.
**Coverage:** ✅ partial via `ENTRA-PIM-009` (permanent eligible — but doesn't cover permanent active). **Gap.** File `feat: ENTRA-PIM-PERMACTIVE-001`.

### 1.2 MFA on every PIM activation

**Intent:** Activating any Tier-0 role triggers an MFA challenge regardless of recent sign-in.
**Detection:** `roleManagementPolicies/<id>/effectiveRules` `Enablement_EndUser_Assignment` rule includes `MultiFactorAuthentication`. Admin tier should specifically require phishing-resistant MFA via authentication context (#327 §5.5).
**Pitfalls:** "Trust MFA from sign-in" rule (`Enablement_EndUser_Assignment.enabledRules` containing `Justification` only) reuses session MFA — for Tier-0 should require fresh.
**Authoritative sources:** Microsoft Learn — Configure activation settings.
**Coverage:** ✅ `ENTRA-PIM-008` for presence. **Narrative refresh recommended** — should explicitly call out "Trust MFA from sign-in" anti-pattern and the auth-context bridge to phishing-resistant MFA.

### 1.3 Justification required on Tier-0 activation

**Intent:** Activating Tier-0 roles requires free-text justification (audit trail + intent capture).
**Detection:** `Enablement_EndUser_Assignment.enabledRules` contains `Justification`.
**Coverage:** ✅ `ENTRA-PIM-007`.

### 1.4 Approval workflow for Tier 0

**Intent:** Activating GA / Privileged Role Admin / Privileged Authentication Admin requires approval from a different identity.
**Detection:** `Approval_EndUser_Assignment.setting.isApprovalRequired = true`, with primary approvers populated.
**Pitfalls:** Approver pool must be non-empty AND not include the self-activator; approvers shouldn't all be the same user (single point of bottleneck or compromise).
**Authoritative sources:** Microsoft Learn — Approve or deny requests for Microsoft Entra roles.
**Coverage:** ✅ `ENTRA-PIM-004` (GA), ✅ `ENTRA-PIM-005` (Privileged Role Admin). **Gap:** Privileged Authentication Admin not covered. File `feat: ENTRA-PIM-APPROVAL-PAA-001`.

### 1.5 Maximum activation duration capped per tier

**Intent:** Tier-0 activations limited to ≤4 hours; Tier-1 ≤8 hours; Tier-2 standard.
**Detection:** `Expiration_EndUser_Assignment.maximumDuration` per role.
**Pitfalls:** Different roles within same tier may have different maxima — assess per-role rather than tenant-wide.
**Coverage:** ✅ `ENTRA-PIM-006` for Tier 0. **Gap:** no Tier-1 / Tier-2 caps. Lower priority — file as `feat: ENTRA-PIM-DURATION-T1T2-001` if v3.4.0 audit budget allows.

### 1.6 Notification on activation

**Intent:** When a Tier-0 role activates, notification fires to a documented recipient set (role admins, security ops).
**Detection:** `Notification_Admin_Admin_Eligibility`, `Notification_Admin_Admin_Assignment`, `Notification_Admin_EndUser_Assignment` rules — verify `notificationRecipients` populated and `defaultRecipients=true` is acceptable depending on org.
**Coverage:** ✅ `ENTRA-PIM-010` (admin notification on activation). **Gap:** notification on assignment changes (eligibility added/removed) not covered. File `feat: ENTRA-PIM-NOTIFY-ASSIGNMENT-001`.

### 1.7 Authentication context for PIM activation

**Intent:** PIM activation triggers a CA evaluation against an authentication context, enforcing stricter step-up at activation moment (passes through phishing-resistant MFA, device compliance, location filter).
**Detection:** `roleManagementPolicies/<id>/effectiveRules.AuthenticationContext_EndUser_Assignment.isEnabled = true`, `claimValue` references a defined auth context, AND that auth context has a corresponding CA policy targeting it.
**Pitfalls:** Auth context defined but no matching CA policy = no actual step-up.
**Authoritative sources:** Microsoft Learn — Conditional Access authentication context for PIM.
**Coverage:** **Gap.** File `feat: ENTRA-PIM-AUTHCONTEXT-001`. *Pairs with #327 §5.5.*

## 2. Assignment hygiene patterns

### 2.1 Eligible-vs-active assignment ratio (Tier-0)

**Intent:** For Tier-0 roles, near-zero permanent active assignments — almost everything is eligible (PIM-mediated).
**Detection:** Per-role count of `roleAssignmentScheduleInstances` (active) vs `roleEligibilityScheduleInstances` (eligible); flag when active > 0 for a Tier-0 role outside of break-glass.
**Pitfalls:** Service principals holding Tier-0 active assignments are sometimes legitimate (e.g., automation accounts); needs allow-list mechanism.
**Authoritative sources:** Microsoft Learn — Best practices for Microsoft Entra roles.
**Coverage:** ✅ partial via `ENTRA-PIM-009` (permanent eligible existence). **Gap:** no active-assignment scrutiny. File `feat: ENTRA-PIM-ACTIVE-DRIFT-001`.

### 2.2 Stale eligible assignments

**Intent:** Eligible assignments not activated in N days indicate role over-provisioning.
**Detection:** Per-eligible-assignment, query last `roleAssignmentScheduleInstance` activation; flag eligibility > 90 days without activation.
**Pitfalls:** Audit log retention limits visibility; needs Microsoft Entra audit logs (P1+) or workspace export.
**Coverage:** ✅ partial via `ENTRA-PIM-003` (access reviews). **Gap:** dedicated stale-eligibility detection. File `feat: ENTRA-PIM-STALE-ELIGIBLE-001`.

### 2.3 Role-assignable groups (PIM for groups)

**Intent:** Modern PIM-for-groups pattern: instead of assigning a role directly, assign it to a role-assignable group whose membership is itself PIM-mediated.
**Detection:** `GET /groups?$filter=isAssignableToRole eq true`; verify each role-assignable group has membership policies (PIM-managed members or strict ownership).
**Pitfalls:** Role-assignable groups bypass standard group management — owners can become privilege-escalation paths if not tier-aligned.
**Authoritative sources:** Microsoft Learn — Microsoft Entra role-assignable groups; PIM for groups.
**Coverage:** **Gap.** File `feat: ENTRA-PIM-GROUPS-001`.

### 2.4 PIM-managed vs unmanaged active assignments (drift)

**Intent:** When PIM is enabled tenant-wide but a Tier-0 role still has active assignments outside PIM's lifecycle (created via Graph or legacy directly), surface the drift.
**Detection:** Compare `roleManagement/directory/roleAssignments` (raw active) against `roleAssignmentScheduleInstances` (PIM-managed); the delta is unmanaged.
**Pitfalls:** Some directory roles aren't PIM-eligible; legitimate exceptions need annotation.
**Coverage:** **Gap.** File `feat: ENTRA-PIM-UNMANAGED-001`.

### 2.5 External user holding privileged roles

**Intent:** Guest / external users should not hold Tier-0 directory roles (compromised home tenant = compromised your tenant).
**Detection:** Resolve role assignees to `users` collection; flag any `userType=Guest` with Tier-0 role.
**Pitfalls:** Some legitimate cross-tenant admin scenarios (M&A, MSP) — needs documented exception list.
**Authoritative sources:** Microsoft Learn — Restrict guest access; Securing privileged access — external collaborators.
**Threats defeated:** T1199 (Trusted Relationship); compromised partner cascading into your tenant.
**Coverage:** **Gap.** File `feat: ENTRA-PIM-GUEST-PRIVILEGED-001`.

### 2.6 Service principal holding sensitive roles

**Intent:** Application service principals with Tier-0 directory role assignments should be inventoried and justified; especially `Privileged Role Administrator` and `Privileged Authentication Administrator` on a service principal are red flags.
**Detection:** Filter role assignments where principal is `servicePrincipal` and role is Tier-0; verify each is documented in a tenant ownership log.
**Pitfalls:** Microsoft first-party service principals legitimately hold some roles.
**Authoritative sources:** MSRC — service principal compromise patterns; Microsoft Threat Intelligence — Storm-X actor reports referencing SP role abuse.
**Threats defeated:** T1098.001 (Additional Cloud Credentials), T1078.004 via SP elevation.
**Coverage:** **Gap.** File `feat: ENTRA-PIM-SP-PRIVILEGED-001`.

## 3. Tier separation patterns

### 3.1 Cloud-only admin accounts

**Intent:** Tier-0 admin accounts are cloud-only — not synced from on-prem AD (which would create a hybrid attack path).
**Detection:** Resolve Tier-0 role assignees; verify `onPremisesSyncEnabled != true` and `onPremisesImmutableId == null`.
**Pitfalls:** Some hybrid orgs intentionally sync admin accounts; documented exceptions needed but should be rare.
**Authoritative sources:** Microsoft Learn — Securing privileged access (cloud-only admin tier). CISA — Privileged access management for hybrid environments.
**Coverage:** **Gap.** File `feat: ENTRA-PIM-CLOUDONLY-001`. (Currently `ENTRA-ADMIN-001` covers admin count but not cloud-only-ness.)

### 3.2 Admin accounts have no mailbox / minimal license

**Intent:** Admin accounts shouldn't have email mailboxes (phishing target reduction) or full Office 365 licenses (reduces blast radius).
**Detection:** Resolve Tier-0 assignees; check `assignedLicenses` is restricted to admin-only license SKUs (e.g., Microsoft Entra ID P2 standalone or admin-restricted bundles).
**Pitfalls:** Many tenants violate this for convenience; severity depends on org maturity.
**Coverage:** **Gap.** File `feat: ENTRA-PIM-ADMIN-LICENSE-001`. (Lower priority — file but mark `medium` severity.)

### 3.3 Naming convention enforced

**Intent:** Admin accounts use a consistent naming pattern (`adm-`, `priv-`, `_admin`, etc.) for visibility in audit and CA targeting.
**Detection:** Compare displayName / UPN of Tier-0 assignees against tenant-configured pattern (would need a curator-supplied regex per tenant).
**Pitfalls:** No global standard; per-tenant configuration is overhead. Possibly out of scope for CheckID — naming policy is org-specific.
**Coverage:** **Gap, but low priority.** May be deferred — could file as `feat: ENTRA-PIM-NAMING-001` with `wontfix` candidate annotation.

### 3.4 Tier 0 role inventory canonical list

**Intent:** Both CheckID-internal use and downstream consumers (M365-Assess, Az-Assess) need agreement on which Microsoft Entra roles count as Tier-0.
**Detection (current):** Each consumer maintains its own list. M365-Assess has `src/M365-Assess/controls/role-tiers.json`.
**Pitfalls:** When a new built-in role is added by Microsoft (recent additions: Cloud App Security Admin, Compliance Data Admin, etc.), every consumer's list drifts.
**Authoritative sources:** Microsoft Learn — Entra built-in roles list; Microsoft — privileged roles map.
**Coverage:** **Gap (structural).** File `data: introduce data/role-tiers.json` so all consumers reference one source. Reference set: Global Admin, Privileged Role Admin, Privileged Authentication Admin, Conditional Access Admin, Security Admin, Application Admin, Cloud Application Admin, Helpdesk Admin, Authentication Admin, Authentication Policy Admin, User Admin, SharePoint Admin, Exchange Admin, Compliance Admin, Compliance Data Admin, Hybrid Identity Admin, Intune Admin, Teams Administrator, Partner Tier2 Support, Domain Name Administrator, Identity Governance Administrator, External Identity Provider Administrator, Authentication Extensibility Administrator, B2C IEF Keyset Administrator, B2C IEF Policy Administrator. (To be confirmed against current Microsoft published list at PR time.)

## 4. Emergency access patterns

### 4.1 At least 2 break-glass accounts configured

**Intent:** ≥2 emergency access accounts to avoid lockout; ideally 3 for failover.
**Detection:** Tenant ownership log + role assignment query; identify accounts tagged or named for emergency access.
**Pitfalls:** Detection requires either naming convention agreement or explicit tagging via `extensionAttribute`/category.
**Coverage:** ✅ `ENTRA-ADMIN-003` (CIS §1.1.2). **Narrative refresh recommended** — current rationale doesn't mention the post-2024 Microsoft guidance shift.

### 4.2 Break-glass MFA registered (modern guidance)

**Intent:** *Updated 2024*: break-glass accounts should have MFA registered (FIDO2 or hardware token), not be excluded from all MFA. The legacy "exclude from MFA entirely" guidance is deprecated.
**Detection:** For each break-glass account: `GET /reports/authenticationMethods/userRegistrationDetails/<id>`; verify `methodsRegistered` includes a strong method.
**Pitfalls:** Legacy CA exclusions may still exclude break-glass from MFA — this is now an anti-pattern.
**Authoritative sources:** Microsoft Learn — Manage emergency access accounts (post-2024 update).
**Coverage:** **Gap.** File `feat: ENTRA-EMERG-MFA-REGISTERED-001`.

### 4.3 Break-glass excluded from lockout-prone CA only (not from all MFA)

**Intent:** Break-glass excluded from CA policies that could lock them out (CAE strict enforcement, location-based restrictions, device compliance) — NOT excluded from MFA-requiring CA.
**Detection:** Cross-reference break-glass account IDs against CA policies' `users.excludeUsers`; classify each excluded policy by intent.
**Pitfalls:** Same anti-pattern surfaced at #327 §4.7 — overlapping coverage.
**Coverage:** **Gap (cross-domain).** Coordinate with #327's `CA-BREAKGLASS-HARDENED-001`.

### 4.4 Break-glass sign-in alerting

**Intent:** Any sign-in from a break-glass account triggers an alert to security ops.
**Detection:** Tenant has alert policy / SIEM rule scoped to break-glass account UPNs (verification is partial — tenant-side via Sentinel/Defender XDR mostly).
**Pitfalls:** Alerting infrastructure is outside CheckID's M365-config scope; we can verify CA-side controls but not the SOC alert pipeline.
**Coverage:** **Gap, partially out of scope.** File as `feat: ENTRA-EMERG-ALERTING-001` with documented "best-effort detection" caveat.

### 4.5 Periodic test sign-in cadence

**Intent:** Break-glass accounts are test-signed-in quarterly to confirm they still work — fail-back insurance.
**Detection:** Audit log query for `signIn` events on break-glass UPNs; verify recent.
**Pitfalls:** Procedural; can be partially detected via sign-in log inspection (P1+).
**Coverage:** **Gap (procedural).** Possibly out of scope — file as `feat: ENTRA-EMERG-TEST-CADENCE-001` with low severity.

## 5. Anti-patterns (deliberate detection)

### 5.1 Permanent Global Admin assignments

**Intent:** No Global Admin role assigned permanently active — every GA grant should be PIM-eligible activated on demand.
**Detection:** Filter `roleAssignments` to GA role definition ID, check for active without expiration.
**Coverage:** ✅ partial via `ENTRA-PIM-001` (PIM in use); ✅ `ENTRA-PIM-009` (permanent eligible). **Gap:** specific to permanent ACTIVE GA. Consolidates under proposed `ENTRA-PIM-PERMACTIVE-001` (1.1).

### 5.2 Service account holding Global Admin

**Intent:** A service principal or shared service account should not hold GA — this is a common compromise vector.
**Detection:** Filter GA role assignees where principal is `servicePrincipal` OR user account name matches service-account heuristics (`svc-`, `sp-`, etc.).
**Coverage:** Folds into `ENTRA-PIM-SP-PRIVILEGED-001` (2.6) — service-principal-holds-Tier-0 covers this.

### 5.3 PIM role with no MFA on activation (Tier-0)

**Intent:** Already covered as 1.2; re-stated as anti-pattern for explicit detection.
**Coverage:** ✅ `ENTRA-PIM-008`.

### 5.4 Excessive activation duration for Tier 0 (>8h)

**Intent:** Even outside the 4-hour cap, durations >8h indicate "always on" intent — usage anti-pattern.
**Coverage:** ✅ partial via `ENTRA-PIM-006`. Refresh narrative to surface trending — currently a pass/fail at threshold.

### 5.5 Break-glass excluded from all MFA (legacy anti-pattern)

**Intent:** Modern guidance: break-glass should have MFA. The legacy "exclude from all MFA" pattern is now an anti-pattern.
**Detection:** Cross-reference break-glass account IDs against tenant MFA enforcement; flag any with no registered MFA methods.
**Coverage:** **Gap.** Folds into `ENTRA-EMERG-MFA-REGISTERED-001` (4.2) — same control surface, opposite framing.

### 5.6 Approval pool of one (or self-approval)

**Intent:** When approval is required, the approver pool must contain ≥2 distinct identities and exclude the requester.
**Detection:** Per-role approval policy: `Approval_EndUser_Assignment.setting.approvalStages[].primaryApprovers` count ≥2; verify no requester is also approver.
**Coverage:** **Gap.** File `feat: ENTRA-PIM-APPROVAL-POOL-001`.

### 5.7 Self-approve enabled

**Intent:** Some PIM configurations let an approver self-approve their own activation request — defeats the workflow.
**Detection:** `Approval_EndUser_Assignment.setting.approvalStages[].isApproverJustificationRequired` interaction; specific PIM "isSelfApprovalEnabled" policy property.
**Coverage:** Rolls into `ENTRA-PIM-APPROVAL-POOL-001`.

## Coverage matrix summary

| Pattern category | Total | Covered | Partial | Gaps |
|---|---:|---:|---:|---:|
| Activation hygiene | 7 | 5 | 1 (1.1, 1.2 refresh) | 3 (1.1 expand, 1.4 PAA, 1.6 assignment-notify, 1.7 auth-context) |
| Assignment hygiene | 6 | 1 | 2 (2.1, 2.2 partial) | 5 (2.1 active-drift, 2.2 stale, 2.3 groups, 2.4 unmanaged, 2.5 guest-priv, 2.6 SP-priv) |
| Tier separation | 4 | 1 | 0 | 3 (3.1 cloud-only, 3.2 license, 3.3 naming + structural 3.4) |
| Emergency access | 5 | 1 | 0 | 4 (4.2 MFA-registered, 4.3 cross-domain, 4.4 alerting, 4.5 test cadence) |
| Anti-patterns | 7 | 4 | 1 (5.4 trending) | 2 (5.6 approval pool — 5.7 folds in) |
| **Total** | **34** | **15** | **4** | **15 to file** |

Plus the structural gap: **`data/role-tiers.json` canonical Tier-0 list** to be introduced (eliminates per-consumer drift). Filed as `data:` issue, not `feat:`.

## Threat-pattern map

| Compromise pattern | What enables it | PIM control that breaks it |
|---|---|---|
| Standing-credential abuse (compromised admin password = ongoing tenant access) | Permanent active Tier-0 assignments | Time-bound activation (1.1); approval workflow (1.4); MFA on activation (1.2) |
| Privilege persistence after AiTM phishing | Tier-0 password compromise + no PIM | Tier-0 cloud-only (3.1); PIM with phishing-resistant on activation via auth context (1.7); active-drift detection (2.4) |
| External-tenant compromise cascading | Guest holding Tier-0 role | Guest-with-privileged detection (2.5); cross-tenant access policy (handled in #333) |
| Service principal abuse for elevation | SP holding Tier-0 role + no monitoring | SP-with-privileged detection (2.6); workload identity CA (handled in #327 §2.9) |
| Approval bypass | Single-approver pool, self-approve enabled | Approval pool ≥2 with requester excluded (5.6) |
| Break-glass key in attacker hands → tenant lockout escape | Break-glass not monitored | Sign-in alerting (4.4); test-cadence verification (4.5) |
| PIM-for-groups membership compromise | Role-assignable group with weak ownership | PIM for groups membership policy (2.3) |

## Detection method appendix

### Primary endpoints

```
GET /policies/roleManagementPolicies                          → activation rules per scope
GET /policies/roleManagementPolicyAssignments                 → maps roles to policy IDs
GET /roleManagement/directory/roleDefinitions                 → role catalog
GET /roleManagement/directory/roleAssignments                 → active assignments (raw)
GET /roleManagement/directory/roleEligibilityScheduleInstances → eligible (PIM-managed)
GET /roleManagement/directory/roleAssignmentScheduleInstances  → currently-activated (PIM-managed)
GET /identityGovernance/privilegedAccess/group/eligibilityScheduleInstances → PIM for groups
GET /reports/authenticationMethods/userRegistrationDetails    → admin MFA registration
GET /groups?$filter=isAssignableToRole eq true                → role-assignable groups inventory
GET /users/<id>?$select=onPremisesSyncEnabled,assignedLicenses,userType,onPremisesImmutableId → tier-separation signals
```

### Edge cases

1. **Role assignments via group membership.** Resolving a Tier-0 role's effective assignees requires recursively expanding role-assignable groups (`groups/<id>/transitiveMembers`). Don't stop at direct role assignments.
2. **PIM eligibility through nested groups.** `roleEligibilityScheduleInstances` may target a group; group may contain other groups. Effective eligible-user set is the transitive closure.
3. **Distinguishing service principals from users in role assignments.** The `principal.@odata.type` discriminates: `#microsoft.graph.user` vs `#microsoft.graph.servicePrincipal`. Both can hold roles; treatment differs (2.6 vs 2.5).
4. **Tier 0 mapping is data, not catalog.** No Microsoft-published authoritative "Tier 0 list" — Microsoft publishes "highly privileged roles" guidance which evolves. CheckID's `data/role-tiers.json` (proposed) becomes the source of truth.
5. **Microsoft-managed role policies.** Microsoft has begun rolling out default activation policies on tenants; these may have `templateId`-equivalent markers. Detection should distinguish "we set this" from "Microsoft set this."
6. **Audit log retention for stale-eligibility detection.** `signIn` and `directoryAudit` logs retain 30 days (P1) or 90+ days (P2). Stale-eligibility detection (2.2) needs a workspace export (Sentinel, Log Analytics) for older windows. Document this as detection limitation.
7. **PIM for groups vs PIM for roles.** Two distinct PIM surfaces with overlapping but separate APIs. PIM for groups uses `/identityGovernance/privilegedAccess/group/*`; PIM for roles uses `/roleManagement/directory/*`. Reconcile both.
8. **Activation policy property naming inconsistency.** `Enablement_EndUser_Assignment.enabledRules` is a list of strings (`"MultiFactorAuthentication"`, `"Justification"`, `"Ticketing"`). Names are case-sensitive; don't substring-match.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 15):**

1. `feat: ENTRA-PIM-PERMACTIVE-001` — permanent ACTIVE Tier-0 assignment (1.1, 5.1)
2. `feat: ENTRA-PIM-APPROVAL-PAA-001` — approval required for Privileged Authentication Admin (1.4)
3. `feat: ENTRA-PIM-DURATION-T1T2-001` — Tier-1/Tier-2 max duration cap (1.5) — *lower priority*
4. `feat: ENTRA-PIM-NOTIFY-ASSIGNMENT-001` — notification on eligibility change (1.6)
5. `feat: ENTRA-PIM-AUTHCONTEXT-001` — PIM activation requires auth context (1.7) — *crosses with #327 §5.5*
6. `feat: ENTRA-PIM-ACTIVE-DRIFT-001` — active-vs-eligible ratio for Tier-0 (2.1)
7. `feat: ENTRA-PIM-STALE-ELIGIBLE-001` — eligibility unactivated > 90 days (2.2)
8. `feat: ENTRA-PIM-GROUPS-001` — role-assignable group lifecycle (2.3)
9. `feat: ENTRA-PIM-UNMANAGED-001` — PIM-managed vs unmanaged active drift (2.4)
10. `feat: ENTRA-PIM-GUEST-PRIVILEGED-001` — guest user with Tier-0 role (2.5)
11. `feat: ENTRA-PIM-SP-PRIVILEGED-001` — service principal with Tier-0 role (2.6, 5.2)
12. `feat: ENTRA-PIM-CLOUDONLY-001` — Tier-0 admin not cloud-only (3.1)
13. `feat: ENTRA-PIM-ADMIN-LICENSE-001` — Tier-0 admin holds full O365 license (3.2) — *medium*
14. `feat: ENTRA-EMERG-MFA-REGISTERED-001` — break-glass MFA registered (4.2, 5.5)
15. `feat: ENTRA-EMERG-ALERTING-001` — break-glass sign-in alerting (4.4) — *partial out-of-scope*
16. `feat: ENTRA-EMERG-TEST-CADENCE-001` — break-glass periodic test sign-in (4.5) — *low priority*
17. `feat: ENTRA-PIM-APPROVAL-POOL-001` — approval pool ≥2 + no self-approve (5.6, 5.7)

(Patterns 3.3 naming convention and out-of-scope items deferred.)

**Cross-domain (coordinate with sibling spike):**

- `CA-BREAKGLASS-HARDENED-001` from #327 §4.7 — break-glass excluded from lockout-prone CA only, not from all MFA. This audit's 4.3 is the same control surface. Reuse single CheckID.

**Structural data (`data:` issue, 1):**

- `data: introduce data/role-tiers.json` — canonical Tier-0 / Tier-1 / Tier-2 role inventory referenced by all detection logic. Eliminates per-consumer drift between CheckID, M365-Assess, Az-Assess, EZ-CMMC. Cross-references Microsoft's "highly privileged roles" guidance.

**Narrative refresh (`chore:` issues, 3):**

- `chore: refresh ENTRA-PIM-008 narrative` — call out "Trust MFA from sign-in" anti-pattern + auth-context bridge to phishing-resistant MFA
- `chore: refresh ENTRA-ADMIN-003 narrative` — incorporate post-2024 Microsoft guidance shift (MFA on break-glass, not exclusion-from-all)
- `chore: refresh ENTRA-PIM-006 narrative` — clarify duration as trending indicator, not just pass/fail at threshold

## Out of scope (handled by sibling spikes)

- On-prem AD privileged access — CheckID is M365-scoped
- Privileged Access Workstation (PAW) detection — procedural
- Sign-in log analytics for activation patterns — runtime telemetry, future track
- Workload identity CA policy — #327 (CA spike) §2.9
- Authentication context CA policy enforcement — #327 §5.5
- Cross-tenant external collaboration — #333
- Authentication methods policy state — #330
- Token / session security — #331
