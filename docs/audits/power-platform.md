# Power Platform — Domain Audit (v3.4.0)

**Status:** Thirteenth domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#336](https://github.com/Galvnyz/CheckID/issues/336).
**Source priorities:** Microsoft Learn primary (Power Platform admin overview, Data loss prevention policies for Power Platform, Tenant isolation, Power Platform Center of Excellence Starter Kit, Connector classifications), Microsoft Power Platform security & governance whitepaper, CISA SCuBA `MS.POWERPLATFORM.*`.

## Summary

CheckID has **26 Power BI-related checks** but **zero coverage of the broader Power Platform** (Power Apps, Power Automate, Dataverse, Copilot Studio, Power Pages). The largest finding from this audit is the inverse of typical: there's *too much* duplicate Power BI coverage (the `PBI-*` ↔ `POWERBI-*` namespace duplication first surfaced in #333), and *zero* coverage of the Power Apps / Power Automate / DLP / tenant-isolation surfaces that #336 covers.

Catalogs **23 canonical patterns** across 6 sub-domains (tenant isolation, environment hygiene, DLP policy coverage, sharing controls, Copilot governance, anti-patterns). **17 coverage gaps** to file as `feat:` issues, **2 narrative-refresh candidates**, and a major **namespace consolidation chore** with **11 confirmed duplicate pairs** between `PBI-*` and `POWERBI-*`.

This is also the first audit where the **Power Platform admin APIs are not Microsoft Graph** — they're a separate REST surface accessed via the `Microsoft.PowerApps.Administration.PowerShell` module. Detection appendix documents the contract.

## Existing CheckID inventory

### Power BI — 11 confirmed duplicate pairs (the core consolidation chore)

| Control intent | `PBI-*` | `POWERBI-*` |
|---|---|---|
| Block ResourceKey Authentication | `PBI-AUTH-001` | `POWERBI-AUTH-001` |
| API access by service principals | `PBI-API-001` | `POWERBI-AUTH-002` |
| SP profile creation restricted | `PBI-PROFILE-001` | `POWERBI-AUTH-003` |
| Guest user access restricted | `PBI-GUEST-001` | `POWERBI-GUEST-001` |
| External user invitations | `PBI-INVITE-001` | `POWERBI-GUEST-002` |
| Guest access to content | `PBI-CONTENT-001` | `POWERBI-GUEST-003` |
| Sensitivity labels enabled | `PBI-LABELS-001` | `POWERBI-INFOPROT-001` |
| Publish to web restricted | `PBI-PUBLISH-001` | `POWERBI-SHARING-001` |
| R/Python visuals disabled | `PBI-SCRIPT-001` | `POWERBI-SHARING-002` |
| Shareable links restricted | `PBI-LINK-001` | `POWERBI-SHARING-003` |
| External data sharing | `PBI-SHARING-001` | `POWERBI-SHARING-004` |

Plus 4 outliers without clean pair-mapping:
- `PBI-TENANT-001` — meta "External Sharing Configuration" (overlaps several PBI-* and POWERBI-* above)
- `PBI-TENANT-002` — meta "Publish to Web Configuration" (overlaps `PBI-PUBLISH-001` / `POWERBI-SHARING-001`)
- `PBI-TENANT-003` — meta "Guest Access Configuration" (overlaps `PBI-GUEST-001` / `POWERBI-GUEST-001`)
- `POWERBI-SERVICEPRINCIPAL-001` — SP cannot create workspaces / connections / deployment pipelines (close to but distinct from the SP-API restrictions above)

### Power Apps / Power Automate / DLP — zero checks

The `POWERPLATFORM-*` namespace doesn't exist. Spike #336's primary scope (tenant isolation, environment hygiene, DLP policy coverage across Power Apps + Power Automate, Copilot governance) has zero coverage today.

## 1. Tenant isolation

### 1.1 Tenant isolation enabled

**Intent:** Tenant isolation blocks guest tenants from connecting to your environments. Without it, anonymous app makers from other tenants can attempt connections to your data.
**Detection:** `Get-TenantSettings` (Power Platform admin PS) — `tenantSettings.disableMakerMatch`, `disableEnvironmentCreationByNonAdminUsers`, `tenantIsolationConfig` properties.
**Pitfalls:** Tenant isolation is configured in the Power Platform admin center; the property names + endpoints have evolved over 2023-2024. Detection should reference current Microsoft documentation at runtime.
**Authoritative sources:** Microsoft Learn — Tenant isolation in Power Platform.
**Threats defeated:** Guest tenant data exfil via Power Platform connectors; cross-tenant unauthorized data flow.
**Coverage:** **Gap.** File `feat: POWERPLATFORM-TENANT-ISOLATION-001`.

### 1.2 Inbound + outbound exception lists per partner tenant

**Intent:** Once tenant isolation is enabled, specific partner tenants can be allow-listed for inbound and/or outbound connections.
**Detection:** Tenant isolation rules + per-direction allow lists.
**Pitfalls:** Same drift problem as cross-tenant access policy (#333) — partner allow list and documented partner relationships should match.
**Coverage:** **Gap.** File `feat: POWERPLATFORM-TENANT-ISOLATION-PARTNERS-001`.

### 1.3 Cross-tenant connection auditing

**Intent:** Cross-tenant Power Platform connections (when allow-listed) are audited and reviewed.
**Detection:** Cross-reference with Microsoft Sentinel / audit log connectors.
**Coverage:** **Gap (low priority).** File `feat: POWERPLATFORM-XTENANT-AUDIT-001`.

## 2. Environment hygiene

### 2.1 Default environment locked down

**Intent:** Default environment is auto-Maker for every licensed user — every user can create apps, flows, and connections in it. Lock it down (restrict makers to a specific group) OR redirect all production work to specific named environments.
**Detection:** `Get-AdminPowerAppEnvironment` for the Default environment + `Get-AdminPowerAppRoleAssignment` for who has Maker. Verify Maker isn't `EveryoneElseInTenant`.
**Pitfalls:** Default environment hardening is the #1 Power Platform governance recommendation per the CoE Starter Kit. Most tenants have wide-open default environments inherited from initial provisioning.
**Authoritative sources:** Microsoft Learn — Default environment management; CoE Starter Kit.
**Coverage:** **Gap.** File `feat: POWERPLATFORM-DEFAULT-ENV-LOCKDOWN-001`.

### 2.2 Custom production environments per team / business unit

**Intent:** Production app/flow workloads run in named, governed environments — not the default. Each environment has assigned admin + maker groups.
**Detection:** `Get-AdminPowerAppEnvironment | Where-Object { $_.EnvironmentType -eq 'Production' }` enumeration; verify per-environment governance.
**Coverage:** **Gap (low priority — depends on org maturity).** File `feat: POWERPLATFORM-PRODUCTION-ENVS-001`.

### 2.3 Sandbox / dev environments labeled and quota-limited

**Intent:** Non-production environments are labeled (Sandbox / Trial / Developer) and have storage quota limits to prevent runaway growth.
**Detection:** `Get-AdminPowerAppEnvironment` + per-environment Dataverse capacity.
**Coverage:** **Gap (low priority).** File `feat: POWERPLATFORM-NONPROD-ENVS-001`.

### 2.4 Environment lifecycle (deletion of stale environments)

**Intent:** Environments unused for >90 days reviewed and deleted. Stale environments accumulate licensing cost + governance scope.
**Detection:** `Get-AdminPowerAppEnvironment.lastActivity` (or equivalent) > 90 days.
**Coverage:** **Gap (low priority).** File `feat: POWERPLATFORM-ENV-LIFECYCLE-001`.

### 2.5 Dataverse capacity per environment monitored

**Intent:** Dataverse capacity tracked per environment to detect runaway data growth before quota exhaustion.
**Detection:** Dataverse storage usage API.
**Coverage:** **Out of scope (operational metric, not security config).**

## 3. DLP policy coverage

### 3.1 Tenant-wide DLP policy applied to all environments

**Intent:** A tenant-level DLP policy applies to all environments by default; individual environments can have stricter policies on top. Without a tenant-wide policy, new environments default to "no DLP" until explicit configuration.
**Detection:** `Get-DlpPolicy` filtered to scope = `AllEnvironments`. Verify ≥1 active policy.
**Authoritative sources:** Microsoft Learn — DLP policies for Power Platform.
**Coverage:** **Gap.** File `feat: POWERPLATFORM-DLP-TENANT-WIDE-001`.

### 3.2 Connector classification (Business / Non-Business / Blocked)

**Intent:** Each Power Platform connector classified as Business (enterprise data), Non-Business (personal data), or Blocked. Connectors in different classifications cannot be combined in the same app/flow — preventing accidental data flow between classifications.
**Detection:** Per-DLP-policy connector group definitions; classification lookup against the ~200+ standard connectors.
**Pitfalls:** Connector classification is the workhorse of Power Platform DLP. Default classifications are insufficient for most orgs — explicit per-connector decisions required.
**Coverage:** **Gap.** File `feat: POWERPLATFORM-DLP-CONNECTOR-CLASS-001`.

### 3.3 All connectors classified (no "default-uncategorized")

**Intent:** Every connector is in one of the three buckets; nothing is in the default-uncategorized bucket which behaves permissively.
**Detection:** Per-policy uncategorized-bucket inventory.
**Coverage:** **Gap.** File `feat: POWERPLATFORM-DLP-UNCATEGORIZED-001`.

### 3.4 Custom connectors evaluated and classified

**Intent:** Custom HTTP connectors (built by the org) are reviewed and classified appropriately. Often these are over-permissive by default.
**Detection:** Per-DLP-policy custom connector classification.
**Coverage:** **Gap (low priority).** File `feat: POWERPLATFORM-DLP-CUSTOM-CONNECTOR-001`.

### 3.5 HTTP connector restricted

**Intent:** The "HTTP" connector (generic webhook caller) is in the Blocked bucket OR Non-Business with strict scope. As a Business connector, it allows arbitrary outbound HTTP from any flow that includes it — i.e., generic data exfil.
**Detection:** Per-policy HTTP connector classification.
**Coverage:** **Gap.** File `feat: POWERPLATFORM-DLP-HTTP-CONNECTOR-001`.

### 3.6 Public Web Service Description / OpenAPI connector restricted

**Intent:** Same anti-pattern as HTTP — a connector that calls arbitrary OpenAPI endpoints is generic-egress unless restricted.
**Coverage:** Folds into 3.5.

## 4. Sharing controls

### 4.1 "Who can share" restricted at tenant level

**Intent:** Restrict who can share apps with whole organization (vs named groups). Default behavior allows broad sharing.
**Detection:** Tenant settings `allowDataSharingWithSecurityGroupsOnly` / equivalent.
**Coverage:** **Gap.** File `feat: POWERPLATFORM-SHARING-RESTRICTION-001`.

### 4.2 Apps shareable with whole organization disabled

**Intent:** End users can't share apps with `Everyone` — must select named groups. Reduces accidental over-share.
**Detection:** Tenant `disableShareWithEveryone` property OR analogous.
**Coverage:** Folds into 4.1.

### 4.3 Power BI workspace + dataset sharing controls

**Coverage:** ✅ via existing Power BI checks (`PBI-CONTENT-001` / `POWERBI-GUEST-003`, `PBI-LINK-001` / `POWERBI-SHARING-003`).

### 4.4 Public links to Power BI reports disabled

**Intent:** Anonymous-link Power BI reports = unauthenticated public report access. Should be disabled tenant-wide.
**Coverage:** ✅ via `PBI-PUBLISH-001` / `POWERBI-SHARING-001` (Publish to web).

## 5. Copilot governance

### 5.1 Copilot Studio bots gated by maker permissions

**Intent:** Copilot Studio (formerly Power Virtual Agents) bots can connect to org data via connectors. Maker permissions for Copilot Studio gated to specific user groups, not Everyone.
**Detection:** Per-environment Copilot Studio permissions; cross-reference with environment governance.
**Coverage:** **Gap.** File `feat: POWERPLATFORM-COPILOT-MAKERS-001`.

### 5.2 Sensitive data labels respected by Copilot grounding

**Intent:** Copilot for M365 grounding queries respect sensitivity labels — content marked `Confidential` doesn't leak into Copilot responses for users without that clearance.
**Detection:** Cross-domain to #335 (Purview) — sensitivity label policy enforcement on Copilot.
**Coverage:** **Gap (cross-spike).** Cross-spike with #335; single CheckID `feat: POWERPLATFORM-COPILOT-LABELS-001`.

### 5.3 Copilot for M365 deployment policies

**Intent:** Copilot for M365 (M365 Chat, Copilot in Word/Excel/Outlook) availability + scope governed by deployment policies.
**Detection:** `Get-CopilotPolicy` (or via Microsoft 365 admin center API).
**Coverage:** **Gap (low priority — emerging area).** File `feat: POWERPLATFORM-COPILOT-DEPLOY-001`.

## 6. Anti-patterns (deliberate detection)

### 6.1 Default environment unrestricted

**Coverage:** Folds into 2.1.

### 6.2 Single tenant-wide DLP policy with no environment-specific overrides for high-risk environments

**Intent:** Some environments need stricter DLP than the tenant default (e.g., PII-handling environment, regulated-industry environment). One-size-fits-all DLP is anti-pattern.
**Detection:** Compare per-environment DLP scope; flag environments without overrides + risk indicator.
**Coverage:** **Gap (low priority).** File `feat: POWERPLATFORM-DLP-PER-ENV-001`.

### 6.3 HTTP connector classified as Business

**Coverage:** Folds into 3.5.

### 6.4 Twitter / Facebook / external email connectors classified as Business

**Intent:** Social media + external email connectors should be Non-Business or Blocked. Classifying them as Business allows the same flow to combine corporate data + social data → exfil path.
**Coverage:** Folds into 3.2.

### 6.5 No tenant isolation → guests can build flows pulling data from your environment

**Coverage:** Folds into 1.1.

### 6.6 Anonymous public link Power BI reports

**Coverage:** ✅ via `PBI-PUBLISH-001`.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| Tenant isolation | 3 | 0 | 0 | 3 |
| Environment hygiene | 5 | 0 | 0 | 4; 2.5 out-of-scope |
| DLP policy coverage | 6 | 0 | 0 | 5 (3.1, 3.2, 3.3, 3.4 low-pri, 3.5); 3.6 folds |
| Sharing controls | 4 | 2 (Power BI side) | 0 | 1 (4.1); 4.2 folds |
| Copilot governance | 3 | 0 | 0 | 3 (1 cross-spike) |
| Anti-patterns | 6 | 1 | 0 | 1 unique (6.2 low-pri); rest fold |
| **Total** | **27 (23 unique after folds)** | **3 (Power BI side only)** | **0** | **17 net to file** |

(Plus 11 namespace duplication pairs to consolidate.)

## Threat-pattern map

| Compromise pattern | Tradecraft | Primary control |
|---|---|---|
| Citizen-developer data exfil via flow | Compromised user creates Power Automate flow that emails CSV to attacker mailbox | DLP HTTP / external-email connector restriction (3.5, 6.4) |
| Cross-tenant data flow via guest maker | Guest from partner tenant builds flow pulling from your env | Tenant isolation enabled (1.1) |
| Default-environment proliferation | Every licensed user becomes a Maker, accumulating apps/flows nobody manages | Default environment lockdown (2.1) |
| Personal-cloud connector to enterprise data | Flow combines OneDrive (Business) + Personal-OneDrive (Non-Business) | Connector classification + cross-classification block (3.2) |
| Custom HTTP connector → arbitrary egress | Maker creates custom connector to attacker-controlled URL | Custom connector evaluation (3.4) + HTTP connector class (3.5) |
| Public Power BI report leak | Sensitive report published anonymously | Publish to web disabled ✅ (PBI-PUBLISH-001) |
| Copilot grounding leak across sensitivity classes | Confidential content surfaces in Copilot response for unprivileged user | Sensitivity-label enforcement on Copilot grounding (5.2) |
| Copilot Studio bot exfil | Maker builds bot that connects to corp data + answers external questions | Copilot maker permissions + DLP on bot's connectors (5.1) |

## Detection method appendix

### Primary surface: Power Platform admin PowerShell

Power Platform admin APIs are **not** Microsoft Graph. They live in a separate REST surface accessed via PowerShell:

```powershell
Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Force
Add-PowerAppsAccount  # auth
```

| Cmdlet | Used for |
|---|---|
| `Get-AdminPowerAppEnvironment` | Environment inventory + properties |
| `Get-AdminPowerAppEnvironmentRoleAssignment` | Per-environment maker / admin role assignments |
| `Get-AdminPowerApp` | App inventory across environments |
| `Get-AdminFlow` | Flow inventory |
| `Get-DlpPolicy` | DLP policies + connector classifications |
| `Get-TenantSettings` | Tenant-level governance flags (sharing, isolation, etc.) |
| `Get-AdminPowerAppRoleAssignment` | Per-app sharing inventory |
| `Get-AdminFlowOwnerRole` | Per-flow ownership |

### Power BI side (different module)

```powershell
Install-Module MicrosoftPowerBIMgmt -Force
Connect-PowerBIServiceAccount
```

| Cmdlet | Used for |
|---|---|
| `Get-PowerBIWorkspace -Scope Organization` | Workspace inventory + sharing |
| `Get-PowerBIDashboard -Scope Organization` | Dashboard inventory |
| Power BI admin REST API: `/admin/groups`, `/admin/dlpPolicies` | Some governance endpoints (limited) |

### Edge cases

1. **Power Platform auth uses different consent flow than Graph.** Service principal access requires explicit Power Platform admin role + tenant-level consent in the Power Platform admin center. Detection tooling can't reuse Graph SP credentials directly.

2. **Connector classification list is dynamic.** New connectors added regularly by Microsoft. Detection needs a "default classification" reference that can be updated; without it, new connectors appear as "uncategorized" silently and may get permissive default treatment. Worth a `data/power-platform-connectors.json` reference file alongside `data/microsoft-first-party-appids.json` (#361) and `data/transport-rule-actions.json` (proposed in #339).

3. **Tenant settings have many nested booleans.** Mapping to "is this safe" requires authoritative reference — Microsoft's recommended baseline configurations for Power Platform are spread across multiple Learn articles + the CoE Starter Kit.

4. **Environment count can be very large.** 100+ environments is common in mature deployments. Pagination + sampling needed for assessment.

5. **`PBI-*` ↔ `POWERBI-*` namespace duplication.** 11 confirmed duplicate pairs. The existing checks measure the same tenant config from two different scaffolds. Consolidation requires picking one namespace AND deciding what to do with the 3 `PBI-TENANT-*` meta-checks (which appear to be duplicate-of-duplicates).

6. **Power Platform admin module versioning.** `Microsoft.PowerApps.Administration.PowerShell` is updated frequently; Pester regressions should pin a version.

7. **DLP connector classifications can be tenant-overridden.** Microsoft default classifications are not authoritative for all tenants — orgs can override per-policy. Detection should distinguish "Microsoft default" from "explicit org choice."

8. **Copilot governance is emerging surface.** Microsoft is rolling out new Copilot governance APIs through 2025-2026. Detection should treat current findings as snapshots and re-validate against current Microsoft documentation regularly.

## Spawned issues to file

**Namespace consolidation chore (PRIMARY for this audit):**

`chore: consolidate PBI-* and POWERBI-* duplicate Power BI checks` — 11 confirmed duplicate pairs covering the same tenant-config control surface from two namespaces. Plus 3 outlier `PBI-TENANT-*` meta-checks that overlap further. Pick one namespace (probably `POWERBI-*` as the more-explicit name); deprecate the other; document the migration for downstream consumers.

**Gap CheckIDs (`feat:` issues, 17 net):**

1. `feat: POWERPLATFORM-TENANT-ISOLATION-001` — tenant isolation enabled (1.1)
2. `feat: POWERPLATFORM-TENANT-ISOLATION-PARTNERS-001` — partner allow-list management (1.2)
3. `feat: POWERPLATFORM-XTENANT-AUDIT-001` — cross-tenant connection auditing (1.3) — *low priority*
4. `feat: POWERPLATFORM-DEFAULT-ENV-LOCKDOWN-001` — default environment hardened (2.1) — *the #1 governance recommendation*
5. `feat: POWERPLATFORM-PRODUCTION-ENVS-001` — production environments per team (2.2) — *low priority*
6. `feat: POWERPLATFORM-NONPROD-ENVS-001` — non-prod environments labeled + quotas (2.3) — *low priority*
7. `feat: POWERPLATFORM-ENV-LIFECYCLE-001` — stale environment detection (2.4) — *low priority*
8. `feat: POWERPLATFORM-DLP-TENANT-WIDE-001` — tenant-wide DLP policy (3.1)
9. `feat: POWERPLATFORM-DLP-CONNECTOR-CLASS-001` — connector classification (3.2)
10. `feat: POWERPLATFORM-DLP-UNCATEGORIZED-001` — no connectors in uncategorized bucket (3.3)
11. `feat: POWERPLATFORM-DLP-CUSTOM-CONNECTOR-001` — custom connector classification (3.4) — *low priority*
12. `feat: POWERPLATFORM-DLP-HTTP-CONNECTOR-001` — HTTP connector restricted (3.5)
13. `feat: POWERPLATFORM-DLP-PER-ENV-001` — per-environment DLP policy stricter than tenant default (6.2) — *low priority*
14. `feat: POWERPLATFORM-SHARING-RESTRICTION-001` — "who can share" restricted at tenant level (4.1)
15. `feat: POWERPLATFORM-COPILOT-MAKERS-001` — Copilot Studio maker permissions (5.1)
16. `feat: POWERPLATFORM-COPILOT-LABELS-001` — Copilot grounding respects sensitivity labels (5.2) — *cross-spike with #335*
17. `feat: POWERPLATFORM-COPILOT-DEPLOY-001` — Copilot for M365 deployment policies (5.3) — *low priority*

**Possible new canonical data file:**

- `data: introduce data/power-platform-connectors.json` — curated reference of Power Platform connectors with recommended classifications (Business / Non-Business / Blocked). Mirrors the canonical-data-file pattern from `data/role-tiers.json` (#328), `data/microsoft-first-party-appids.json` (#361), `data/transport-rule-actions.json` (proposed in #339). Fourth canonical reference data file across the audit work — worth coordinating these as a v3.5 release theme.

## Out of scope (handled by sibling spikes)

- Application-level Power App security (each app's data sources, role-based access) — too org-specific
- Power BI report-level sensitivity labels — covered under #335 (Purview)
- Dataverse RLS / column security specifics — out of audit scope
- Power Automate runtime telemetry (flow execution patterns) — runtime, not config
- Sign-in patterns for Power Platform admin portal — runtime telemetry, future track
