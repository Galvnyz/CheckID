# Microsoft Defender for Cloud Apps (MDCA) — Domain Audit (v3.4.0)

**Status:** Twelfth domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#338](https://github.com/Galvnyz/CheckID/issues/338).
**Source priorities:** Microsoft Learn primary (Microsoft Defender for Cloud Apps overview, Connect apps to MDCA, App governance, Conditional Access app control, Anomaly detection policies), MSRC blog (OAuth consent abuse patterns; Storm-X actor playbooks targeting OAuth grants).

## Summary

CheckID has a **stark asymmetry** in this domain: only **1 MDCA-specific check** (`DEFENDER-CLOUDAPPS-001` — "is MDCA enabled") versus **27 OAuth/app-governance checks** in `ENTRA-ENTAPP-*` and `ENTRA-CONSENT-*` namespaces. The OAuth governance dimension that MDCA's spike #338 covers is heavily catalogued already at the Entra layer; MDCA's distinct value (Cloud Discovery, session policies, anomaly detection, app governance integration) is barely covered.

This audit catalogs **24 canonical patterns** across 5 sub-domains (app connectors, OAuth app governance, Cloud Discovery, session policies, anomaly detection + alert policies). Maps the existing checks against the patterns. **15 coverage gaps** to file as `feat:` issues, **2 narrative-refresh candidates**.

The audit also surfaces a **strategic finding**: OAuth governance has migrated from MDCA-specific into Entra ID's app governance feature (formerly called "App Governance for Microsoft 365" addon). Many of the "MDCA OAuth governance" patterns are now Entra-side controls (which CheckID covers extensively). Net: this audit's gap list focuses on the *uniquely-MDCA* surfaces — Cloud Discovery, session policies, anomaly detection — rather than re-cataloguing OAuth.

## Existing CheckID inventory

### MDCA-specific (1 check)

| CheckId | Severity | Pattern category |
|---|---|---|
| `DEFENDER-CLOUDAPPS-001` | Medium | MDCA enabled + configured |

### Entra app governance / OAuth (cross-domain, 27 checks)

The `ENTRA-ENTAPP-*` (21) + `ENTRA-CONSENT-*` (6) namespaces cover OAuth governance comprehensively. These are catalogued in #328 (privileged access — for SP roles) and the Entra app-registration tier rather than under MDCA. Highlights for cross-reference:

- `ENTRA-CONSENT-001/-002/-003/-004/-005/-006` — admin consent workflow + user consent restrictions
- `ENTRA-ENTAPP-001/-002` — apps with credentials, inactive credentialed apps
- `ENTRA-ENTAPP-003/-004/-005` — foreign apps with dangerous permissions / directory roles
- `ENTRA-ENTAPP-008/-009` — managed identities with dangerous permissions / directory roles
- `ENTRA-ENTAPP-010` — Critical: internal apps with Tier 0 permissions
- `ENTRA-ENTAPP-011` — foreign apps with Tier 1 data access permissions
- `ENTRA-ENTAPP-014/-015/-016/-017` — credentials posture and ownership of privileged apps
- `ENTRA-ENTAPP-018/-019` — orphan + unused-privileged apps
- `ENTRA-ENTAPP-020` — foreign apps impersonating Microsoft display names
- `ENTRA-ENTAPP-021` — multi-tenant app registrations

These are CheckID's strongest single-domain coverage area (27 checks). MDCA-specific gaps below are about MDCA's *additional* visibility on top of what Entra provides natively.

## 1. App connectors

### 1.1 Microsoft 365 connector configured

**Intent:** MDCA's M365 connector ingests data from Exchange, SharePoint, OneDrive, Teams via Graph + EWS. This is the foundational connector for any MDCA deployment in M365.
**Detection:** MDCA REST API `/api/v1/data_enrichment/connectors` — verify M365 connector present + active. (MDCA API uses per-tenant URL `https://<tenant>.portal.cloudappsecurity.com/api/`.)
**Coverage:** ✅ partial via `DEFENDER-CLOUDAPPS-001` (MDCA enabled). **Narrative refresh recommended** — explicit M365-connector-required framing.

### 1.2 Third-party SaaS connectors enabled where licensed

**Intent:** Tenants licensed for cross-cloud coverage (Box, Salesforce, ServiceNow, Google Workspace, AWS, Azure) connect those SaaS surfaces. Without third-party connectors, MDCA only sees M365 — narrower than the value proposition.
**Detection:** MDCA `/api/v1/data_enrichment/connectors` — enumerate beyond M365.
**Pitfalls:** Each connector requires its own consent + permissions; partial deployments are common.
**Coverage:** **Gap.** File `feat: MDCA-CONNECTOR-SAAS-001`.

### 1.3 Connector permissions (least privilege for scan)

**Intent:** Connectors granted only the scopes required for visibility, not write access. (Most MDCA connectors are read-only by design, but some configurations grant broader access.)
**Detection:** Per-connector `oauthScope` review.
**Coverage:** **Gap (low priority).** File `feat: MDCA-CONNECTOR-SCOPE-001`.

## 2. OAuth app governance

### 2.1 High-permission OAuth apps detected and reviewed

**Intent:** OAuth apps with high-impact scopes (Mail.Read.Shared, Files.ReadWrite.All, Directory.Read.All, etc.) are inventoried + reviewed.
**Detection:** Cross-domain — already covered by `ENTRA-ENTAPP-003`, `ENTRA-ENTAPP-004`, `ENTRA-ENTAPP-006`, `ENTRA-ENTAPP-010`, `ENTRA-ENTAPP-011`. No new MDCA-specific CheckID needed.
**Coverage:** ✅ via Entra namespace.

### 2.2 Auto-revoke policies for high-risk app permissions

**Intent:** When an OAuth app reaches a defined risk threshold (suspicious scope combinations, MS publisher impersonation, no recent verified-publisher status), MDCA can auto-revoke its grants.
**Detection:** Microsoft 365 Defender app governance policies (Graph beta `/security/applicationGovernance/policies`); per-policy revocation actions.
**Pitfalls:** App governance is licensed separately (Microsoft 365 Defender plan + app governance addon). Detection should distinguish "feature available but not used" from "feature not licensed."
**Authoritative sources:** Microsoft Learn — Microsoft 365 Defender app governance policies.
**Threats defeated:** OAuth consent abuse (Storm-X tradecraft); T1098.001 (Additional Cloud Credentials), T1528 (Steal Application Access Token).
**Coverage:** **Gap.** File `feat: MDCA-APPGOVERN-AUTO-REVOKE-001`.

### 2.3 Publisher-verified-only enforcement for end-user OAuth grants

**Intent:** End users can only consent to apps from verified publishers (Microsoft-vetted ID program). Stops most opportunistic OAuth phishing.
**Detection:** Cross-domain — covered by `ENTRA-CONSENT-003`. Not a new MDCA-specific CheckID.
**Coverage:** ✅ via Entra namespace.

### 2.4 Workload identity / managed identity inventory

**Intent:** Service principals + managed identities are inventoried and high-permission ones flagged.
**Coverage:** Cross-domain — covered by `ENTRA-ENTAPP-008`, `ENTRA-ENTAPP-009` and #328's privileged-access SP rotation work.

### 2.5 Recent app consent activity reviewed

**Intent:** App consent grants over the last N days reviewed by an admin (consent surge detection — see Storm-X campaigns).
**Detection:** Microsoft 365 Defender app governance OR MDCA OAuth app activity dashboard. Programmatic: `/security/applicationGovernance/policies` activity, or audit logs `Search-UnifiedAuditLog -Operations 'Add app role assignment grant to user'`.
**Coverage:** **Gap.** File `feat: MDCA-CONSENT-SURGE-001`.

## 3. Cloud Discovery

### 3.1 Cloud Discovery report ingested

**Intent:** Cloud Discovery analyzes traffic logs (Defender for Endpoint integration, log collector for unmanaged endpoints, manual upload) to surface shadow IT — apps users access from corporate networks that aren't sanctioned.
**Detection:** MDCA `/api/v1/discovery/reports` — enumerate report sources + recent ingestion.
**Pitfalls:** No reports = either no integration OR no shadow IT visibility — distinguish in the verdict.
**Coverage:** **Gap.** File `feat: MDCA-DISCOVERY-INGESTION-001`.

### 3.2 Sanctioned / unsanctioned app classification reviewed

**Intent:** Discovered apps classified as Sanctioned / Unsanctioned / Monitored. Stale or empty classification = no governance signal.
**Detection:** MDCA `/api/v1/saas/services` — enumerate classification distribution.
**Coverage:** **Gap.** File `feat: MDCA-DISCOVERY-CLASSIFICATION-001`.

### 3.3 Risk-rating thresholds for "block in proxy" vs "monitor"

**Intent:** Tenant has defined risk-rating thresholds tied to enforcement actions (e.g., apps with risk score < 5 block at proxy; 5-7 monitor; 7+ allow).
**Detection:** MDCA per-app risk score + tenant policy thresholds.
**Coverage:** **Gap (low priority — depends on org maturity).** File `feat: MDCA-DISCOVERY-RISK-THRESHOLD-001`.

## 4. Session policies (Conditional Access App Control)

### 4.1 Session policies for sensitive SaaS apps

**Intent:** Block download of labeled files, monitor activity, prevent copy/paste from selected SaaS apps via reverse proxy. Most useful for unmanaged-device access to sensitive cloud workloads.
**Detection:** MDCA `/api/v1/policies` — enumerate session policies and their target apps.
**Authoritative sources:** Microsoft Learn — Conditional Access app control deployment.
**Coverage:** **Gap.** File `feat: MDCA-SESSION-POLICY-001`.

### 4.2 Session policies tied to CA "Use Conditional Access App Control" grant

**Intent:** Session policy in MDCA is meaningful only when paired with CA policy session control `Use Conditional Access App Control`. Without the CA pairing, the session policy doesn't activate.
**Detection:** Cross-reference: MDCA session policies + CA policies with `cloudAppSecurity.cloudAppSecurityType` = `monitorOnly` / `blockDownloads` / `mcasConfigured`.
**Pitfalls:** This is the most common MDCA misconfiguration: session policy created in MDCA UI but no CA policy uses it. Effectively dead config.
**Coverage:** **Gap.** File `feat: MDCA-SESSION-CA-PAIRING-001`. *Cross-domain with #327.*

### 4.3 Block-on-anomaly session policy

**Intent:** Session policy with anomaly conditions (impossible travel + sensitive download, anomalous bulk download) that blocks the session in real time.
**Detection:** MDCA session policies with anomaly conditions populated.
**Coverage:** **Gap (low priority — high-maturity feature).** File `feat: MDCA-SESSION-ANOMALY-001`.

## 5. Anomaly detection + alert policies

### 5.1 Default anomaly policies enabled

**Intent:** MDCA ships default anomaly policies (impossible travel, infrequent country, unusual file activity, mass download, mass deletion, etc.). All should be enabled in a baseline configuration.
**Detection:** MDCA `/api/v1/policies` filtered by `policyType=ANUBIS_DETECTION` (or equivalent) — verify default policies in `enabled` state.
**Pitfalls:** Some tenants disable anomaly policies "due to noise" — better to tune sensitivity than disable.
**Coverage:** **Gap.** File `feat: MDCA-ANOMALY-DEFAULT-001`.

### 5.2 Custom alert policies for org-specific patterns

**Intent:** Org-specific alert policies (mass download from Sales SaaS, bulk delete from finance, share to external by HR) tuned to the tenant's threat model.
**Detection:** Beyond default policy count — custom policies tied to org-specific labels / conditions.
**Coverage:** **Gap (low priority — depends on org maturity).** File `feat: MDCA-ANOMALY-CUSTOM-001`.

### 5.3 Alert routing to SOC tooling

**Intent:** Alerts route to Sentinel / Microsoft Sentinel / ServiceNow / SIEM rather than dying in the MDCA UI. Critical for actionable response.
**Detection:** MDCA SIEM connector configuration; `/api/v1/data_enrichment/log_collectors` for log forwarding.
**Coverage:** **Gap.** File `feat: MDCA-ALERT-ROUTING-001`.

### 5.4 Auto-remediation for high-confidence anomalies

**Intent:** Some anomalies (impossible travel, suspicious sign-in from unusual country) can auto-remediate — suspend user, require MFA, force password reset. High-confidence policies have auto-remediation; low-confidence ones alert for human review.
**Detection:** MDCA policies with `governance` actions populated; verify per-policy.
**Coverage:** **Gap (low priority).** File `feat: MDCA-AUTO-REMEDIATE-001`.

## 6. Anti-patterns (deliberate detection)

### 6.1 MDCA licensed but only M365 connector enabled

**Intent:** Tenant has the MDCA license but only M365 connector deployed; missing visibility into third-party SaaS = wasted license.
**Coverage:** Folds into 1.2 narrative.

### 6.2 Default anomaly policies disabled "due to noise"

**Intent:** Disabling instead of tuning indicates SOC fatigue + reduced visibility. Better path: tune sensitivity per policy.
**Coverage:** Folds into 5.1.

### 6.3 OAuth app governance reviewed manually with no policy enforcement

**Intent:** Tenant has visibility into high-permission apps but no auto-revoke policy → reactive, not preventive.
**Coverage:** Folds into 2.2.

### 6.4 Cloud Discovery reports never reviewed (sanctioning never happens)

**Intent:** Reports ingested but apps never classified Sanctioned/Unsanctioned → effectively dead data.
**Coverage:** Folds into 3.2.

### 6.5 Session policies in monitor-only mode for >90 days

**Intent:** Session policy stuck in `monitorOnly` mode beyond a reasonable test window indicates intent-to-enforce that never followed through. Same anti-pattern as Token Protection monitor-only stale (#331 §3.2).
**Detection:** Per-policy `actions` includes `monitorOnly` AND `modifiedDateTime` > 90 days ago.
**Coverage:** **Gap (low priority).** File `feat: MDCA-SESSION-MONITOR-STALE-001`.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| App connectors | 3 | 1 partial | 1 (1.1) | 2 (1.2, 1.3 low-pri) |
| OAuth app governance | 5 | 3 (cross-domain to ENTRA-*) | 0 | 2 (2.2, 2.5) |
| Cloud Discovery | 3 | 0 | 0 | 3 (3.1, 3.2, 3.3 low-pri) |
| Session policies | 3 | 0 | 0 | 3 (4.1, 4.2, 4.3 low-pri) |
| Anomaly detection + alert policies | 4 | 0 | 0 | 4 (5.1, 5.2 low-pri, 5.3, 5.4 low-pri) |
| Anti-patterns | 5 | 0 | 0 | 1 unique (6.5); others fold |
| **Total** | **23 (24 with anti-pattern fold)** | **4 + 3 cross-domain** | **1** | **15 net to file** |

## Threat-pattern map

| Compromise pattern | Tradecraft | Primary control |
|---|---|---|
| OAuth consent abuse / Storm-X campaigns | Phishing user into granting OAuth scope to attacker app | App governance auto-revoke (2.2) + verified-publisher restriction (2.3, ENTRA-CONSENT-003) |
| Sudden surge of new app consent | Storm-0539-style consent campaign | Recent consent activity review (2.5) |
| Unsanctioned SaaS access ("shadow IT") | Users discovering corporate data exfil paths via personal SaaS apps | Cloud Discovery ingestion + classification (3.1, 3.2) |
| Sensitive download from unmanaged device | BYOD-flavored data exfil from sensitive SaaS | Session policy block-download (4.1) + CA pairing (4.2) |
| Impossible travel sign-in pattern | Compromised credentials used from unusual geography | Default anomaly policies enabled (5.1) + auto-remediation (5.4) |
| Mass file download / bulk delete | Insider threat or compromised account exfiltrating | Custom alert policies (5.2) + alert routing to SOC (5.3) |
| Multi-cloud blind spot | Org uses Azure + AWS + GCP; only M365 visibility | Third-party SaaS connectors (1.2) |

## Detection method appendix

### Primary surface: MDCA REST API + Microsoft 365 Defender (app governance)

This is the first audit where detection lives in **a per-tenant URL endpoint** — MDCA's REST API at `https://<tenant>.portal.cloudappsecurity.com/api/v1/`. App governance lives separately in Microsoft 365 Defender via Graph beta.

| Endpoint | Used for |
|---|---|
| `GET /api/v1/policies` | All MDCA policies (anomaly, session, alert) |
| `GET /api/v1/discovery/reports` | Cloud Discovery report inventory + recency |
| `GET /api/v1/saas/services` | Sanctioned / Unsanctioned / Monitored classification |
| `GET /api/v1/data_enrichment/connectors` | M365 + third-party SaaS connectors |
| `GET /api/v1/data_enrichment/log_collectors` | Log collector configuration |
| `GET /api/v1/data_enrichment/ip_address_ranges` | Custom IP ranges |
| Microsoft 365 Defender Graph beta:|  |
| `GET /security/applicationGovernance/policies` | App governance policies (auto-revoke, surge detection) |
| Audit logs: |  |
| `Search-UnifiedAuditLog -Operations 'Add app role assignment grant to user'` | OAuth grant audit trail (2.5 surge detection) |

### Edge cases

1. **Per-tenant URL.** MDCA API is `https://<tenant>.portal.cloudappsecurity.com/api/` — not a standard Graph endpoint. Detection logic needs to discover the per-tenant URL (Microsoft 365 admin center → MDCA portal redirect, or DNS lookup pattern). Tooling has to handle the discovery.

2. **Authentication is separate from Graph.** MDCA API uses its own OAuth flow with API tokens generated in the MDCA portal. Service principal auth requires explicit MDCA-side configuration, not just Graph permissions.

3. **App governance vs MDCA OAuth governance overlap.** Microsoft has migrated OAuth governance from MDCA-specific into Microsoft 365 Defender's "App Governance" (formerly the "App Governance for Microsoft 365" addon). Modern path: use `/security/applicationGovernance/policies`. Older path: MDCA's own OAuth dashboard. Detection should prefer the Defender Graph endpoint.

4. **License detection.** Distinguish "feature not licensed" from "feature available but unused" — different remediation. App Governance is licensed via Microsoft 365 E5 + App Governance addon (separate from MDCA license).

5. **Cloud Discovery requires log ingestion.** "No reports" can mean (a) no Defender for Endpoint integration, (b) no log collector for unmanaged endpoints, OR (c) no shadow IT — detection must distinguish.

6. **Session policy + CA pairing dependency.** Most common MDCA misconfiguration: session policy created in MDCA UI but no CA policy references it. Effectively dead config. Cross-reference required.

7. **Anomaly policy thresholds vary by Microsoft tuning.** Default policies' sensitivity changes over time as Microsoft updates baselines. Detection should distinguish "Microsoft default" from "tenant-explicitly-tuned."

8. **SIEM forwarding vs alert email.** Alerts can route to email OR SIEM. Email alerts are often missed; SIEM integration is the modern best practice.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 15 net):**

1. `feat: MDCA-CONNECTOR-SAAS-001` — third-party SaaS connectors deployed (1.2)
2. `feat: MDCA-CONNECTOR-SCOPE-001` — connector least-privilege scope (1.3) — *low priority*
3. `feat: MDCA-APPGOVERN-AUTO-REVOKE-001` — auto-revoke policies for high-risk apps (2.2)
4. `feat: MDCA-CONSENT-SURGE-001` — recent consent activity review / surge detection (2.5)
5. `feat: MDCA-DISCOVERY-INGESTION-001` — Cloud Discovery report ingested (3.1)
6. `feat: MDCA-DISCOVERY-CLASSIFICATION-001` — Sanctioned / Unsanctioned classification reviewed (3.2)
7. `feat: MDCA-DISCOVERY-RISK-THRESHOLD-001` — risk-rating thresholds tied to enforcement (3.3) — *low priority*
8. `feat: MDCA-SESSION-POLICY-001` — session policies for sensitive SaaS (4.1)
9. `feat: MDCA-SESSION-CA-PAIRING-001` — session policies tied to CA App Control grant (4.2) — *cross-domain with #327*
10. `feat: MDCA-SESSION-ANOMALY-001` — block-on-anomaly session policy (4.3) — *low priority*
11. `feat: MDCA-ANOMALY-DEFAULT-001` — default anomaly policies enabled (5.1)
12. `feat: MDCA-ANOMALY-CUSTOM-001` — custom alert policies for org-specific patterns (5.2) — *low priority*
13. `feat: MDCA-ALERT-ROUTING-001` — alert routing to SOC tooling (5.3)
14. `feat: MDCA-AUTO-REMEDIATE-001` — auto-remediation for high-confidence anomalies (5.4) — *low priority*
15. `feat: MDCA-SESSION-MONITOR-STALE-001` — session policies stuck in monitor-only > 90 days (6.5) — *low priority*

**Cross-spike (single CheckID, document overlap):**

- `MDCA-SESSION-CA-PAIRING-001` covers a CA-side session control type that #327 discusses; single CheckID with cross-link
- App governance auto-revoke (2.2) is a Microsoft 365 Defender feature — clarify in narrative whether to file as `MDCA-*` or `DEFENDER-APPGOVERN-*` namespace

**Narrative refresh (`chore:` issues, 1):**

- `chore: refresh DEFENDER-CLOUDAPPS-001 narrative` — explicit M365-connector-required framing + the asymmetry that this is "presence" only, not configuration depth

## Out of scope (handled by sibling spikes)

- Defender XDR cross-product correlation — not specifically MDCA, separate concern
- Defender for Identity (sibling product, AD-focused) — separate product
- Sentinel + MDCA streaming — separate integration concern
- OAuth app governance / consent grants — `ENTRA-CONSENT-*` (already covered) + #328 (privileged access SP)
- App impersonating Microsoft display names — `ENTRA-ENTAPP-020` (already covered)
