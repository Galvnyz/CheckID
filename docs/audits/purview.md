# Microsoft Purview — Domain Audit (v3.4.0)

**Status:** Fourteenth and final domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#335](https://github.com/Galvnyz/CheckID/issues/335).
**Source priorities:** Microsoft Learn primary (Microsoft Purview overview, DLP policy creation, Sensitivity labels overview, Retention policies and labels, Insider Risk Management, eDiscovery), CIS M365 v6 §3 (Purview / Compliance), CISA SCuBA `MS.PURVIEW.*` baselines (where applicable), MSRC + Microsoft blog (data exfiltration prevention patterns).

## Summary

CheckID has **16 M365-scope Purview-related checks** (excluding 4 Azure-side retention controls): 6 in `COMPLIANCE-*`, 5 in `PURVIEW-*`, 2 cross-domain Power BI sensitivity labels, plus 3 audit + alert policy meta-checks. This audit catalogs **27 canonical patterns** across 5 sub-domains (DLP policy coverage, sensitivity labels / MIP, retention, eDiscovery + Insider Risk, anti-patterns) and maps them against the registry.

**14 coverage gaps** to file as `feat:` issues, **3 narrative-refresh candidates**, **1 namespace-cross-cluster duplication chore** (`COMPLIANCE-DLP-*` ↔ proposed deeper Purview DLP coverage will overlap), and the **biggest content-quality observation** of the audit series: Purview is the most heterogeneous detection surface — workload coverage gaps (Teams chat, OneDrive sync, etc.) + label-driven configuration that requires cross-referencing labels with consumer policies + Insider Risk's emerging surface area.

This is also the **final v3.4.0 audit**. With this PR, all 14 spikes complete (#327, #328, #329, #330, #331, #332, #333, #334, #336, #337, #338, #339, #340, #335) — the v3.4.0 milestone is ready to close once the spawned-issue backlog is filed.

## Existing CheckID inventory (16 M365-scope)

| CheckId | Severity | Pattern category |
|---|---|---|
| `COMPLIANCE-ALERTPOLICY-001` | High | Security alert policies (meta) |
| `COMPLIANCE-AUDIT-001` | High | M365 audit log search enabled |
| `COMPLIANCE-COMMS-001` | Medium | Communication Compliance policies |
| `COMPLIANCE-DLP-001` | High | DLP policies enabled |
| `COMPLIANCE-DLP-002` | High | DLP policies for Teams |
| `COMPLIANCE-DLP-003` | High | DLP Policies cover Exchange + SPO/OneDrive |
| `COMPLIANCE-LABELS-001` | Medium | Sensitivity label policies published |
| `COMPLIANCE-LABELS-002` | High | Auto-Sensitivity Labeling policies |
| `PBI-LABELS-001` | Medium | PBI: sensitivity labels in Power BI (cross-domain) |
| `POWERBI-INFOPROT-001` | Medium | (duplicate of `PBI-LABELS-001` — see #336 dedup) |
| `PURVIEW-AUDIT-001` | Critical | Unified Audit Logging enabled |
| `PURVIEW-RETENTION-001` | Medium | Data retention policies (general) |
| `PURVIEW-RETENTION-002` | High | Retention policy covers Exchange |
| `PURVIEW-RETENTION-003` | High | Retention policy covers Teams |
| `PURVIEW-RETENTION-004` | High | Retention policy covers SPO/OneDrive |
| `PURVIEW-RETENTION-005` | High | Retention policies in Enforce mode |

## 1. DLP policy coverage

### 1.1 Default templates applied

**Intent:** DLP policies use Microsoft's pre-built sensitive-info-type templates for common regulated data types: U.S. Financial (credit card, SSN), HIPAA (PHI), GDPR (EU PII), Australian PII, etc. Tenants in regulated industries should have at minimum the templates that match their regulatory obligations.
**Detection:** `Get-DlpCompliancePolicy` (Security & Compliance PowerShell) — enumerate policies; identify which use named Microsoft templates vs custom rules.
**Pitfalls:** Templates change over time; tenants that adopted in 2020 may be on outdated templates that don't cover 2024+ patterns (newer SSN formats, EU expanded PII categories).
**Authoritative sources:** Microsoft Learn — Sensitive information types reference; CIS M365 v6 §3.x.
**Coverage:** ✅ partial via `COMPLIANCE-DLP-001` (presence). **Gap on template-currency review.** File `feat: PURVIEW-DLP-TEMPLATES-001`.

### 1.2 Custom sensitive info types reflecting org's actual data

**Intent:** Org-specific data types (employee IDs, customer numbers, IP repository identifiers, source code patterns) are defined as custom sensitive info types. Microsoft templates don't cover org-specific patterns.
**Detection:** `Get-DlpSensitiveInformationType -Type Custom` — verify ≥1 org-specific custom type if the org has documented unique data formats.
**Coverage:** **Gap.** File `feat: PURVIEW-DLP-CUSTOM-SIT-001` (per-org applicability).

### 1.3 Locations covered (Exchange, SharePoint, OneDrive, Teams chat + channel, Devices, Power Platform)

**Intent:** DLP policy coverage spans every relevant location:
- Exchange Online (mail in transit + at rest)
- SharePoint Online sites
- OneDrive accounts
- Teams chat + channel messages
- Devices (endpoint DLP)
- Power Platform connectors (cross-domain)

Tenants commonly have email + SPO covered but miss Teams chat, OneDrive sync, and endpoint.
**Detection:** Per-policy `ExchangeLocation`, `SharePointLocation`, `OneDriveLocation`, `TeamsLocation`, `EndpointDlpLocation`, `OnPremisesScannerDlp` populated.
**Coverage:** ✅ partial via `COMPLIANCE-DLP-002` (Teams) + `COMPLIANCE-DLP-003` (Exchange + SPO/OneDrive). **Gap on Endpoint DLP** — file `feat: PURVIEW-DLP-ENDPOINT-001`.

### 1.4 Action progression: notify → block-with-override → block

**Intent:** Mature DLP rolls out in phases — start with notification (educate users), then block-with-override (force friction but not block), then block (hard enforcement). Most tenants stop at notification.
**Detection:** Per-DLP-rule action distribution; flag policies with only "Notify" actions for >90 days.
**Pitfalls:** Some scenarios (regulated financial data, healthcare PHI) should never have override option. Detection should distinguish "phased rollout in progress" from "stalled at notification."
**Coverage:** **Gap.** File `feat: PURVIEW-DLP-ACTION-PROGRESSION-001`.

### 1.5 Mode in production (test vs enforce)

**Intent:** DLP policies in `Test` mode for >30 days indicate forgotten testing → no enforcement. Should transition to `Enable` (enforcement).
**Detection:** Per-policy `Mode` property: `Enable`, `TestWithNotifications`, `TestWithoutNotifications`. Flag `Test*` modes > 30 days.
**Coverage:** **Gap.** File `feat: PURVIEW-DLP-TEST-MODE-STALE-001`.

### 1.6 DLP policies for high-volume external-recipient detection

**Intent:** Policies that detect mass-recipient outbound mail (e.g., 100+ external recipients in a single message) — a common exfil pattern.
**Coverage:** **Gap (cross-domain with #339).** Could fold into mail flow audit's outbound spam policy work.

## 2. Sensitivity labels (MIP)

### 2.1 Label hierarchy defined (Public → Internal → Confidential → Highly Confidential)

**Intent:** Tenants have a documented label hierarchy with at minimum 4 tiers reflecting data sensitivity. Microsoft's recommended baseline is Public / Internal / Confidential / Highly Confidential, with sublabels for the upper two tiers.
**Detection:** `Get-Label` enumeration; verify ≥4 labels exist and are organized hierarchically.
**Pitfalls:** Some orgs have inconsistent label vocabulary (mixing Microsoft's recommended naming with legacy). Tenants with single-label or no-label hierarchy aren't using MIP meaningfully.
**Authoritative sources:** Microsoft Learn — Sensitivity labels overview.
**Coverage:** ✅ partial via `COMPLIANCE-LABELS-001` (presence). **Narrative refresh recommended** — explicit hierarchy expectations.

### 2.2 Encryption applied at upper tiers

**Intent:** Labels at Confidential + Highly Confidential apply encryption (RMS protection). Label-without-encryption is just metadata; doesn't actually protect content.
**Detection:** Per-label `EncryptionEnabled` + `EncryptionRightsDefinitions` populated for upper tiers.
**Coverage:** **Gap.** File `feat: PURVIEW-LABEL-ENCRYPTION-001`.

### 2.3 Sublabels for granular controls

**Intent:** Sublabels (e.g., Confidential\Finance, Confidential\Legal, Highly Confidential\Customer-PII) enable granular policy decisions — e.g., specific encryption rights per business unit.
**Detection:** `Get-Label` parent-child relationships.
**Coverage:** **Gap (low priority — depends on org maturity).** File `feat: PURVIEW-LABEL-SUBLABELS-001`.

### 2.4 Auto-labeling policies for known patterns

**Intent:** Documents containing known patterns (credit card numbers, SSN, project codenames) are auto-labeled at upload OR on-demand scan. Without auto-labeling, label adoption depends on user discipline.
**Detection:** `Get-AutoSensitivityLabelPolicy` enumeration; per-policy verify scope (Exchange, SharePoint, OneDrive) + condition rules.
**Coverage:** ✅ partial via `COMPLIANCE-LABELS-002` (presence). **Narrative refresh recommended** — explicit scope-coverage framing.

### 2.5 Default label per location

**Intent:** Each location has a default label so unlabeled content gets a baseline classification automatically:
- SharePoint sites: default label per site
- Teams: default label per team
- Outlook: default label on new messages
**Detection:** Per-label-policy `Settings.defaultlabelid` populated per location.
**Coverage:** **Gap.** File `feat: PURVIEW-LABEL-DEFAULTS-001`.

### 2.6 Co-authoring on labeled documents enabled

**Intent:** Co-authoring on encrypted/labeled documents was a longstanding limitation; Microsoft enabled it as a tenant opt-in. Modern tenants should have it on for collaboration friction.
**Detection:** Tenant setting `EnableLabelCoauth` (or equivalent).
**Coverage:** **Gap (low priority).** File `feat: PURVIEW-LABEL-COAUTH-001`.

### 2.7 Power BI sensitivity labels

**Coverage:** ✅ via `PBI-LABELS-001` / `POWERBI-INFOPROT-001` (note: duplicate pair — see #336).

### 2.8 Sensitivity-label site protection (cross-spike)

**Intent:** Sensitivity labels can carry SharePoint site-level protections (block external sharing, force device compliance). Cross-spike with #337 (SPO).
**Coverage:** **Gap (cross-domain with #337 §3.2).** Single CheckID `feat: PURVIEW-LABEL-SITE-PROTECTION-001`. Same surface as #337's `SPO-SENSITIVITY-LABEL-001`.

### 2.9 Teams sensitivity label policy (cross-spike)

**Intent:** Sensitivity labels applied to Teams (block guest access, force private channel only, etc.). Cross-spike with #340.
**Coverage:** **Gap (cross-domain with #340 §2.4).** Single CheckID `feat: PURVIEW-LABEL-TEAMS-001`. Same surface as #340's `TEAMS-SENSITIVITY-LABEL-001`.

### 2.10 Copilot grounding respects sensitivity labels (cross-spike)

**Intent:** Copilot responses respect sensitivity-label-based access. Cross-spike with #336.
**Coverage:** **Gap (cross-domain with #336 §5.2).** Single CheckID `feat: PURVIEW-LABEL-COPILOT-001`. Same surface as #336's `POWERPLATFORM-COPILOT-LABELS-001`.

## 3. Retention

### 3.1 Retention policies per workload

**Intent:** Each workload (Exchange, SharePoint, OneDrive, Teams chat, Yammer/Viva Engage) has at least one retention policy. Tenants commonly miss Teams chat (a relatively new retention scope).
**Coverage:** ✅ `PURVIEW-RETENTION-002` (Exchange), `PURVIEW-RETENTION-003` (Teams), `PURVIEW-RETENTION-004` (SPO/OneDrive). **Gap on Yammer/Viva Engage** — file `feat: PURVIEW-RETENTION-VIVA-001` (low priority).

### 3.2 Retention policies for legal hold scenarios

**Intent:** Legal hold capability (preservation lock) configured + tested. Required for legal / regulatory scenarios where data must be preserved beyond standard retention.
**Detection:** `Get-RetentionCompliancePolicy` filtered to those with preservation-lock enabled.
**Coverage:** **Gap.** File `feat: PURVIEW-RETENTION-LEGAL-HOLD-001`.

### 3.3 Disposition review workflows

**Intent:** When retention period ends, content goes through human disposition review (rather than auto-delete). Compliance requirement for some industries.
**Detection:** `Get-RetentionComplianceRule | Where { $_.RetentionDispositionType -ne 'Delete' }` enumeration.
**Coverage:** **Gap (low priority).** File `feat: PURVIEW-RETENTION-DISPOSITION-001`.

### 3.4 Records management (immutable retention)

**Intent:** Records management labels (vs retention labels) impose immutable retention — content cannot be modified or deleted regardless of user permissions.
**Detection:** `Get-Label -IncludeFileLabel | Where { $_.IsRecord -eq $true }` enumeration.
**Coverage:** **Gap (low priority — depends on regulatory profile).** File `feat: PURVIEW-RECORDS-MGMT-001`.

### 3.5 Retention policies in Enforce mode

**Intent:** Retention policies should be in Enforce mode, not Test or Disabled.
**Coverage:** ✅ `PURVIEW-RETENTION-005`.

## 4. eDiscovery + Insider Risk

### 4.1 eDiscovery permissions assigned to defined role group

**Intent:** eDiscovery (specifically Premium eDiscovery — case management) requires specific role assignments. These role groups should be small and reviewed; not everyone should be `eDiscovery Manager`. Definitely NOT Global Admin assigned for eDiscovery purposes.
**Detection:** `Get-RoleGroup eDiscoveryManager`, `Get-RoleGroup ComplianceAdministrator` membership.
**Coverage:** **Gap.** File `feat: PURVIEW-EDISCOVERY-RBAC-001`.

### 4.2 Premium eDiscovery in use vs Standard

**Intent:** Premium eDiscovery (case management, predictive coding, custodian holds) is licensed separately. For litigation-preparedness, mature orgs use Premium.
**Detection:** Cross-reference license + `Get-ComplianceCase` premium-feature usage.
**Coverage:** **Gap (low priority).** File `feat: PURVIEW-EDISCOVERY-PREMIUM-001`.

### 4.3 Insider Risk Management policies enabled

**Intent:** Insider Risk policies for the major scenarios:
- Data theft by departing user (within N days of resignation, suspicious activity)
- Data leak (exfiltration patterns regardless of departure)
- Security policy violations (security control bypass attempts)

Insider Risk Management is licensed separately (E5 add-on).
**Detection:** `Get-InsiderRiskPolicy` enumeration; verify ≥1 active policy per major scenario.
**Authoritative sources:** Microsoft Learn — Insider Risk Management overview.
**Threats defeated:** Insider data theft (named cases: Storm-X actor playbooks featuring departing employees).
**Coverage:** **Gap.** File `feat: PURVIEW-INSIDER-RISK-001`.

### 4.4 Communication Compliance policies

**Intent:** Communication Compliance covers offensive language, regulatory keywords (e.g., financial services compliance regs), and inappropriate content in Teams + Exchange + Yammer.
**Detection:** `Get-SupervisoryReviewPolicyV2` enumeration; verify ≥1 active.
**Coverage:** ✅ `COMPLIANCE-COMMS-001`. **Narrative refresh recommended** — pair with regulatory-industry framing.

### 4.5 Audit log retention period

**Intent:** Unified Audit Log retention period set per regulatory needs:
- Default 90 days (E3)
- 1 year (E5 + Audit add-on)
- Up to 10 years (E5 + 10-year retention add-on)

Insufficient retention defeats incident response (can't review activity from 6 months ago).
**Detection:** `Get-AuditConfig` + per-retention-policy.
**Coverage:** **Gap.** File `feat: PURVIEW-AUDIT-RETENTION-001`.

## 5. Anti-patterns (deliberate detection)

### 5.1 DLP policies in test mode for >30 days

**Coverage:** Folds into 1.5.

### 5.2 Sensitivity labels published but no auto-labeling policies

**Intent:** Labels exist but rely entirely on user choice. Most users don't apply labels manually → label adoption stays low → MIP isn't meaningfully protective.
**Detection:** Count `Get-Label` vs `Get-AutoSensitivityLabelPolicy`; flag tenants with labels but no auto-labeling policies > 60 days post-label-creation.
**Coverage:** **Gap.** File `feat: PURVIEW-LABEL-AUTO-MISSING-001`.

### 5.3 Encryption labels without "Allow offline access" expiration

**Intent:** When encrypted content is opened offline, RMS caches access. Without offline-access expiration, a former employee retains decryption access indefinitely after leaving — until cache invalidation.
**Detection:** Per-label `OfflineAccessDuration` ≤ org-defined threshold (typically 7-30 days).
**Coverage:** **Gap.** File `feat: PURVIEW-LABEL-OFFLINE-EXPIRY-001`.

### 5.4 Retention policies missing Teams chat

**Intent:** Modern collaboration data lives in Teams chat. Retention coverage that misses Teams = entire conversations lost.
**Coverage:** ✅ `PURVIEW-RETENTION-003`.

### 5.5 DLP policy "low match accuracy" thresholds

**Intent:** Low confidence threshold = high false-positive rate = user fatigue. DLP rules should have appropriate confidence thresholds (≥85% match accuracy for most patterns).
**Detection:** Per-rule `MinConfidenceLevel`.
**Coverage:** **Gap (low priority).** File `feat: PURVIEW-DLP-CONFIDENCE-001`.

### 5.6 Insider Risk policies enabled but no analysts assigned

**Intent:** Insider Risk policies generate alerts; without analyst role assignments, alerts go nowhere.
**Detection:** `Get-RoleGroup InsiderRiskManagement` + analyst role membership.
**Coverage:** **Gap.** File `feat: PURVIEW-INSIDER-RISK-ANALYSTS-001`.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| DLP policy coverage | 6 | 1 partial | 0 | 4 (1.1 templates, 1.2 custom SIT, 1.4 progression, 1.5 test-mode-stale); 1.3 Endpoint partial; 1.6 cross-spike |
| Sensitivity labels (MIP) | 10 | 2 partial | 2 | 5 (2.2 encryption, 2.3 sublabels low-pri, 2.5 defaults, 2.6 coauth low-pri, 2.10 cross-spike); 2.7 ✅; 2.8/2.9/2.10 cross-spike |
| Retention | 5 | 4 | 0 | 3 (3.1 Viva low-pri, 3.2 legal hold, 3.3 disposition low-pri, 3.4 records low-pri) |
| eDiscovery + Insider Risk | 5 | 1 (4.4) | 1 | 4 (4.1 RBAC, 4.2 premium low-pri, 4.3 IRM, 4.5 audit retention) |
| Anti-patterns | 6 | 1 (5.4) | 0 | 3 (5.2, 5.3, 5.6); 5.1 + 5.5 fold |
| **Total** | **32 (27 unique after folds)** | **9** | **3** | **14 net to file** |

(Plus 3 cross-spike CheckID consolidations: site-protection with #337, Teams labels with #340, Copilot labels with #336.)

## Threat-pattern map

| Compromise pattern | Tradecraft | Primary control |
|---|---|---|
| Data theft by departing employee | Mass file download / external upload in last 30 days | Insider Risk Management policy (4.3) |
| Outbound email with sensitive content | User mistakenly attaches credit card / SSN-bearing doc | DLP policy + appropriate action progression (1.4) |
| Sensitive label content cached on personal device | Former employee retains decryption indefinitely | Offline access duration limit (5.3) |
| Modern collaboration data lost | Teams chat not in retention policy | Retention covers Teams ✅ (`PURVIEW-RETENTION-003`) |
| MIP without auto-labeling | Labels exist but adoption stays low without auto-labeling | Auto-labeling policies match label scope (5.2) |
| eDiscovery role over-permissioned | Anyone-as-eDiscovery-manager can search/export org content | eDiscovery RBAC restricted (4.1) |
| Insider Risk alerts go nowhere | Policies enabled but analyst role unassigned | Analyst role membership (5.6) |
| Audit log evidence missing for incident | Default 90-day retention insufficient for IR | Audit retention period extended (4.5) |
| Endpoint DLP gap | Sensitive data exfiltrated via USB / cloud sync | Endpoint DLP location coverage (1.3) |
| Custom org data not protected | Org-specific patterns (employee IDs, IP) not in DLP | Custom sensitive info types (1.2) |

## Detection method appendix

### Primary: Security & Compliance PowerShell

Like #332 (MDO), Purview lives almost entirely outside Microsoft Graph. Detection uses Security & Compliance PowerShell + Exchange Online connector.

| Cmdlet | Used for |
|---|---|
| `Get-DlpCompliancePolicy` / `Get-DlpComplianceRule` | DLP policy + rule inventory (1.x) |
| `Get-DlpSensitiveInformationType` | Built-in + custom sensitive info types (1.1, 1.2) |
| `Get-Label` / `Get-LabelPolicy` | Sensitivity labels + label policies (2.x) |
| `Get-AutoSensitivityLabelPolicy` / `Get-AutoSensitivityLabelRule` | Auto-labeling policies (2.4) |
| `Get-RetentionCompliancePolicy` / `Get-RetentionComplianceRule` | Retention policies + rules (3.x) |
| `Get-ComplianceCase` / `Get-ComplianceTag` | eDiscovery + records management (4.1, 4.2) |
| `Get-InsiderRiskPolicy` | Insider Risk Management policies (4.3) |
| `Get-SupervisoryReviewPolicyV2` | Communication Compliance (4.4) |
| `Get-AuditConfig` | Unified Audit Log retention period (4.5) |
| `Get-RoleGroup` | RBAC for compliance roles |

### Edge cases

1. **Multiple PowerShell modules required.** Detection spans S&C PowerShell + Exchange Online + Compliance Center modules. Auth flows differ; consumers need to handle each connection.

2. **Policy `Mode` enum.** `Enable`, `TestWithNotifications`, `TestWithoutNotifications`, `Disable`. Identical-output between `Enable` and `Test*` in Get-* cmdlets — must read `Mode` field carefully.

3. **Sensitivity labels are 3 artifacts.**
   - Label store (`Get-Label`) — what labels exist
   - Label policies (`Get-LabelPolicy`) — who gets which labels
   - Auto-labeling policies (`Get-AutoSensitivityLabelPolicy`) — automatic label application
   All three need reconciliation for the full picture.

4. **Retention labels vs retention policies.** Two different artifacts with overlapping but separate cmdlets:
   - Retention policy (`Get-RetentionCompliancePolicy`) — applies to all content in scope
   - Retention label (`Get-Label -IncludeFileLabel`) — applies per-document via labeling
   Don't conflate.

5. **Endpoint DLP requires onboarded devices.** Endpoint DLP coverage requires devices to be onboarded to Defender for Endpoint. Detection should distinguish "policy configured" from "devices reporting telemetry" (cross-domain to #334 Intune).

6. **Insider Risk requires E5 + IRM addon.** License-gated. Detection should distinguish "feature not licensed" from "feature unused."

7. **Auto-labeling scope is per-location.** Auto-labeling policies have scope (Exchange, SPO, OneDrive). Tenants commonly auto-label SPO but not Exchange or vice versa — partial coverage.

8. **Records management vs retention labels.** Records labels (`IsRecord = true`) impose immutable retention beyond standard retention behavior. Detection should treat these as a distinct sub-category, not lump with retention labels.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 14 net):**

1. `feat: PURVIEW-DLP-TEMPLATES-001` — Microsoft template currency review (1.1)
2. `feat: PURVIEW-DLP-CUSTOM-SIT-001` — custom sensitive info types for org-specific data (1.2)
3. `feat: PURVIEW-DLP-ENDPOINT-001` — Endpoint DLP location coverage (1.3)
4. `feat: PURVIEW-DLP-ACTION-PROGRESSION-001` — DLP rule action progression notify→block (1.4)
5. `feat: PURVIEW-DLP-TEST-MODE-STALE-001` — DLP policies stuck in Test mode (1.5)
6. `feat: PURVIEW-LABEL-ENCRYPTION-001` — encryption applied at upper-tier labels (2.2)
7. `feat: PURVIEW-LABEL-SUBLABELS-001` — sublabel hierarchy (2.3) — *low priority*
8. `feat: PURVIEW-LABEL-DEFAULTS-001` — default label per location (2.5)
9. `feat: PURVIEW-LABEL-COAUTH-001` — co-authoring on labeled documents (2.6) — *low priority*
10. `feat: PURVIEW-RETENTION-VIVA-001` — Yammer/Viva Engage retention (3.1) — *low priority*
11. `feat: PURVIEW-RETENTION-LEGAL-HOLD-001` — preservation lock for legal hold (3.2)
12. `feat: PURVIEW-RETENTION-DISPOSITION-001` — disposition review workflows (3.3) — *low priority*
13. `feat: PURVIEW-RECORDS-MGMT-001` — records management labels (3.4) — *low priority*
14. `feat: PURVIEW-EDISCOVERY-RBAC-001` — eDiscovery role group restricted (4.1)
15. `feat: PURVIEW-EDISCOVERY-PREMIUM-001` — Premium eDiscovery in use (4.2) — *low priority*
16. `feat: PURVIEW-INSIDER-RISK-001` — Insider Risk Management policies (4.3)
17. `feat: PURVIEW-AUDIT-RETENTION-001` — audit log retention period (4.5)
18. `feat: PURVIEW-LABEL-AUTO-MISSING-001` — labels published but no auto-labeling (5.2)
19. `feat: PURVIEW-LABEL-OFFLINE-EXPIRY-001` — encryption offline-access duration (5.3)
20. `feat: PURVIEW-DLP-CONFIDENCE-001` — DLP rule confidence threshold (5.5) — *low priority*
21. `feat: PURVIEW-INSIDER-RISK-ANALYSTS-001` — Insider Risk policies have analysts assigned (5.6)

**Cross-spike (single CheckID, document overlap):**

- `PURVIEW-LABEL-SITE-PROTECTION-001` (this audit §2.8) ↔ `SPO-SENSITIVITY-LABEL-001` (#337 §3.2) — same surface
- `PURVIEW-LABEL-TEAMS-001` (this audit §2.9) ↔ `TEAMS-SENSITIVITY-LABEL-001` (#340 §2.4) — same surface
- `PURVIEW-LABEL-COPILOT-001` (this audit §2.10) ↔ `POWERPLATFORM-COPILOT-LABELS-001` (#336 §5.2) — same surface

**Narrative refresh (`chore:` issues, 3):**

- `chore: refresh COMPLIANCE-LABELS-001 narrative` — explicit hierarchy expectations (4-tier baseline)
- `chore: refresh COMPLIANCE-LABELS-002 narrative` — explicit scope-coverage framing (Exchange + SPO + OneDrive)
- `chore: refresh COMPLIANCE-COMMS-001 narrative` — pair with regulatory-industry framing

## Out of scope (handled by sibling spikes)

- Microsoft Priva (privacy management — separate product)
- Compliance Manager scoring (separate)
- Data Map / data catalog scanning (Azure Purview overlap)
- Communication compliance content sampling specifics — touched lightly
- Sensitivity labels in Power BI — `PBI-LABELS-001` / `POWERBI-INFOPROT-001` (already covered, with #336 dedup chore)
- Endpoint DLP onboarding (Defender for Endpoint integration) — #334 Intune adjacency

---

## v3.4.0 audit umbrella complete

This is the **fourteenth and final domain audit** of the v3.4.0 audit umbrella (#326). All 14 spikes are now resolved:

| # | Domain | PR | Spike |
|---|---|---|---|
| 1 | Conditional Access | merged | #327 |
| 2 | Privileged access (PIM) | merged | #328 |
| 3 | MFA enforcement | merged | #329 |
| 4 | Authentication methods | merged | #330 |
| 5 | Token + session security | merged | #331 |
| 6 | External / guest collaboration | merged | #333 |
| 7 | Defender for Office | merged | #332 |
| 8 | SharePoint + OneDrive | merged | #337 |
| 9 | Microsoft Teams | merged | #340 |
| 10 | Mail flow | merged | #339 |
| 11 | Microsoft Intune | merged | #334 |
| 12 | Defender for Cloud Apps | merged | #338 |
| 13 | Power Platform | merged | #336 |
| 14 | Microsoft Purview | this PR | #335 |

Once this PR merges, the v3.4.0 milestone is ready for the next phase: **filing the spawned-issue backlog** (~150 `feat:` gap CheckIDs + ~40 `chore:` narrative-refresh + ~10 cross-spike consolidations + ~6 namespace consolidations + 4 canonical data file proposals). That filing is mechanical batch work; happy to do it in chunks once you give the green light.

The audit work surfaces several cross-cutting themes that would benefit from coordinated treatment:

1. **AZ-namespace boundary issues** — `AZ-IDENTITY-015/016/030/039/041` are Entra controls in the AZ namespace. Filed as boundary chores in #331, #333, etc.
2. **Namespace duplications** — `DEFENDER-* ↔ EXO-*` (3 pairs from #332), `PBI-* ↔ POWERBI-*` (11 pairs from #336), and the implicit `COMPLIANCE-DLP-* ↔ proposed PURVIEW-DLP-*` overlap.
3. **Canonical data file pattern** — 4 proposed: `data/role-tiers.json` (#328), `data/microsoft-first-party-appids.json` (#361), `data/transport-rule-actions.json` (#339), `data/power-platform-connectors.json` (#336). Worth coordinating as a v3.5 release theme.
4. **Detection-method surface diversity** — 5 distinct detection contracts surfaced: Microsoft Graph, Exchange Online PowerShell, S&C PowerShell, MDCA REST API, Power Platform admin PowerShell. Each consumer needs to handle multiple. Worth a `docs/CONSUMER-GUIDE.md` page documenting the contracts.
