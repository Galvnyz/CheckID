# Defender for Office 365 — Domain Audit (v3.4.0)

**Status:** Seventh domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#332](https://github.com/Galvnyz/CheckID/issues/332).
**Source priorities:** Microsoft Learn primary (Preset security policies, Recommended settings for EOP and MDO, Configuration analyzer for protection policies, Anti-phishing/Safe Links/Safe Attachments docs), MSRC + Microsoft Threat Intelligence (campaign-specific MDO mitigations), CIS M365 v6 §2 (Defender), CISA SCuBA `MS.EXO.*` and `MS.DEFENDER.*`.

## Summary

CheckID has **27 MDO-related checks** spanning the `DEFENDER-*` namespace (anti-phish/-spam/-malware, Safe Links/Attachments, presets, ZAP, priority accounts) and the `EXO-*` namespace (anti-phish/-spam/-malware policies, transport, external-tag). This audit catalogs **31 canonical patterns** across 7 sub-domains (preset adoption, anti-phishing, Safe Attachments, Safe Links, anti-malware, anti-spam, anti-patterns) and maps them against the registry.

**8 coverage gaps** to file as `feat:` issues, **5 narrative-refresh candidates**, **3 namespace-duplication chores** (DEFENDER-* and EXO-* both cover anti-phish/anti-spam/malware policies — likely consolidatable). One **detection-method shift** noted: this is the first audit where detection lives almost entirely in **Exchange Online PowerShell**, not Microsoft Graph. The detection appendix focuses on the EXO-PS contract.

## Existing CheckID inventory (27 MDO-related)

### DEFENDER-* namespace (15 checks)

| CheckId | Severity | Pattern category |
|---|---|---|
| `DEFENDER-ANTIMALWARE-001` | Medium | Common Attachment Types Filter |
| `DEFENDER-ANTIMALWARE-002` | Medium | Internal sender malware notifications |
| `DEFENDER-ANTIPHISH-001` | Medium | Anti-phishing policy presence |
| `DEFENDER-ANTISPAM-001` | Medium | Anti-spam admin notifications |
| `DEFENDER-ANTISPAM-002` | High | Anti-spam allowed-domains anti-pattern |
| `DEFENDER-CFGDETECT-001` | High | Misconfiguration detection (meta) |
| `DEFENDER-CLOUDAPPS-001` | Medium | MDCA enabled (cross-domain to #338) |
| `DEFENDER-MALWARE-002` | Medium | Comprehensive attachment filtering |
| `DEFENDER-OUTBOUND-001` | Medium | Outbound spam message limits |
| `DEFENDER-PRIORITY-001` | Medium | Priority account protection enabled |
| `DEFENDER-PRIORITY-002` | Medium | Priority accounts on Strict preset |
| `DEFENDER-REALTIMESCAN-001` | Critical | Defender Antivirus real-time protection (cross-domain) |
| `DEFENDER-SAFEATTACH-001` | High | Safe Attachments for Email |
| `DEFENDER-SAFEATTACH-002` | Medium | Safe Attachments for SharePoint/OneDrive/Teams |
| `DEFENDER-SAFELINKS-001` | High | Safe Links for Office Applications |
| `DEFENDER-SECUREMON-001` | Medium | Continuous monitoring via Secure Score (meta) |
| `DEFENDER-SECURESCORE-001` | Medium | Secure Score posture (meta) |
| `DEFENDER-VULNSCAN-001` | High | Defender for Endpoint vuln scanning (cross-domain) |
| `DEFENDER-ZAP-001` | Medium | ZAP for Microsoft Teams |

### EXO-* namespace (4 MDO-relevant; transport is handled in #339)

| CheckId | Severity | Pattern category | Note |
|---|---|---|---|
| `EXO-ANTIPHISH-001` | High | Anti-phishing policy config | **Likely overlaps `DEFENDER-ANTIPHISH-001`** |
| `EXO-ANTISPAM-001` | Medium | Anti-spam policy config | **Likely overlaps `DEFENDER-ANTISPAM-001`** |
| `EXO-MALWARE-001` | High | Malware filter policy config | **Likely overlaps `DEFENDER-ANTIMALWARE-001/002`** |
| `EXO-EXTTAG-001` | Low | External-sender identification (mail tip) | Distinct |

The `EXO-* / DEFENDER-*` overlap is a recurring theme — see "Spawned issues" for the consolidation chore.

## 1. Preset policy adoption

### 1.1 Standard preset applied

**Intent:** Microsoft's Standard preset is applied to all users (or specific recipient groups), giving them Microsoft-managed-default protection across anti-phish, anti-spam, anti-malware, Safe Links, Safe Attachments without each policy having to be hand-tuned.
**Detection:** `Get-EOPProtectionPolicyRule` (and `Get-ATPProtectionPolicyRule` for Defender presets) — verify `State = Enabled` AND recipients populated for the Standard preset rule.
**Pitfalls:** Preset policy applied with no recipients is effectively dead. Custom policies with HIGHER priority than the preset will override it for matching recipients.
**Authoritative sources:** Microsoft Learn — Preset security policies; Recommended settings for EOP and Microsoft Defender for Office 365.
**Coverage:** **Gap.** File `feat: DEFENDER-PRESET-STANDARD-001`.

### 1.2 Strict preset applied to high-value users

**Intent:** Strict preset (more aggressive thresholds, stricter actions) applied to executives, finance, IT admins, board members — the population most-targeted by spear phishing.
**Detection:** Strict preset rule `State = Enabled` AND recipients targeting at least the priority-account population.
**Coverage:** ✅ partial via `DEFENDER-PRIORITY-002`. **Narrative refresh recommended** — should explicitly enumerate the populations Strict belongs on.

### 1.3 Built-in protection enabled tenant-wide

**Intent:** Built-in protection (default Safe Links/Attachments rule) is on, providing the floor of protection even for users not in any preset or custom policy.
**Detection:** Built-in protection is default-enabled by Microsoft for all M365 tenants since 2022; verify it hasn't been explicitly disabled. Read via `Get-AtpBuiltInProtectionRule` and check that no `Get-AtpBuiltInProtectionRule` excludes the user population.
**Pitfalls:** A custom rule with `RecipientDomainIs` set to the entire tenant domain effectively shadows built-in for those recipients.
**Coverage:** **Gap.** File `feat: DEFENDER-BUILTIN-PROTECTION-001`.

### 1.4 Configuration analyzer recommendations followed

**Intent:** Microsoft's Configuration analyzer surfaces drift between current policy state and Standard/Strict recommendations. A tenant with persistent drift indicates intentional weakening or neglected tuning.
**Detection:** `Get-ProtectionAlert` and `Get-ConfigAnalyzerPolicyRecommendation` (Security & Compliance PowerShell). Count recommendations not addressed.
**Pitfalls:** Configuration analyzer recommendations include legitimate per-tenant exceptions (e.g., a tenant intentionally raising the bulk threshold for B2B partners). Count alone isn't a verdict.
**Coverage:** **Gap.** File `feat: DEFENDER-CONFIG-ANALYZER-DRIFT-001` (lower priority — needs careful threshold tuning to avoid noise).

## 2. Anti-phishing

### 2.1 Impersonation protection covers protected users

**Intent:** Per-policy `EnableTargetedUserProtection = $true` AND `TargetedUsersToProtect` populated with named executives / high-impact users. Without this, attackers spoofing the CEO bypass impersonation defense.
**Detection:** `Get-AntiPhishPolicy` per-recipient policy: check `EnableTargetedUserProtection` and population of `TargetedUsersToProtect` (display name + email).
**Pitfalls:** Names entered as display name only (no email) match weakly. Policy applied to wrong recipient scope means executives without the policy are unprotected.
**Coverage:** **Gap.** File `feat: DEFENDER-ANTIPHISH-IMPERSONATION-USER-001`.

### 2.2 Impersonation protection covers protected domains

**Intent:** `EnableTargetedDomainsProtection = $true` AND `TargetedDomainsToProtect` populated with own + partner domains. Defends against domain look-alikes.
**Detection:** `Get-AntiPhishPolicy` — `EnableTargetedDomainsProtection` and `TargetedDomainsToProtect`.
**Pitfalls:** Many tenants enable `EnableOrganizationDomainsProtection` (cover own accepted domains automatically) but miss partner domains where a typosquat would be most effective.
**Coverage:** **Gap.** File `feat: DEFENDER-ANTIPHISH-IMPERSONATION-DOMAIN-001`.

### 2.3 Mailbox intelligence enabled

**Intent:** Mailbox intelligence builds a per-mailbox communication graph, so anomalous senders impersonating common contacts get flagged.
**Detection:** `Get-AntiPhishPolicy.EnableMailboxIntelligence = $true` AND `EnableMailboxIntelligenceProtection = $true`.
**Coverage:** **Gap.** File `feat: DEFENDER-ANTIPHISH-MAILBOX-INTEL-001`.

### 2.4 Phishing threshold appropriate per recipient profile

**Intent:** Phishing threshold (1-4 scale; 4 = "most aggressive") set ≥ 3 for most users; 4 for Strict preset / priority accounts. Lower thresholds let more phish through.
**Detection:** `Get-AntiPhishPolicy.PhishThresholdLevel`.
**Coverage:** **Gap.** File `feat: DEFENDER-ANTIPHISH-THRESHOLD-001`.

### 2.5 First contact safety tip enabled

**Intent:** First-contact safety tip warns users when they receive email from a new sender they haven't communicated with before — defends against display-name spoofing of unknown contacts.
**Detection:** `Get-AntiPhishPolicy.EnableFirstContactSafetyTips = $true`.
**Coverage:** **Gap.** File `feat: DEFENDER-ANTIPHISH-FIRST-CONTACT-001`.

### 2.6 Spoof intelligence + safety tips configured

**Intent:** `EnableSpoofIntelligence = $true` (active spoof detection); `EnableUnauthenticatedSender = $true` (?-to-unauthenticated-senders mail tip).
**Detection:** `Get-AntiPhishPolicy` — these two properties.
**Coverage:** ✅ partial via `DEFENDER-ANTIPHISH-001` (presence). **Narrative refresh recommended** — should explicitly enumerate the per-policy properties.

### 2.7 General anti-phish policy presence

**Coverage:** ✅ `DEFENDER-ANTIPHISH-001`, ✅ `EXO-ANTIPHISH-001` — **likely duplicates**, see consolidation chore.

## 3. Safe Attachments

### 3.1 Safe Attachments for Email enabled

**Intent:** All email attachments scanned by Safe Attachments before delivery; appropriate action policy.
**Detection:** `Get-SafeAttachmentPolicy`:
- `Action` ∈ {`Block`, `DynamicDelivery`, `Replace`} (NOT `Allow`)
- Per-policy + rule combination covers the recipient population
**Pitfalls:** `Action = Allow` (deliver attachment without scan completion) defeats Safe Attachments. `Action = MonitorOnly` is a deprecated mode. `DynamicDelivery` is recommended for low-friction UX with full protection.
**Coverage:** ✅ `DEFENDER-SAFEATTACH-001`.

### 3.2 Safe Attachments for SharePoint/OneDrive/Teams

**Intent:** File uploads to SharePoint, OneDrive, and Teams scanned by Safe Attachments.
**Detection:** `Get-AtpPolicyForO365`:
- `EnableATPForSPOTeamsODB = $true`
- `EnableSafeDocs = $true` (for Office desktop client integration)
**Coverage:** ✅ `DEFENDER-SAFEATTACH-002`.

### 3.3 Action delay configured (don't bypass-on-error)

**Intent:** When Safe Attachments scan fails (timeout, sandbox unavailable), the message is still scrubbed — not delivered with the attachment intact.
**Detection:** `Get-SafeAttachmentPolicy.ActionOnError = $true` (deliver scrubbed) NOT `$false` (deliver original).
**Coverage:** **Gap.** File `feat: DEFENDER-SAFEATTACH-ERROR-DELIVERY-001`.

### 3.4 Quarantine policy with end-user notification

**Intent:** Items quarantined by Safe Attachments deliver an end-user notification so users know a message was held.
**Detection:** `Get-SafeAttachmentPolicy.QuarantineTag` references a quarantine policy with notification enabled (`Get-QuarantinePolicy` + `EndUserQuarantinePermissionsValue`).
**Coverage:** **Gap.** File `feat: DEFENDER-SAFEATTACH-QUARANTINE-NOTIFY-001` (low priority).

## 4. Safe Links

### 4.1 Real-time URL scan enabled

**Intent:** URLs in email + Office docs scanned at click time, not just at delivery (defeats post-delivery weaponization where an attacker changes the URL target after the message lands).
**Detection:** `Get-SafeLinksPolicy`:
- `EnableSafeLinksForEmail = $true`
- `ScanUrls = $true`
- `EnableForInternalSenders = $true` (defends against compromised internal accounts)
**Coverage:** ✅ partial via `DEFENDER-SAFELINKS-001`. **Narrative refresh recommended** — explicit per-property enumeration.

### 4.2 Click-through warning enabled

**Intent:** When a malicious URL is detected, the user gets a warning page (not a "click anyway" bypass).
**Detection:** `Get-SafeLinksPolicy`:
- `AllowClickThrough = $false` (NOT `$true`)
- `DoNotAllowClickThrough` correctly set per Strict preset

**Coverage:** **Gap.** File `feat: DEFENDER-SAFELINKS-NO-CLICKTHROUGH-001`.

### 4.3 Safe Links for Office apps + Teams

**Intent:** Safe Links activates inside Word/Excel/PowerPoint/Outlook desktop AND Teams chat URL clicks, not just email.
**Detection:** `Get-SafeLinksPolicy`:
- `EnableSafeLinksForOffice = $true`
- `EnableSafeLinksForTeams = $true`

**Coverage:** ✅ `DEFENDER-SAFELINKS-001` (per name, "Office Applications"). **Narrative refresh** — explicitly include Teams.

### 4.4 Internal URL rewrite enabled

**Intent:** URLs from internal senders are rewritten too — defends against compromised-internal-account phishing campaigns where an attacker uses a takeover'd account to send legitimate-looking URLs internally.
**Detection:** `Get-SafeLinksPolicy.EnableForInternalSenders = $true`.
**Coverage:** **Gap.** File `feat: DEFENDER-SAFELINKS-INTERNAL-001`.

### 4.5 Click tracking enabled

**Intent:** URL clicks tracked + retained (for incident response: who clicked the malicious link before it was blocked).
**Detection:** `Get-SafeLinksPolicy.TrackClicks = $true`.
**Coverage:** **Gap.** File `feat: DEFENDER-SAFELINKS-TRACK-001`.

## 5. Anti-malware

### 5.1 Common attachment types filter populated

**Intent:** Common attachment types filter blocks executable + script extensions tenant-wide (`.exe`, `.js`, `.vbs`, `.lnk`, `.iso`, `.ps1`, etc.).
**Detection:** `Get-MalwareFilterPolicy`:
- `EnableFileFilter = $true`
- `FileTypes` populated with the full standard list (Microsoft maintains a recommended list)
**Coverage:** ✅ `DEFENDER-ANTIMALWARE-001`. **Narrative refresh recommended** — should explicitly call out `.iso` and `.lnk` as 2024-era favorites for malware delivery.

### 5.2 Zero-hour Auto Purge (ZAP) enabled

**Intent:** ZAP retroactively removes messages from mailboxes when they're determined malicious *after* delivery.
**Detection:** Per-policy: `ZapEnabled = $true` (anti-spam policy property), and Teams ZAP via `Get-TeamsClientConfiguration` or related.
**Pitfalls:** Three ZAP variants: malware ZAP, phish ZAP, spam ZAP — verify all enabled. Teams ZAP is separate from email.
**Coverage:** ✅ partial via `DEFENDER-ZAP-001` (Teams ZAP). **Gap on email-side ZAP coverage** — file `feat: DEFENDER-ZAP-EMAIL-001`.

### 5.3 Quarantine policies + end-user notifications

**Intent:** Malicious + phish + spam quarantines deliver end-user notifications so users know messages were held; admin notifications for the highest-confidence detections.
**Detection:** `Get-QuarantinePolicy` + per-protection-policy `QuarantineTag` references.
**Coverage:** Folds into 3.4 + admin-side coverage.

### 5.4 Internal sender notifications on detected malware (admins alerted)

**Intent:** When a detected outbound malware message originates from an internal sender (likely compromised account), admins are alerted.
**Detection:** `Get-MalwareFilterPolicy.EnableInternalSenderAdminNotifications = $true`, `InternalSenderAdminAddress` populated.
**Coverage:** ✅ `DEFENDER-ANTIMALWARE-002`.

## 6. Anti-spam

### 6.1 Connection filter not relying on IP allow list

**Intent:** Connection filter IP allow list (`Get-HostedConnectionFilterPolicy.IPAllowList`) bypasses spam filtering entirely for listed IPs. A populated allow list with broad ranges (entire /24 or /16) defeats spam protection for those senders.
**Detection:** Threshold check — flag if `IPAllowList.Count > 5` OR if any entry is a /24-or-broader subnet.
**Coverage:** **Gap.** File `feat: DEFENDER-ANTISPAM-IP-ALLOWLIST-001`.

### 6.2 Outbound spam policy with per-user limits

**Intent:** Outbound spam policy limits per-user external recipients per hour / day. Without limits, a compromised account can send to thousands before being throttled, contaminating tenant outbound reputation.
**Detection:** `Get-HostedOutboundSpamFilterPolicy`:
- `RecipientLimitExternalPerHour` ≤ 500 (default 1000)
- `RecipientLimitInternalPerHour` ≤ 1000
- `RecipientLimitPerDay` ≤ 1000

**Coverage:** ✅ `DEFENDER-OUTBOUND-001`. **Narrative refresh recommended** — explicit threshold values + the "compromised account → tenant reputation hit" framing.

### 6.3 High Confidence Phish action = Quarantine

**Intent:** When MDO detects high-confidence phish, the message is quarantined (not delivered to Junk folder where users can still preview / click).
**Detection:** `Get-HostedContentFilterPolicy.HighConfidencePhishAction = "Quarantine"` (NOT `MoveToJmf`).
**Coverage:** **Gap.** File `feat: DEFENDER-ANTISPAM-HCPHISH-QUARANTINE-001`.

### 6.4 Bulk complaint level (BCL) thresholds

**Intent:** Bulk Complaint Level threshold set per recipient profile. Default is 7 (allow most bulk); Strict preset is 4 (more aggressive). Tenants should match preset thresholds to user expectations.
**Detection:** `Get-HostedContentFilterPolicy.BulkThreshold`.
**Coverage:** **Gap.** File `feat: DEFENDER-ANTISPAM-BCL-001` (low priority).

### 6.5 Anti-spam admin notifications

**Intent:** Per-policy admin notifications when high-volume / high-severity spam detected.
**Coverage:** ✅ `DEFENDER-ANTISPAM-001`.

### 6.6 Allowed-domains anti-pattern

**Intent:** Anti-spam policy allowed-domains list shouldn't be populated with broad allow lists that bypass spam filtering for entire partner domains.
**Coverage:** ✅ `DEFENDER-ANTISPAM-002`.

## 7. Anti-patterns (deliberate detection)

### 7.1 Custom policy overriding preset for "exceptions" that's actually weaker

**Intent:** Custom anti-phish/spam/malware/SafeLinks/SafeAttachments policy with HIGHER priority than the Standard/Strict preset, applying weaker settings to its recipient scope.
**Detection:** Per-policy compare effective settings against preset baseline; flag custom policies with priority < preset rule priority that have weaker thresholds.
**Pitfalls:** Some custom policies legitimately tune stricter (e.g., Strict applied to executives). Detection should distinguish "custom is stricter" (good) from "custom is weaker" (anti-pattern).
**Coverage:** **Gap.** File `feat: DEFENDER-CUSTOM-WEAKER-001`.

### 7.2 "Allow recipient to click through warning" enabled for executives

**Intent:** Executives shouldn't have click-through-warning bypass on Safe Links — they're the highest-impact spear phishing target.
**Coverage:** Folds into 4.2 `DEFENDER-SAFELINKS-NO-CLICKTHROUGH-001` (executives are the primary case).

### 7.3 Outbound spam limit at default (10000/day)

**Intent:** Default values can't catch botnet-driven outbound spam from a compromised account.
**Coverage:** Folds into 6.2 narrative refresh.

### 7.4 Connection filter IP allow list with broad ranges

**Coverage:** Folds into 6.1.

### 7.5 Safe Attachments policy missing for SharePoint/OneDrive

**Intent:** Tenant has email Safe Attachments but missed enabling for SPO/OD/Teams (file-share infection vector).
**Coverage:** ✅ `DEFENDER-SAFEATTACH-002` already covers.

### 7.6 Safe Links action = "Allow click through"

**Coverage:** Folds into 4.2.

### 7.7 ZAP disabled

**Coverage:** Folds into 5.2.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| Preset adoption | 4 | 1 partial | 1 (1.2) | 3 (1.1, 1.3, 1.4) |
| Anti-phishing | 7 | 2 partial | 1 (2.6) | 5 (2.1, 2.2, 2.3, 2.4, 2.5); 2.7 dedup |
| Safe Attachments | 4 | 2 | 0 | 2 (3.3, 3.4 low-pri) |
| Safe Links | 5 | 1 partial | 2 (4.1, 4.3) | 3 (4.2, 4.4, 4.5) |
| Anti-malware | 4 | 2 | 1 (5.1) | 1 (5.2 email-ZAP) |
| Anti-spam | 6 | 3 | 1 (6.2) | 3 (6.1, 6.3, 6.4 low-pri) |
| Anti-patterns | 7 | 0 | 0 | 1 unique (7.1); others fold |
| **Total** | **37 patterns; 31 unique after folds** | **11** | **5** | **18 — 8 dedup folds = 10 net gaps** |

(Net of folds: ~18 distinct patterns surfaced as gaps; 8 of those collapse to existing CheckIDs via consolidation. Net new CheckIDs to file: ~10.)

## Threat-pattern map

| Compromise pattern | Tradecraft | Primary control |
|---|---|---|
| Spear phishing of executives | Display-name impersonation, look-alike domain | Targeted user/domain protection (2.1, 2.2) + mailbox intelligence (2.3) |
| Post-delivery URL weaponization | Attacker sets benign URL at send, swaps target after delivery | Real-time scan at click (4.1) + click-through warning (4.2) |
| Compromised internal sender | Internal-to-internal phish from takeover'd account | Internal URL rewrite (4.4) + ZAP (5.2) |
| Outbound spam from compromised account → tenant reputation hit | Botnet driving high-volume external sends | Outbound spam per-user limits (6.2) |
| Malware delivery via .iso / .lnk / script files | Modern file-format pivots from .docx macros | Common attachment types filter (5.1) |
| Bypass via "exception" policy | Custom policy with broader reach + weaker settings | Custom-weaker-than-preset detection (7.1) |
| MFA fatigue / push bombing of email-tied admin | (handled by #330 + #329) | Cross-spike |
| Quishing (QR-code phishing in email) | URL embedded in QR image bypasses URL scanner | (Out of scope — Microsoft enabled QR detection in built-in protection 2024+; verify with built-in protection coverage 1.3) |

## Detection method appendix

### Primary surface: Exchange Online + Security & Compliance PowerShell

This audit's detection contract is **almost entirely Exchange Online PowerShell** (and S&C PowerShell for some preset cmdlets). Microsoft Graph does not currently expose MDO policies in their full form. Consumers reading the registry need to know they're dispatching to PowerShell, not Graph.

| Cmdlet | Used for |
|---|---|
| `Get-EOPProtectionPolicyRule` | Standard / Strict preset rules (state, recipients, priority) |
| `Get-ATPProtectionPolicyRule` | Defender-tier preset rules (Safe Links/Attachments preset states) |
| `Get-AtpBuiltInProtectionRule` | Built-in protection rule (default-on Safe Links/Attachments) |
| `Get-AntiPhishPolicy` / `Get-AntiPhishRule` | Per-policy anti-phish settings + rule scoping |
| `Get-MalwareFilterPolicy` / `Get-MalwareFilterRule` | Anti-malware policy + scoping |
| `Get-HostedContentFilterPolicy` / `Get-HostedContentFilterRule` | Anti-spam (inbound) policy + scoping |
| `Get-HostedConnectionFilterPolicy` | Connection filter (IP allow/block list) |
| `Get-HostedOutboundSpamFilterPolicy` / `Get-HostedOutboundSpamFilterRule` | Outbound spam policy + scoping |
| `Get-SafeLinksPolicy` / `Get-SafeLinksRule` | Safe Links policy + scoping |
| `Get-SafeAttachmentPolicy` / `Get-SafeAttachmentRule` | Safe Attachments (email) policy + scoping |
| `Get-AtpPolicyForO365` | Safe Attachments for SharePoint/OneDrive/Teams (separate from email) |
| `Get-QuarantinePolicy` | Quarantine policies referenced by per-protection policy QuarantineTag |
| `Get-ProtectionAlert` | Protection alert configuration (Configuration Analyzer territory) |
| `Get-ConfigAnalyzerPolicyRecommendation` (S&C PS) | Drift recommendations vs Standard/Strict |

### Edge cases

1. **Policy + rule pair contract.** Almost every MDO policy type has TWO cmdlets: `Get-XPolicy` (the settings) + `Get-XRule` (the recipient scoping). Effective protection requires both populated AND linked. A policy with no rule applies to nobody.

2. **Effective-policy-per-user evaluation.** Multiple policies of the same type (Default + Custom1 + Custom2…) — must evaluate effective policy per user via rule priority + recipient match. Highest-priority matching rule wins. This is conceptually identical to CA effective-policy reasoning (#327).

3. **Preset policies vs custom.** Preset policies appear in `Get-EOPProtectionPolicyRule` and `Get-ATPProtectionPolicyRule` separately from custom policies. Preset settings are MS-managed (read-only); custom policies appear in the per-feature cmdlets. Need to reconcile both surfaces to compute effective state.

4. **"Recipients" scoping.** A policy with no recipients applied is effectively dead. Detection should flag policies with empty recipient sets.

5. **Microsoft-managed Built-in protection.** `Get-AtpBuiltInProtectionRule` returns Microsoft-managed defaults. Some properties don't exist until set; verify via Configuration Analyzer rather than only the Get-* cmdlets.

6. **Authentication context for cmdlets.** Different cmdlets require different roles. `Get-AntiPhishPolicy` requires Exchange Online admin or Security Admin; `Get-ProtectionAlert` requires Compliance Admin. Detection should fail gracefully when the calling identity lacks permissions for some surface.

7. **Quarantine policy `EndUserQuarantinePermissionsValue` is a bit-flag.** Reading specific quarantine permissions (release, request release, delete, preview) requires bit-mask interpretation, not enum.

8. **`Action` enum on Safe Attachments.** `Block` (drop attachment), `Replace` (replace with notification), `DynamicDelivery` (deliver body, attach when scan completes), `Allow` (deliver as-is — anti-pattern). Verify for the action choice + per-recipient-group scope.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 10 net):**

1. `feat: DEFENDER-PRESET-STANDARD-001` — Standard preset applied (1.1)
2. `feat: DEFENDER-BUILTIN-PROTECTION-001` — Built-in protection not shadowed (1.3)
3. `feat: DEFENDER-CONFIG-ANALYZER-DRIFT-001` — Configuration Analyzer drift (1.4) — *low priority*
4. `feat: DEFENDER-ANTIPHISH-IMPERSONATION-USER-001` — targeted-user impersonation list (2.1)
5. `feat: DEFENDER-ANTIPHISH-IMPERSONATION-DOMAIN-001` — targeted-domain impersonation list (2.2)
6. `feat: DEFENDER-ANTIPHISH-MAILBOX-INTEL-001` — mailbox intelligence (2.3)
7. `feat: DEFENDER-ANTIPHISH-THRESHOLD-001` — phishing threshold per profile (2.4)
8. `feat: DEFENDER-ANTIPHISH-FIRST-CONTACT-001` — first-contact safety tip (2.5)
9. `feat: DEFENDER-SAFEATTACH-ERROR-DELIVERY-001` — ActionOnError = $true (3.3)
10. `feat: DEFENDER-SAFEATTACH-QUARANTINE-NOTIFY-001` — quarantine notification (3.4) — *low priority*
11. `feat: DEFENDER-SAFELINKS-NO-CLICKTHROUGH-001` — click-through disabled (4.2)
12. `feat: DEFENDER-SAFELINKS-INTERNAL-001` — internal URL rewrite (4.4)
13. `feat: DEFENDER-SAFELINKS-TRACK-001` — click tracking (4.5)
14. `feat: DEFENDER-ZAP-EMAIL-001` — email-side ZAP (5.2)
15. `feat: DEFENDER-ANTISPAM-IP-ALLOWLIST-001` — connection filter allowlist breadth (6.1)
16. `feat: DEFENDER-ANTISPAM-HCPHISH-QUARANTINE-001` — high-confidence phish action (6.3)
17. `feat: DEFENDER-ANTISPAM-BCL-001` — BCL threshold (6.4) — *low priority*
18. `feat: DEFENDER-CUSTOM-WEAKER-001` — custom policy weaker than preset (7.1)

(That's 18 net feat issues. Higher-than-typical because MDO has many discrete per-property gaps.)

**Namespace consolidation chores (3):**

- `chore: reconcile DEFENDER-ANTIPHISH-001 ↔ EXO-ANTIPHISH-001` — likely duplicates; pick one namespace
- `chore: reconcile DEFENDER-ANTISPAM-001 ↔ EXO-ANTISPAM-001` — same
- `chore: reconcile DEFENDER-ANTIMALWARE-001 ↔ EXO-MALWARE-001` — same

**Narrative refresh (`chore:` issues, 5):**

- `chore: refresh DEFENDER-PRIORITY-002 narrative` — enumerate the populations Strict belongs on (executives, finance, IT admins, board members)
- `chore: refresh DEFENDER-ANTIPHISH-001 narrative` — explicit per-property enumeration (mailbox intelligence, spoof intelligence, first-contact tip)
- `chore: refresh DEFENDER-SAFELINKS-001 narrative` — include Teams + per-property enumeration
- `chore: refresh DEFENDER-ANTIMALWARE-001 narrative` — call out 2024-era favorites (.iso, .lnk)
- `chore: refresh DEFENDER-OUTBOUND-001 narrative` — explicit thresholds + reputation-hit framing

## Out of scope (handled by sibling spikes)

- Defender for Endpoint (separate product) — not M365 config audit scope
- Defender for Cloud Apps — #338 (MDCA spike); `DEFENDER-CLOUDAPPS-001` belongs there
- Defender Antivirus real-time — `DEFENDER-REALTIMESCAN-001` is endpoint scope
- Mail flow rules / transport rules — #339
- Microsoft Teams external access (separate from MDO Teams ZAP) — #340
- Defender Vulnerability Management — `DEFENDER-VULNSCAN-001` is endpoint scope
