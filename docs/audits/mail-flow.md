# Mail Flow — Domain Audit (v3.4.0)

**Status:** Tenth domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#339](https://github.com/Galvnyz/CheckID/issues/339).
**Source priorities:** Microsoft Learn primary (Mail flow rules in Exchange Online, Connectors in Exchange Online, Configure email forwarding, Outbound spam policy and auto-forwarding control), Microsoft DART blog (incident response patterns featuring transport rule + inbox rule persistence), MSRC (mailbox compromise tradecraft — Storm-X actors using inbox rules), CIS M365 v6 §6 (Exchange Online), CISA SCuBA `MS.EXO.*`.

## Summary

CheckID has **9 mail-flow-related checks** across the `EXO-*` (transport, forwarding, direct-send, SMTP AUTH) and `DNS-*` (SPF, DKIM, DMARC) namespaces. This audit catalogs **27 canonical patterns** across 5 sub-domains (transport rule hygiene, connector posture, accepted + remote domains, mailbox-level forwarding controls, anti-patterns) and maps them against the registry.

**12 coverage gaps** to file as `feat:` issues, **3 narrative-refresh candidates**, and one notable **cross-cutting** finding: the **three-surface auto-forwarding problem** — auto-forwarding to external is governed independently by Remote Domain default `AutoForwardEnabled`, outbound spam policy `AutoForwardingMode`, and per-mailbox `DeliverToMailboxAndForward`. All three must align for "external auto-forwarding blocked" to be effective. CheckID's existing `EXO-FORWARD-001` covers part of this; the gap analysis enumerates each surface.

This audit completes the **Exchange Online posture** triad alongside #332 (MDO content protection) and the upcoming #338 (Defender for Cloud Apps for OAuth governance overlay).

## Existing CheckID inventory (mail-flow scope, 9 checks)

| CheckId | Severity | Pattern category |
|---|---|---|
| `EXO-TRANSPORT-001` | Medium | Transport rule whitelist anti-pattern |
| `EXO-TRANSPORT-002` | High | Transport rule configuration for external forwarding |
| `EXO-FORWARD-001` | High | All forms of mail forwarding blocked |
| `EXO-DIRECTSEND-001` | High | Direct Send not allowed for unauthorized relay |
| `EXO-AUTH-002` | (Medium) | SMTP AUTH disabled (legacy mail auth) |
| `DNS-SPF-001` | High | SPF records published for all EXO domains |
| `DNS-DKIM-001` | Low | DKIM enabled for all EXO domains |
| `DNS-DMARC-001` | High | DMARC records published for all EXO domains |
| `EXO-EXTTAG-001` | Low | External-sender mail tip / identifier |

## 1. Transport rule hygiene

### 1.1 Total transport rule count (drift indicator)

**Intent:** Tenants accumulate transport rules over time without removing stale ones. A baseline rule count + recency review surfaces drift. Most healthy tenants have ≤30 active rules.
**Detection:** `Get-TransportRule | Measure-Object | Select-Object Count` — flag tenants with > 50 rules for review.
**Pitfalls:** Some legitimate large tenants have hundreds of rules for compliance / regulatory mailflow. Threshold is heuristic, not absolute.
**Coverage:** **Gap (low priority).** File `feat: EXO-TRANSPORT-COUNT-001`.

### 1.2 Rules with header-rewriting actions reviewed

**Intent:** Transport rules that rewrite headers (`SetHeaderName`, `SetHeaderValue`) are inventoried. Most legitimate; some are exfil-flavored (rewriting From: header to spoof identity).
**Detection:** `Get-TransportRule | Where-Object { $_.Actions -match 'SetHeaderName' -or $_.SetHeaderName }` — enumerate, flag for review.
**Authoritative sources:** Microsoft Learn — Mail flow rule actions reference.
**Coverage:** **Gap.** File `feat: EXO-TRANSPORT-HEADER-REWRITE-001`.

### 1.3 Rules bypassing spam / Safe Attachments / Safe Links

**Intent:** Rules that explicitly bypass spam, Safe Links, or Safe Attachments (`SetAuditSeverity`, `SetSCL = -1`, `StopRuleProcessing` paired with bypass) are inventoried. Bypasses justified scope only — broad bypass defeats MDO.
**Detection:** `Get-TransportRule | Where-Object { $_.SetSCL -eq -1 -or $_.SetMessageHeader -match 'BypassFiltering' }` — enumerate scope.
**Coverage:** **Gap.** File `feat: EXO-TRANSPORT-BYPASS-FILTER-001`.

### 1.4 Rules forwarding mail externally

**Intent:** Transport rules that explicitly forward mail to external addresses (`AddManagerAsRecipientType`, `BlindCopyTo`, `RedirectMessageTo` with external) are extreme exfil risk if the destination is unauthorized.
**Detection:** `Get-TransportRule | Where-Object { $_.RedirectMessageTo -or $_.BlindCopyTo -or $_.AddBccBox }` — enumerate destinations; verify each is internal OR documented external (e.g., compliance archiving partner).
**Pitfalls:** Some legitimate scenarios (compliance archiving, security forensic copying). Detection should call out the population, not auto-fail.
**Coverage:** ✅ partial via `EXO-TRANSPORT-002`. **Narrative refresh recommended** — explicit destination-validation framing.

### 1.5 Rules redirecting mail to a single mailbox (potential exfil pattern)

**Intent:** A rule that routes mail to a single (often internal-but-attacker-controlled) mailbox can be a data exfil pattern. Detection focuses on the volume + scope.
**Detection:** Enumerate rules with single-recipient redirection where the recipient isn't a known compliance / legal address.
**Coverage:** Folds into 1.4.

### 1.6 Disabled rules persisting in tenant

**Intent:** Disabled (`State = Disabled`) rules persisting in tenant indicate forgotten cleanup or "re-enable later" intent. Most should be deleted.
**Detection:** `Get-TransportRule | Where-Object { $_.State -eq 'Disabled' }` — flag for review.
**Coverage:** **Gap (low priority).** File `feat: EXO-TRANSPORT-DISABLED-001`.

### 1.7 Rule priority / ordering

**Intent:** Transport rules execute in priority order (0 = highest). Stop-on-match rules at lower priority can mask higher-priority security rules. Detection inventories rule order + flags potential masking.
**Detection:** `Get-TransportRule | Sort-Object Priority | Select-Object Priority, Name, StopRuleProcessing` — annotate.
**Pitfalls:** Detection of "masking" requires comparing rule conditions to determine which rules apply to overlapping populations. Heuristic, not deterministic.
**Coverage:** **Gap (low priority).** File `feat: EXO-TRANSPORT-PRIORITY-001`.

### 1.8 Domain whitelist anti-pattern

**Intent:** Transport rules that whitelist domains (`SenderDomainIs`, `RecipientDomainIs`) for spam-bypass should be reviewed for breadth.
**Coverage:** ✅ `EXO-TRANSPORT-001`.

## 2. Connector posture

### 2.1 Inbound connector posture

**Intent:** Inbound connectors are authenticated (TLS-required, certificate or IP-based) — not "open to all."
**Detection:** `Get-InboundConnector`:
- `RestrictDomainsToCertificate = $true` OR `RestrictDomainsToIPAddresses = $true`
- `RequireTLS = $true`
- Per-connector destination domains configured

**Authoritative sources:** Microsoft Learn — Configure mail flow with custom inbound connectors.
**Coverage:** **Gap.** File `feat: EXO-CONNECTOR-INBOUND-001`.

### 2.2 Outbound connector with restricted scope

**Intent:** Outbound connectors restricted to specific recipient domains (the partner you intend to send to), not "all."
**Detection:** `Get-OutboundConnector`:
- Recipients block populated (specific domains)
- `RouteAllMessagesViaOnPremises` reviewed (legacy)

**Coverage:** **Gap.** File `feat: EXO-CONNECTOR-OUTBOUND-001`.

### 2.3 Partner connectors (B2B mail flow)

**Intent:** Partner connectors verified per-partner; cert + TLS validated. Stale connectors removed.
**Coverage:** Folds into 2.1 + 2.2.

### 2.4 Hybrid coexistence connectors (Exchange on-prem)

**Intent:** Hybrid connectors match documented topology. Outdated hybrid wizard runs may leave stale connectors.
**Detection:** Identify connectors with `ConnectorType = OnPremises` and verify they match expected hybrid configuration.
**Coverage:** **Gap (low priority — most tenants are cloud-only).** File `feat: EXO-CONNECTOR-HYBRID-001`.

### 2.5 Stale / unused connectors removed

**Intent:** Connectors with `Enabled = $false` for >90 days OR `WhenCreated` >2 years ago without recent message delivery indicate stale config.
**Detection:** Per-connector recency check.
**Coverage:** **Gap (low priority).** File `feat: EXO-CONNECTOR-STALE-001`.

## 3. Accepted + remote domains

### 3.1 Accepted domains (authoritative vs internal-relay)

**Intent:** Accepted domains have correct `DomainType`:
- `Authoritative` for domains your tenant fully owns
- `InternalRelay` for hybrid scenarios where mail flows to on-prem
- `ExternalRelay` for mail-relay-to-external scenarios (rare)

Mismatched types cause silent mail loss or unexpected loopback.
**Detection:** `Get-AcceptedDomain | Select-Object DomainName, DomainType, AuthenticationType`.
**Coverage:** **Gap.** File `feat: EXO-ACCEPTED-DOMAIN-TYPE-001`.

### 3.2 No "shadow" accepted domains

**Intent:** Orphaned accepted domains from divested business units OR test domains left behind. Each is a potential mail-misdelivery surface.
**Detection:** Compare `Get-AcceptedDomain` against documented domain inventory.
**Pitfalls:** Detection requires curator-supplied authoritative domain list.
**Coverage:** **Out of scope** — too org-specific without curator input.

### 3.3 Remote domain settings

**Intent:** Remote domain default has `AutoForwardEnabled = $false` (block external auto-forward by default). Per-domain remote settings (e.g., for partner email) reviewed.
**Detection:** `Get-RemoteDomain Default.AutoForwardEnabled = $false` AND per-domain remote settings reviewed.
**Coverage:** ✅ partial via `EXO-FORWARD-001` (general forward block). **Narrative refresh recommended** — explicit Remote Domain framing as part of the three-surface auto-forwarding problem.

### 3.4 DNS posture: SPF, DKIM, DMARC

**Intent:** Every accepted domain has SPF + DKIM + DMARC published. SPF lists authorized senders; DKIM signs outbound; DMARC instructs receivers what to do with failures.
**Detection:** Per-domain DNS lookup + record validation.
**Coverage:** ✅ `DNS-SPF-001`, ✅ `DNS-DKIM-001`, ✅ `DNS-DMARC-001`. **Note:** `DNS-DKIM-001` is `Low` severity but DKIM is foundational for DMARC alignment — narrative refresh recommended.

## 4. Mailbox-level forwarding controls (the three-surface problem)

The central reconciliation in this audit. **Auto-forwarding to external is governed by THREE INDEPENDENT surfaces.** All three must align for blocking to be effective.

### 4.1 Tenant-wide block via Remote Domain

**Intent:** `Get-RemoteDomain Default.AutoForwardEnabled = $false`.
**Coverage:** Folds into 3.3.

### 4.2 Outbound spam policy `AutoForwardingMode`

**Intent:** `Get-HostedOutboundSpamFilterPolicy.AutoForwardingMode = 'Off'`.
**Pitfalls:** This is independent of Remote Domain — both must be set. Tenants frequently get one and miss the other.
**Coverage:** Folds into ✅ `EXO-FORWARD-001`. **Narrative refresh strongly recommended** — call out the three-surface alignment requirement.

### 4.3 Per-mailbox forwarding addresses inventoried

**Intent:** Even with tenant blocks, individual mailboxes can have `ForwardingAddress` or `ForwardingSmtpAddress` set (admin-configured). These need inventory + review.
**Detection:** `Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress }`.
**Coverage:** **Gap.** File `feat: EXO-MAILBOX-FORWARDING-INVENTORY-001`.

### 4.4 Inbox rule audit (server-side persistence detection)

**Intent:** Inbox rules with forwarding actions, redirection, or auto-deletion are documented mailbox-compromise persistence patterns. Hidden rules (with non-printable / unicode names) are advanced persistence per Microsoft DART.
**Detection:** `Get-InboxRule -Mailbox <upn>` per high-risk mailbox (executive, finance, IT admin). Iterate; flag rules with:
- `ForwardTo` or `RedirectTo` to external
- `DeleteMessage = $true`
- Names with non-printable characters (whitespace-only, unicode invisible)

**Pitfalls:** Per-mailbox iteration doesn't scale tenant-wide for >10K mailbox tenants. Sample-based or risk-based scoping needed (executives, recently-changed-password accounts, high-value targets).
**Authoritative sources:** Microsoft DART blog — incident response patterns; MITRE ATT&CK T1564.008 (Hidden Files: Email Hiding Rules), T1114 (Email Collection).
**Threats defeated:** Hidden inbox rule persistence (Storm-X actor playbooks); compromised account exfiltration via auto-forward; account takeover audit-trail evasion.
**Coverage:** **Gap.** File `feat: EXO-INBOX-RULE-AUDIT-001`.

### 4.5 Tenant-level forwarding controls (`Get-OrganizationConfig`)

**Intent:** `MailTipsExternalRecipientsTipsEnabled = $true` (warns when sending external) — pairs with auto-forward blocks for end-user awareness.
**Detection:** `Get-OrganizationConfig.MailTipsExternalRecipientsTipsEnabled`.
**Coverage:** ✅ `EXO-MAILTIPS-001` (already in `EXO-*` namespace; slightly tangential here).

## 5. Anti-patterns (deliberate detection)

### 5.1 Connector with `RestrictDomainsToCertificate: false` + `RestrictDomainsToIPAddresses: false`

**Intent:** This combination = open relay. Any sender can use the connector, breaking trust + flooding inbox spam.
**Coverage:** Folds into 2.1 `EXO-CONNECTOR-INBOUND-001`.

### 5.2 Forwarding-to-external transport rule covering broad recipient scope

**Intent:** A transport rule with `RedirectMessageTo` / `BlindCopyTo` external + recipient scope = entire tenant or large user group = mass exfil.
**Coverage:** Folds into 1.4 narrative.

### 5.3 Auto-forwarding allowed via Remote Domain `AutoForwardEnabled: true` AND outbound spam `AutoForwardingMode: On`

**Intent:** Both surfaces permissive = external forwarding fully enabled, regardless of #325 §3.6.1 compliance posture.
**Coverage:** Folds into 4.1 + 4.2 (`EXO-FORWARD-001` covers).

### 5.4 "ByPassSpamFiltering" rules covering broad sender lists

**Coverage:** Folds into 1.3.

### 5.5 Hidden inbox rules using non-printable characters in name

**Intent:** Server-side persistence pattern documented by Microsoft DART. Hidden inbox rule (whitespace-only or unicode-invisible name) created post-account-compromise to exfiltrate or delete messages.
**Coverage:** Folds into 4.4.

### 5.6 Connector legacy "On-Premises" type without modern certificate-based auth

**Coverage:** Folds into 2.4.

### 5.7 SMTP AUTH enabled tenant-wide

**Intent:** Tenant-wide SMTP AUTH (basic auth for SMTP) is legacy and exploitable for password spray. Modern path: disabled tenant-wide; enable per-mailbox only as exception.
**Detection:** `Get-TransportConfig.SmtpClientAuthenticationDisabled = $true`. Per-mailbox: `Get-CASMailbox -Identity <upn> | Select SmtpClientAuthenticationDisabled`.
**Coverage:** ✅ `EXO-AUTH-002`.

### 5.8 Direct Send relay accessible

**Intent:** Direct Send is the SMTP relay path that doesn't require auth — for legitimate scanner/copier email-to-mailbox scenarios. Anti-pattern when accessible from public internet without restriction.
**Coverage:** ✅ `EXO-DIRECTSEND-001`.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| Transport rule hygiene | 8 | 1 partial | 1 (1.4) | 5 (1.1, 1.2, 1.3, 1.6, 1.7); 1.5 folds |
| Connector posture | 5 | 0 | 0 | 4 (2.1, 2.2, 2.4 low-pri, 2.5 low-pri); 2.3 folds |
| Accepted + remote domains | 4 | 3 partial | 2 (3.3, 3.4 DKIM severity) | 1 (3.1); 3.2 out-of-scope |
| Mailbox-level forwarding | 5 | 2 (4.5) + folds | 1 (4.2) | 2 (4.3, 4.4) |
| Anti-patterns | 8 | 2 | 0 | 0 unique (all fold) |
| **Total** | **30 (27 unique after folds)** | **6** | **3** | **12 net to file** |

## Threat-pattern map

| Compromise pattern | Tradecraft | Primary control |
|---|---|---|
| Server-side mailbox persistence (hidden inbox rule) | Storm-X actor playbooks; MITRE T1564.008 | Inbox rule audit per high-risk mailbox (4.4) |
| Mass external auto-forwarding from compromised account | Compromised user → set forwardingAddress to attacker | Three-surface auto-forwarding alignment (3.3, 4.2, 4.3) + per-mailbox inventory |
| Open mail relay via misconfigured connector | Inbound connector without TLS / cert / IP restrictions | Connector posture review (2.1, 5.1) |
| Header rewriting for spoof identity | Transport rule with `SetHeaderName` rewriting From: | Header-rewrite rule audit (1.2) |
| Spam/MDO bypass via transport rule | `SetSCL = -1`, `BypassFiltering` headers | Bypass-filter rule audit (1.3) |
| SMTP AUTH password spray | Legacy SMTP basic auth credential spray | SMTP AUTH disabled tenant-wide (5.7) |
| Direct Send abuse | Anonymous SMTP relay through tenant | Direct Send restriction (5.8) |
| DMARC failure exfil → spoofed sender exploitation | No DMARC published; receivers don't reject spoof | DNS DMARC published + DKIM aligned (3.4) |
| Stale accepted domain mail loss | Old domain still accepting mail nobody monitors | Accepted domain inventory (3.1, 3.2) |
| Compromised mailbox audit trail erasure | Inbox rule deleting messages or moving to deleted-items + auto-purge | Inbox rule audit (4.4) + mailbox audit logging (`EXO-AUDIT-*`) |

## Detection method appendix

### Primary: Exchange Online PowerShell

| Cmdlet | Used for |
|---|---|
| `Get-TransportRule` | Transport rule inventory + state + actions (1.x) |
| `Get-InboundConnector` / `Get-OutboundConnector` | Connector posture (2.x) |
| `Get-AcceptedDomain` | Accepted domains + types (3.1) |
| `Get-RemoteDomain` | Remote domain + auto-forward defaults (3.3, 4.1) |
| `Get-HostedOutboundSpamFilterPolicy` | Outbound spam + auto-forwarding mode (4.2) |
| `Get-Mailbox` (with filter) | Per-mailbox forwarding addresses (4.3) |
| `Get-InboxRule` | Per-mailbox inbox rules (4.4) |
| `Get-OrganizationConfig` | Tenant-level forwarding controls + MailTips (4.5) |
| `Get-TransportConfig` | SMTP AUTH state (5.7) |
| `Get-CASMailbox` | Per-mailbox SMTP AUTH state |
| `Get-MessageTrace` | Runtime message-flow analytics (out of static config scope) |

### Edge cases

1. **Transport rule action enum is large.** ~50 actions including `SetSCL`, `RedirectMessageTo`, `BlindCopyTo`, `SetHeaderName`, `StopRuleProcessing`, etc. Per-action classification (benign / suspicious / hostile) needs a curated reference table — propose `data/transport-rule-actions.json` for tenant-side use.

2. **Per-mailbox iteration doesn't scale.** Tenants with 10K+ mailboxes can't iterate `Get-InboxRule` against every one. Sample-based (executives, finance, IT admin, recently-changed-password) or risk-based scoping required.

3. **Hidden inbox rules with whitespace / unicode names.** Special string handling required; can't rely on `Where-Object Name -like '*'` alone. Detection should explicitly check for non-printable characters.

4. **Auto-forwarding three-surface state.** All three surfaces (Remote Domain `AutoForwardEnabled`, outbound spam `AutoForwardingMode`, per-mailbox `DeliverToMailboxAndForward`) must be checked. Stop-checking-after-one is the most common bug in detection logic.

5. **Stale connectors that are "Disabled" but not removed.** `Enabled = $false` connector still in inventory but not delivering mail — appears in audit but doesn't cause harm. Detection should distinguish "Disabled-AND-stale" (cleanup candidate) from "Disabled-temporarily" (operational pause).

6. **Accepted domain `DomainType` enum subtleties.** `Authoritative` vs `InternalRelay` vs `ExternalRelay` — wrong type causes silent mail loss. Detection should match expected type to documented topology.

7. **Audit log retention for inbox rule changes.** Inbox rule create/modify/delete events surface via `Search-UnifiedAuditLog -Operations 'New-InboxRule', 'Set-InboxRule', 'Remove-InboxRule'`. Retention default 90 days (P1) or 365+ days (P2). Long-window analysis requires workspace export.

8. **DKIM severity reflects defense-in-depth value.** DNS-DKIM-001 is `Low` in the registry but DKIM is foundational for DMARC alignment. Without DKIM, DMARC `policy=reject` doesn't fire on spoof attempts. The severity probably warrants `Medium` reassessment.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 12 net):**

1. `feat: EXO-TRANSPORT-COUNT-001` — total transport rule count drift indicator (1.1) — *low priority*
2. `feat: EXO-TRANSPORT-HEADER-REWRITE-001` — header-rewriting rule audit (1.2)
3. `feat: EXO-TRANSPORT-BYPASS-FILTER-001` — bypass-filter rule audit (1.3)
4. `feat: EXO-TRANSPORT-DISABLED-001` — disabled rules persistence (1.6) — *low priority*
5. `feat: EXO-TRANSPORT-PRIORITY-001` — rule priority / masking detection (1.7) — *low priority*
6. `feat: EXO-CONNECTOR-INBOUND-001` — inbound connector posture (TLS / cert / IP)
7. `feat: EXO-CONNECTOR-OUTBOUND-001` — outbound connector recipient restriction
8. `feat: EXO-CONNECTOR-HYBRID-001` — hybrid coexistence connectors (2.4) — *low priority*
9. `feat: EXO-CONNECTOR-STALE-001` — stale / unused connectors (2.5) — *low priority*
10. `feat: EXO-ACCEPTED-DOMAIN-TYPE-001` — accepted domain type matches topology (3.1)
11. `feat: EXO-MAILBOX-FORWARDING-INVENTORY-001` — per-mailbox forwarding addresses inventory (4.3)
12. `feat: EXO-INBOX-RULE-AUDIT-001` — inbox rule audit for high-risk mailboxes (4.4)

**Possible new data file:**

- `data: introduce data/transport-rule-actions.json` — curated reference of ~50 transport rule action types classified as benign / suspicious / hostile (mirrors role-tiers.json + microsoft-first-party-appids.json pattern). Useful both for CheckID consumers AND for the audit framework itself.

**Narrative refresh (`chore:` issues, 3):**

- `chore: refresh EXO-TRANSPORT-002 narrative` — explicit destination-validation framing for redirect-to-external rules
- `chore: refresh EXO-FORWARD-001 narrative` — call out the three-surface auto-forwarding alignment requirement (Remote Domain + outbound spam policy + per-mailbox)
- `chore: re-evaluate DNS-DKIM-001 severity` — currently `Low` but DKIM is foundational for DMARC alignment; consider `Medium`

## Out of scope (handled by sibling spikes / future)

- Defender for Office content scanning (anti-phish, anti-spam, anti-malware) — #332
- Mailbox audit logging (`EXO-AUDIT-*` series) — orthogonal, not mail-flow specific
- Sign-in to mailbox / shared mailbox sign-in (`EXO-SHAREDMBX-001`) — orthogonal
- M365 Groups distribution / dynamic groups — separate concern
- Compliance-side message journaling — #335 (Purview)
- Outlook add-ins (`EXO-ADDINS-001`) — orthogonal
- Customer Lockbox (`EXO-LOCKBOX-001`) — orthogonal
- Calendar external sharing (`EXO-SHARING-001`) — touched in #333 indirectly
