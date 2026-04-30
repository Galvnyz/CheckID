# Microsoft Teams — Domain Audit (v3.4.0)

**Status:** Ninth domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#340](https://github.com/Galvnyz/CheckID/issues/340).
**Source priorities:** Microsoft Learn primary (Manage external access in Microsoft Teams, Manage guest access, B2B Direct Connect with shared channels, Teams meeting policies reference, Teams app permission policies, Sensitivity labels for Teams), MSRC (Teams chat phishing patterns, Midnight Blizzard / Storm-0539 Teams tradecraft), CIS M365 v6 §8 (Teams), CISA SCuBA `MS.TEAMS.*`.

## Summary

CheckID has **20 TEAMS-* checks** covering external access, guest access, meeting policies, app permissions, client config, and reporting. This audit catalogs **30 canonical patterns** across 6 sub-domains (external access, B2B Direct Connect, guest access, meeting policies, app + custom integration, anti-patterns) and maps them against the registry.

**10 coverage gaps** to file as `feat:` issues, **3 narrative-refresh candidates**. Notable structural finding: Teams has **multiple distinct external surfaces** (federation, B2B Direct Connect for shared channels, guest access, anonymous meeting join) that get conflated easily — the audit doc includes an **external-surface reconciliation guide** distinguishing each.

This audit completes the **collaboration triad** of v3.4.0:
- #332 (MDO) — content protection layer
- #337 (SPO/OneDrive) — file-share layer
- #340 (Teams) — chat / meeting / app layer

## Existing CheckID inventory (20 TEAMS-*)

| CheckId | Severity | Pattern category |
|---|---|---|
| `TEAMS-APPS-001` | Medium | Resource-Specific Consent (RSC) |
| `TEAMS-APPS-002` | Medium | App permission policies configured |
| `TEAMS-CLIENT-001` | Medium | External file sharing approved cloud storage only |
| `TEAMS-CLIENT-002` | Low | Channel email address from external |
| `TEAMS-EXTACCESS-001` | Medium | Unmanaged Teams users communication |
| `TEAMS-EXTACCESS-002` | Medium | External Teams cannot initiate |
| `TEAMS-EXTACCESS-003` | Medium | External domains restricted |
| `TEAMS-EXTACCESS-004` | Medium | Skype users communication disabled |
| `TEAMS-GUEST-001` | High | Guest access enabled (cross-domain to #333) |
| `TEAMS-INFO-001` | Informational | Teams workload active (meta) |
| `TEAMS-MEETING-001` | High | Anonymous users cannot join |
| `TEAMS-MEETING-002` | Medium | Anonymous + dial-in cannot start |
| `TEAMS-MEETING-003` | Medium | Only org users bypass lobby |
| `TEAMS-MEETING-004` | Medium | Dial-in cannot bypass lobby |
| `TEAMS-MEETING-005` | Medium | External cannot give/request control |
| `TEAMS-MEETING-006` | Medium | Meeting chat blocks anonymous |
| `TEAMS-MEETING-007` | Medium | Only organizers can present |
| `TEAMS-MEETING-008` | Medium | External meeting chat off |
| `TEAMS-MEETING-009` | Medium | Meeting recording off by default |
| `TEAMS-REPORTING-001` | Medium | Users can report security concerns |

## External-surface reconciliation guide

Teams has multiple distinct external surfaces that share names but mean different things. This is the central confusion the audit untangles.

| Surface | What it allows | Where configured | Companion identity-plane control |
|---|---|---|---|
| **External access (federation)** | Teams chat between your tenant and another Teams tenant (or Skype consumer) | `Get-CsTenantFederationConfiguration` | Cross-tenant access policy (#333) |
| **B2B Direct Connect** | Shared channels with another tenant's users (no guest-account creation; users authenticate from their home tenant) | `Get-CsTeamsChannelsPolicy` + cross-tenant access policy `b2bDirectConnectInbound`/`Outbound` | Cross-tenant access policy (#333) |
| **Guest access** | External users created as guest objects in your tenant (subject to #333 guest controls) join Teams | `Get-CsTeamsGuestMeetingConfiguration` + tenant guest policy | Guest CA policy (#327, #333) |
| **Anonymous meeting join** | Users with a meeting link who haven't authenticated at all | `Get-CsTeamsMeetingPolicy.AllowAnonymousUsersToJoinMeeting` | None — anonymous = no identity |

A tenant may have all four enabled simultaneously, or just some. Each has its own threat model. CheckID's Teams checks should explicitly call out which surface each one governs.

## 1. External access (federation)

### 1.1 External access mode

**Intent:** Federation mode set to `Allow specific external domains` (whitelist) or `Block specific external domains` (blacklist) — NOT `Allow all` (open federation).
**Detection:** `Get-CsTenantFederationConfiguration`:
- `AllowFederatedUsers = $true` (with allow/block list as appropriate)
- `AllowedDomains` populated when whitelisting
- `BlockedDomains` populated when using blacklist mode
- `AllowFederatedUsers = $false` if federation completely blocked

**Pitfalls:** "Allow all" with empty block list = open federation; any tenant on the internet can chat with yours. Whitelist-mode is the recommended posture but adds operational overhead (every new partner requires admin add).
**Authoritative sources:** Microsoft Learn — Manage external access; CIS M365 v6 §8.1.1.
**Threats defeated:** Phishing-via-Teams-chat from arbitrary external tenants (Midnight Blizzard / Storm-0539 tradecraft 2023-2024); T1566 (Phishing).
**Coverage:** ✅ partial via `TEAMS-EXTACCESS-003` (external domains restricted). **Narrative refresh recommended** — explicit whitelist-vs-blacklist mode framing + threat-pattern naming.

### 1.2 Skype consumer interop disabled

**Intent:** Skype consumer (legacy) interop disabled. Modern recommendation: zero Skype consumer scenarios in 2026.
**Detection:** `Get-CsTenantFederationConfiguration.AllowPublicUsers = $false`.
**Coverage:** ✅ `TEAMS-EXTACCESS-004`.

### 1.3 Trusted partners list reconciled with cross-tenant access policy

**Intent:** Federation `AllowedDomains` and cross-tenant access policy `partners` should be a consistent list. Drift means Teams allows chat with tenants that the cross-tenant policy doesn't allow B2B with (or vice versa).
**Detection:** Compare `Get-CsTenantFederationConfiguration.AllowedDomains` vs `/policies/crossTenantAccessPolicy/partners`; flag drift.
**Coverage:** **Gap (cross-domain).** File `feat: TEAMS-FEDERATION-XTAS-CONSISTENCY-001`. Cross-spike with #333.

### 1.4 Teams identity provider trust scope

**Intent:** Teams federation respects the cross-tenant access policy's `inboundTrust` settings (#333 §1.2).
**Coverage:** Folds into cross-tenant access policy controls (#333). Document the cross-link.

### 1.5 External users cannot initiate

**Intent:** External Teams users can join chats your users invite them to but cannot initiate unsolicited chats.
**Coverage:** ✅ `TEAMS-EXTACCESS-002`.

### 1.6 Communication with unmanaged Teams users

**Intent:** Communication with unmanaged Teams users (free-tier Teams accounts not affiliated with a paid tenant) typically blocked.
**Coverage:** ✅ `TEAMS-EXTACCESS-001`.

## 2. B2B Direct Connect (shared channels)

### 2.1 Shared channel creation policy

**Intent:** Who can create shared channels (Owners only? specific user groups?). Restricted creation prevents shadow-shared-channel proliferation.
**Detection:** `Get-CsTeamsChannelsPolicy`:
- `AllowSharedChannelCreation` = `$true` only for specific Channel Creator policy targeting privileged users
- Default policy may have `AllowSharedChannelCreation = $false`

**Coverage:** **Gap.** File `feat: TEAMS-SHARED-CHANNEL-CREATE-001`.

### 2.2 Cross-tenant access policy B2B Direct Connect settings

**Intent:** B2B Direct Connect inbound/outbound configured per cross-tenant access policy — explicit per-partner allow vs deny.
**Detection:** Cross-domain to #333 §3.3 (B2B Direct Connect partner gating).
**Coverage:** Cross-spike. Single CheckID with #333 `CA-B2B-DIRECT-001`.

### 2.3 Trusted tenants for shared channels

**Intent:** Shared channels only with explicitly-allowlisted partner tenants.
**Coverage:** Folds into 2.2.

### 2.4 Sensitivity label policy on shared channels

**Intent:** Sensitivity labels can restrict which channels can be shared (e.g., "Confidential" label blocks shared-channel creation).
**Detection:** `Get-Label` with `SiteAndGroupProtectionEnabled = $true` and policy that targets Teams scope. Cross-domain to #335.
**Coverage:** **Gap (cross-domain).** Cross-spike with #335 (Purview); single CheckID `feat: TEAMS-SENSITIVITY-LABEL-001`.

## 3. Guest access

### 3.1 Guest access enabled at Teams policy level

**Intent:** Guest access enabled with appropriate guest meeting / messaging / calling policies — distinct from tenant-wide M365 guest setting.
**Detection:** `Get-CsTeamsClientConfiguration.AllowGuestUser = $true` (or false if guests blocked entirely from Teams).
**Coverage:** ✅ `TEAMS-GUEST-001`.

### 3.2 Guest message + content controls

**Intent:** Guest messaging policy: can guests delete/edit messages, share files, use giphys/stickers, etc. Restrictive guest scope reduces social-engineering surface.
**Detection:** `Get-CsTeamsGuestMessagingConfiguration`:
- `AllowUserDeleteChat = $true/$false` (allow guest to delete from their own chat — typically fine)
- `AllowUserEditMessage = $true/$false` (allow guest to edit own — typically fine)
- `AllowUserDeleteMessage = $true/$false` — **anti-pattern when true**: guest can erase audit trail of their own messages
- `AllowImmersiveReader = $true/$false`
- `AllowGiphy`, `AllowStickers`, `AllowMemes` — UX flexibility vs noise

**Pitfalls:** `AllowUserDeleteMessage = $true` for guests means guest can send phishing payload then delete it before the user reports — surfaces only in Teams audit log if retained.
**Coverage:** **Gap.** File `feat: TEAMS-GUEST-MESSAGE-CONTROL-001`.

### 3.3 Guest video calling + screen sharing permissions

**Intent:** Guests can/can't initiate calls, share screens. Restricted guest scope reduces phishing-via-screen-share surface.
**Detection:** `Get-CsTeamsGuestCallingConfiguration`:
- `AllowPrivateCalling = $true/$false`
- `AllowMeetingsInChannels` (separate but related)

**Coverage:** **Gap.** File `feat: TEAMS-GUEST-CALLING-001`.

### 3.4 Guest user expiration / sponsor controls

**Coverage:** Cross-domain to #333 §3.3 — same control surface, single CheckID.

## 4. Meeting policies

### 4.1 Anonymous meeting join allowed (per policy)

**Intent:** Default meeting policy disallows anonymous join; specific custom policies may allow for community-event scenarios.
**Detection:** `Get-CsTeamsMeetingPolicy -Identity Global.AllowAnonymousUsersToJoinMeeting = $false` for default; opt-in via custom policy for specific user populations.
**Pitfalls:** Default-policy allowing anonymous join means EVERY meeting allows it unless the organizer changes per-meeting. Population-default-restrictive matches the principle of least privilege.
**Coverage:** ✅ `TEAMS-MEETING-001` (anonymous can't join). Pair with custom-policy opt-in framing.

### 4.2 Lobby behavior for anonymous + guests

**Intent:** Anonymous and external participants ALWAYS go through lobby; can't bypass even when invited.
**Detection:** `Get-CsTeamsMeetingPolicy.AutoAdmittedUsers`:
- `EveryoneInCompany` = only org users bypass lobby (CIS rec)
- `EveryoneInCompanyExcludingGuests` = strictest
- `Everyone` = anti-pattern (anyone bypasses)

**Pitfalls:** Combined with anonymous-join-allowed, lobby-bypassed = "anyone joins directly" — control hijacking risk for executive meetings.
**Coverage:** ✅ `TEAMS-MEETING-003`, ✅ `TEAMS-MEETING-004` (dial-in can't bypass).

### 4.3 "Who can present" default

**Intent:** Default policy: "Only organizers and co-organizers can present" — defends against meeting hijacking + accidental presenter handoff.
**Detection:** `Get-CsTeamsMeetingPolicy.WhoCanPresent`:
- `OrganizerOnly` = strictest
- `OrganizerOnlyUserOverride` = organizer can opt up
- `EveryoneUserOverride` = default flexibility
- `EveryoneInCompanyUserOverride` = org-wide (anti-pattern for sensitive meetings)
- `Everyone` = anti-pattern

**Coverage:** ✅ `TEAMS-MEETING-007`.

### 4.4 Meeting recording + transcription scope

**Intent:** Recording off by default; participants can opt up for specific meeting types. Transcription separately governed.
**Detection:** `Get-CsTeamsMeetingPolicy.AllowCloudRecording = $false` for default; AllowTranscription, AllowMeetingCoach, AllowMeetingNotes.
**Coverage:** ✅ `TEAMS-MEETING-009`.

### 4.5 End-to-end encrypted meetings

**Intent:** E2EE meetings allowed for sensitive scenarios (executive, M&A, legal hold). Specific user policy enables per-meeting opt-in.
**Detection:** `Get-CsTeamsMeetingPolicy.AllowEndToEndEncryption` (boolean) + `EndToEndEncryptionEnabledType` enum.
**Coverage:** **Gap.** File `feat: TEAMS-MEETING-E2EE-001`.

### 4.6 Meeting chat retention + post-meeting access

**Intent:** Meeting chat persists / expires per retention policy. External meeting chat off by default per Microsoft post-2024 default.
**Coverage:** ✅ `TEAMS-MEETING-008` (external chat off). **Narrative refresh recommended** — pair with retention policy reference.

### 4.7 External participants control / give-control restrictions

**Coverage:** ✅ `TEAMS-MEETING-005`.

### 4.8 Meeting chat blocks anonymous

**Coverage:** ✅ `TEAMS-MEETING-006`.

### 4.9 Anonymous + dial-in cannot start

**Coverage:** ✅ `TEAMS-MEETING-002`.

## 5. App + custom integration policy

### 5.1 Teams app permission policy

**Intent:** App permission policy restricts which apps users can install (Microsoft, third-party, custom). Default policy is permissive; custom restrictive policies for sensitive populations.
**Detection:** `Get-CsTeamsAppPermissionPolicy`:
- `DefaultCatalogApps` = `Allow` / `Block`
- `GlobalCatalogApps` = `Allow` / `Block`
- `PrivateCatalogApps` = `Allow` / `Block`
- Per-policy app inclusion/exclusion lists

**Coverage:** ✅ `TEAMS-APPS-002`.

### 5.2 Custom app sideloading restrictions

**Intent:** Sideloading custom apps disabled in default policy; allowed only for developer/IT user populations. Sideloading bypasses the org's app review.
**Detection:** `Get-CsTeamsAppSetupPolicy.AllowSideLoading = $false` for default; `AllowUserPinning` similar.
**Pitfalls:** Sideloading is a known lateral-movement path — malicious Teams app installed on a user can read messages, files, screen captures.
**Authoritative sources:** Microsoft Learn — App sideloading in Teams; MSRC — Teams app abuse.
**Coverage:** **Gap.** File `feat: TEAMS-APP-SIDELOAD-001`.

### 5.3 Third-party app store enabled / blocked

**Intent:** Third-party (non-Microsoft) app store availability is intentional — most orgs should restrict.
**Detection:** Folds into 5.1 `TEAMS-APPS-002` (DefaultCatalogApps reflects Microsoft default state).
**Coverage:** Folds into 5.1.

### 5.4 App setup policy (which apps are pinned)

**Intent:** Apps pinned in default user UX (Calendar, Calls, Tasks, Approvals, etc.) match enterprise expectations; sensitive integrations (PowerApps, Power Automate) gated to specific user groups.
**Detection:** `Get-CsTeamsAppSetupPolicy.PinnedAppBarApps` enumeration.
**Coverage:** **Gap (low priority).** File `feat: TEAMS-APP-SETUP-001`.

### 5.5 Resource-Specific Consent (RSC)

**Intent:** RSC is the Teams app permission model where apps request specific channel/team-scoped permissions instead of tenant-wide. Should be enabled (modern best practice) but with admin-consent-required for sensitive scopes.
**Detection:** `Get-CsTeamsClientConfiguration.AllowResourceAccountSendMessage` + tenant settings on resource-specific consent. `Get-MgPolicyAdminConsentRequestPolicy` for admin-consent flow.
**Coverage:** ✅ `TEAMS-APPS-001`.

### 5.6 External file sharing approved storage

**Coverage:** ✅ `TEAMS-CLIENT-001`.

### 5.7 Channel email address from external

**Coverage:** ✅ `TEAMS-CLIENT-002`.

## 6. Anti-patterns (deliberate detection)

### 6.1 External access = "Allow all"

**Intent:** Federation with any tenant on the internet = Teams chat phishing surface.
**Coverage:** Folds into 1.1 narrative refresh.

### 6.2 B2B Direct Connect inbound default-allow without partner allow list

**Coverage:** Cross-domain to #333 §3.3.

### 6.3 Anonymous meeting join allowed AND lobby bypassed

**Intent:** This combination = anyone joins directly; control hijacking risk.
**Detection:** Cross-check `AllowAnonymousUsersToJoinMeeting = $true` AND `AutoAdmittedUsers` looser than `EveryoneInCompany`.
**Coverage:** **Gap.** File `feat: TEAMS-MEETING-ANON-LOBBY-COMBO-001`.

### 6.4 "Everyone can present" + anonymous join

**Intent:** This combination = control hijacking risk for executive meetings.
**Detection:** Cross-check on default policy.
**Coverage:** Folds into 4.3 narrative.

### 6.5 Custom app sideloading enabled in default policy

**Coverage:** Folds into 5.2.

### 6.6 Guest message edit / delete enabled

**Coverage:** Folds into 3.2.

### 6.7 Shared channel sensitivity label policy not enforced

**Coverage:** Folds into 2.4.

### 6.8 Channel email address open to external

**Coverage:** ✅ `TEAMS-CLIENT-002`.

### 6.9 Federation allowed to consumer Skype

**Coverage:** ✅ `TEAMS-EXTACCESS-004`.

### 6.10 Anonymous user can start a meeting

**Coverage:** ✅ `TEAMS-MEETING-002`.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| External access (federation) | 6 | 4 | 1 | 1 (1.3 cross-domain) |
| B2B Direct Connect | 4 | 0 | 0 | 2 (2.1, 2.4 cross-spike) |
| Guest access | 4 | 1 | 0 | 2 (3.2, 3.3); 3.4 cross-spike |
| Meeting policies | 9 | 7 | 1 | 1 (4.5 E2EE) |
| App + custom integration | 7 | 4 | 0 | 2 (5.2, 5.4 low-pri); 5.3 folds |
| Anti-patterns | 10 | 4 | 0 | 1 unique (6.3); others fold |
| **Total** | **40 (30 unique after folds)** | **20** | **2** | **8 net to file** |

(Plus 3 cross-spike CheckIDs folded into #333 + #335.)

## Threat-pattern map

| Compromise pattern | Tradecraft | Primary control |
|---|---|---|
| Phishing-via-Teams-chat from arbitrary external tenant | Midnight Blizzard 2023-2024; Storm-0539 | Federation whitelist mode + cross-tenant policy consistency (1.1, 1.3) |
| Anonymous meeting join + lobby bypass → control hijacking | Crashing exec meetings, screen-share weaponization | Anonymous-disabled-by-default + lobby-required for non-org (4.1, 4.2, 6.3) |
| Malicious Teams app sideloading | Lateral movement post-account-compromise | Sideloading disabled in default policy (5.2) |
| Guest erases their own malicious chat | Post-attack audit-trail destruction | `AllowUserDeleteMessage = $false` for guests (3.2) |
| Compromised guest screen-shares to phish | Social engineering during guest meeting | Guest calling/screen-share restrictions (3.3) |
| External meeting chat phishing | Embedded malicious URL in chat post-meeting | External meeting chat off (4.6) + Safe Links Teams scope from #332 |
| Skype-bridge phishing | Legacy interop attack surface | Skype consumer interop disabled (1.2) |
| Meeting recording without consent | Compliance / privacy risk | Recording off by default + per-meeting opt-in (4.4) |
| Open federation = chat-phishing surface | Generic outbound | Federation whitelist mode (1.1) |
| RSC abuse | App requests broader scope than declared | RSC enabled with admin consent for sensitive scopes (5.5) |

## Detection method appendix

### Primary: Microsoft Teams PowerShell

| Cmdlet | Used for |
|---|---|
| `Get-CsTenantFederationConfiguration` | External access mode (1.1, 1.2, 1.3, 1.6) |
| `Get-CsTeamsClientConfiguration` | Client-level controls (3.1, 5.5, 5.6, 5.7) |
| `Get-CsTeamsMeetingPolicy` | Per-policy meeting controls (4.x) — Default + Custom |
| `Get-CsTeamsMessagingPolicy` | Message edit / delete / chat scope (3.2, anti-patterns) |
| `Get-CsTeamsAppSetupPolicy` | App setup / pinned apps / sideloading (5.2, 5.4) |
| `Get-CsTeamsAppPermissionPolicy` | App catalog + per-policy allow/block lists (5.1) |
| `Get-CsTeamsChannelsPolicy` | Shared channel + private channel policy (2.1) |
| `Get-CsTeamsGuestMeetingConfiguration` / `Get-CsTeamsGuestMessagingConfiguration` / `Get-CsTeamsGuestCallingConfiguration` | Guest scope (3.x) |

### Graph beta complement

```
GET /teamwork/teamsAppSettings                                       → tenant-wide app settings (limited)
GET /teams                                                           → team inventory
GET /policies/crossTenantAccessPolicy/partners                        → b2bDirectConnectInbound/Outbound (cross-spike #333)
```

### Edge cases

1. **Default vs Custom policies.** Almost every Teams policy type has Default + multiple Custom policies. Effective policy per user requires resolving via assignment (`Get-CsOnlineUser -Identity user@tenant`). Most Pester regressions can check Default policy only as a baseline.

2. **Teams policy assignment via group membership.** Users assigned to Teams custom policies via groups; resolution requires expanding group membership. Effective state is complex.

3. **Federation, B2B Direct Connect, Guest access, anonymous meeting overlap.** Four distinct surfaces; easy to misread one as another. The reconciliation guide above is canonical for the audit.

4. **"Default" policy values change over time as Microsoft updates baseline.** Microsoft has shipped restrictive-default updates for several Teams policies in 2023-2024 (e.g., anonymous meeting join disabled by default in new tenants). Detection should distinguish "Microsoft default has improved" from "we set this explicitly."

5. **Anonymous meeting join had default-on history.** Tenants created before the Microsoft default flip may still have the legacy permissive default. Verify explicitly rather than inferring from Microsoft current default.

6. **`Get-CsTeamsMeetingPolicy` returns OBJECTS, not strings.** `WhoCanPresent` returns enum value; comparing as string requires `.ToString()` or explicit type handling.

7. **App permission policy + setup policy interaction.** Permission policy controls what's INSTALLABLE; setup policy controls what's PINNED in the UI. Both must be reviewed for full coverage.

8. **Resource-Specific Consent vs delegated permission consent.** Two different consent flows. Detection should distinguish.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 8 net):**

1. `feat: TEAMS-FEDERATION-XTAS-CONSISTENCY-001` — federation allowed-domains vs cross-tenant partners drift detection (1.3) — *cross-spike with #333*
2. `feat: TEAMS-SHARED-CHANNEL-CREATE-001` — shared channel creation policy (2.1)
3. `feat: TEAMS-SENSITIVITY-LABEL-001` — sensitivity-label policy on shared channels (2.4) — *cross-spike with #335*
4. `feat: TEAMS-GUEST-MESSAGE-CONTROL-001` — guest delete-own-message anti-pattern (3.2)
5. `feat: TEAMS-GUEST-CALLING-001` — guest video/screen-share controls (3.3)
6. `feat: TEAMS-MEETING-E2EE-001` — end-to-end encrypted meetings allowed (4.5)
7. `feat: TEAMS-APP-SIDELOAD-001` — custom app sideloading restricted in default (5.2)
8. `feat: TEAMS-APP-SETUP-001` — app setup policy / pinned apps review (5.4) — *low priority*
9. `feat: TEAMS-MEETING-ANON-LOBBY-COMBO-001` — anonymous-allowed + lobby-bypassed combo (6.3)

**Cross-spike (single CheckID, document overlap):**

- `CA-B2B-DIRECT-001` from #333 §3.3 covers 2.2 — B2B Direct Connect partner gating
- `CA-GUEST-MFA-001` from #327 §3.1 / #333 §3.4 covers 3.4 — guest MFA enforcement

**Narrative refresh (`chore:` issues, 3):**

- `chore: refresh TEAMS-EXTACCESS-003 narrative` — explicit whitelist-vs-blacklist mode framing + Midnight Blizzard / Storm-0539 threat-pattern naming
- `chore: refresh TEAMS-MEETING-001 narrative` — pair with custom-policy opt-in framing for community events
- `chore: refresh TEAMS-MEETING-008 narrative` — pair with retention policy reference

## Out of scope (handled by sibling spikes / future)

- Teams Phone (Calling Plans, Direct Routing) — separate concern
- Teams Rooms / Teams device hardening — out of M365 software-config scope
- Live Events / Webinars — touched lightly under meeting policies; deeper coverage if a gap surfaces
- Identity-plane controls for guests — #333 (already covered)
- Sensitivity label definitions (Teams-scope) — #335 (Purview)
- Teams ZAP / message scanning — #332 (MDO covers ZAP)
- Defender for Cloud Apps Teams session policies — #338
- Sign-in log analytics for Teams chat patterns — runtime telemetry, future track
