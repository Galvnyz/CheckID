# SharePoint Online + OneDrive — Domain Audit (v3.4.0)

**Status:** Eighth domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#337](https://github.com/Galvnyz/CheckID/issues/337).
**Source priorities:** Microsoft Learn primary (Manage sharing settings for SharePoint and OneDrive, External sharing overview, Conditional Access policies for SPO, Limit accidental exposure to files when sharing, OneDrive sync app restrictions), CIS M365 v6 §7 (SharePoint & OneDrive), CISA SCuBA `MS.SHAREPOINT.*`.

## Summary

CheckID has **27 SPO-* checks** covering tenant + site sharing, OneDrive, sync, sessions, scripting, modern auth, B2B integration, content sharing, malware, Loop, Sway, and versioning. This audit catalogs **30 canonical patterns** across 6 sub-domains (tenant-level sharing, external user controls, site-level overrides, CA integration, OneDrive specifics, anti-patterns) and maps them against the registry.

**8 coverage gaps** to file as `feat:` issues, **4 narrative-refresh candidates**, and one **anti-pattern reframing** noted: many existing SPO checks are "Ensure X is set to Y" rather than "Ensure tenant configuration matches an intent." Several gaps are about effective-state rather than property-value (e.g., "tenant sharing capability is consistent with sensitive-site labels") which the existing single-property checks don't catch.

## Existing CheckID inventory (27 SPO-*)

| CheckId | Severity | Pattern category |
|---|---|---|
| `SPO-ACCESS-001` | High | CA coverage for SPO |
| `SPO-ACCESS-002` | Medium | Unmanaged device sync restriction |
| `SPO-AUTH-001` | High | Modern auth required (cross-domain to legacy auth #327) |
| `SPO-B2B-001` | Medium | B2B integration with Entra |
| `SPO-CUIACCESS-001` | High | External sharing restrictions for CUI |
| `SPO-LOOP-001` | Low | Loop Components enabled |
| `SPO-LOOP-002` | Medium | OneDrive Loop sharing |
| `SPO-MALWARE-002` | High | Infected files disallow download |
| `SPO-OD-001` | High | OneDrive content sharing restricted |
| `SPO-SCRIPT-001` | High | Custom script on personal sites |
| `SPO-SCRIPT-002` | High | Custom script on site collections |
| `SPO-SESSION-001` | Medium | Idle session timeout (cross-domain to #331) |
| `SPO-SHARING-001` | Critical | External content sharing restricted |
| `SPO-SHARING-002` | Medium | Guest re-share own-only |
| `SPO-SHARING-003` | Medium | Domain whitelist/blacklist |
| `SPO-SHARING-004` | Critical | Link sharing restricted |
| `SPO-SHARING-005` | Medium | Guest access auto-expiry |
| `SPO-SHARING-006` | Medium | Re-auth verification code |
| `SPO-SHARING-007` | Medium | Default sharing link permission |
| `SPO-SHARING-008` | Medium | External sharing by security group |
| `SPO-SITE-001` | High | Site sharing within tenant policy |
| `SPO-SITE-002` | High | Sensitive sites restricted external |
| `SPO-SITE-003` | Informational | Site collection admin visibility |
| `SPO-SWAY-001` | Medium | Sway external sharing |
| `SPO-SYNC-001` | Medium | OneDrive sync unmanaged-device restriction |
| `SPO-SYNC-002` | Low | Mac sync app enabled |
| `SPO-VERSIONING-001` | Medium | Version history config |

## 1. Tenant-level sharing

### 1.1 SharePoint sharing capability

**Intent:** Tenant-level SharePoint sharing capability is set to "New and existing guests" (CIS recommended) or "Existing guests" (more restrictive) or "Only people in your organization" (most restrictive). NOT "Anyone" (anonymous links allowed), which is the default in unconfigured tenants.
**Detection:** `Get-SPOTenant`:
- `SharingCapability` ∈ {`Disabled`, `ExistingExternalUserSharingOnly`, `ExternalUserSharingOnly`, `ExternalUserAndGuestSharing`}
- Maps to UI: `Disabled` = "Only people in your org", `ExistingExternalUserSharingOnly` = "Existing guests", `ExternalUserSharingOnly` = "New and existing guests" (CIS rec), `ExternalUserAndGuestSharing` = "Anyone" (anti-pattern)

**Pitfalls:** Anonymous-allowed at tenant level can be tightened per-site, but the tenant is the ceiling — sites can be more restrictive, never less.
**Authoritative sources:** Microsoft Learn — Manage sharing settings; CIS M365 v6 §7.2.2.
**Coverage:** ✅ `SPO-SHARING-001` (Critical severity reflects the criticality of getting this right).

### 1.2 OneDrive sharing capability (separate from SPO)

**Intent:** OneDrive sharing capability often more restrictive than SPO ("Only people in your organization" common). CIS recommends OneDrive ≤ "Only people in your org" since OneDrive content tends to be personal-data-flavored.
**Detection:** `Get-SPOTenant.OneDriveSharingCapability` (separate from `SharingCapability`).
**Pitfalls:** Easy to assume OneDrive inherits SharePoint setting; it doesn't. Defaults match SharePoint at provisioning.
**Coverage:** ✅ `SPO-OD-001`.

### 1.3 Default sharing link type

**Intent:** Default link type is "People in your organization" or "Specific people," NOT "Anyone with the link." Default link is what UI defaults to when a user clicks Share.
**Detection:** `Get-SPOTenant.DefaultSharingLinkType` ∈ {`Direct` (specific people), `Internal` (org), `AnonymousAccess` (anti-pattern)}.
**Coverage:** Folds into ✅ `SPO-SHARING-007`.

### 1.4 Default link permission (View vs Edit)

**Intent:** Default link permission is View (read-only), not Edit. Edit-default escalation surface for accidental shares.
**Detection:** `Get-SPOTenant.DefaultLinkPermission` ∈ {`View`, `Edit`}.
**Coverage:** ✅ `SPO-SHARING-007`.

### 1.5 Anonymous link expiration

**Intent:** When anonymous links are allowed (often unavoidable for partner workflows), they expire by default. CIS recommends ≤30 days.
**Detection:** `Get-SPOTenant.RequireAnonymousLinksExpireInDays` > 0 AND ≤ 30.
**Coverage:** **Gap.** File `feat: SPO-ANONYMOUS-EXPIRY-001`.

### 1.6 Anonymous link permission cap

**Intent:** Anonymous links capped at View permission (never Edit). An anonymous Edit link is data-modify-without-attribution.
**Detection:** `Get-SPOTenant.FileAnonymousLinkType` = `View`, `FolderAnonymousLinkType` = `View`.
**Coverage:** **Gap.** File `feat: SPO-ANONYMOUS-PERMISSION-001`.

## 2. External user controls

### 2.1 Guests must sign in with same account that received invitation

**Intent:** External users authenticate with the email address that received the invitation, not a different account they happen to have. Defends against invitation-phishing-and-redirect.
**Detection:** `Get-SPOTenant.RequireAcceptingAccountMatchInvitedAccount = $true`.
**Coverage:** **Gap.** File `feat: SPO-INVITE-MATCH-001`.

### 2.2 Guests can / cannot share items they don't own

**Intent:** Guests should NOT be able to re-share content they don't own (defaults the file's reach to multiple unattributed downstream recipients).
**Detection:** `Get-SPOTenant.PreventExternalUsersFromResharing = $true`.
**Coverage:** ✅ `SPO-SHARING-002`.

### 2.3 Email verification required for unauthenticated recipients

**Intent:** When anonymous link is opened, recipient must verify email before content access. Prevents link-leakage from giving raw access.
**Detection:** `Get-SPOTenant.RequireAnonymousLinksToBeAccessedByEmailAddress` (varies by SPO version) OR via verification-code re-auth setting.
**Coverage:** ✅ partial via `SPO-SHARING-006` (re-auth verification code). **Narrative refresh recommended** — explicit framing as anti-link-leakage.

### 2.4 External users restricted by domain (allow / deny)

**Intent:** B2B sharing restricted to allowed partner domains (allow list) or excludes specific high-risk domains (deny list).
**Detection:** `Get-SPOTenant.SharingDomainRestrictionMode` ∈ {`AllowList`, `BlockList`, `None`} + `Get-SPOTenant.SharingAllowedDomainList` / `SharingBlockedDomainList`.
**Coverage:** ✅ `SPO-SHARING-003`.

### 2.5 External users gated by security group

**Intent:** Only users in a specified security group can share externally — limits the population that can initiate B2B.
**Detection:** `Get-SPOTenant.WhoCanShareAllowListInTenant` populated.
**Coverage:** ✅ `SPO-SHARING-008`.

## 3. Site-level overrides

### 3.1 Sensitive sites set more restrictive than tenant default

**Intent:** Specific sites (containing CUI, financial, executive content) should override tenant default with stricter sharing capability.
**Detection:** `Get-SPOSite -Limit All` per-site `SharingCapability` — flag sites with capability looser than tenant default OR specific sensitive-site identifiers.
**Pitfalls:** Detection requires curator-supplied "sensitive sites list" OR sensitivity-label-based grouping (modern path).
**Coverage:** ✅ `SPO-SITE-002`. **Narrative refresh recommended** — explicit recommendation for sensitivity-label-based site grouping.

### 3.2 Sensitivity labels applied to sites that enforce site-level controls

**Intent:** Modern label-based site governance: sensitivity labels carry sharing restrictions (block external, force device compliance, etc.) that auto-apply to sites the label is published to.
**Detection:** `Get-Label` for sensitivity labels with `SiteAndGroupProtectionEnabled = $true`. Cross-reference site labels via `Get-SPOSite.SensitivityLabel`.
**Pitfalls:** Sensitivity labels are a Purview feature; cross-domain to #335.
**Coverage:** **Gap (cross-domain).** Coordinate with #335 (Purview); file `feat: SPO-SENSITIVITY-LABEL-001`.

### 3.3 "Communication Sites" vs "Team Sites" sharing patterns

**Intent:** Communication sites (broadcasting) typically have different sharing intent than Team sites (collaboration). Tenant should review per-template sharing defaults.
**Detection:** `Get-SPOSite.Template` differentiates; aggregate per-template effective sharing capability.
**Coverage:** **Out of scope** — too org-specific without curator input.

### 3.4 Site lifecycle (orphaned site detection)

**Intent:** Sites with no recent activity, no owners, or invalid groups behind them are detected and reviewed.
**Detection:** `Get-SPOSite -Limit All` + `LastContentModifiedDate` + `Get-SPOUser` for owner state.
**Coverage:** **Gap.** File `feat: SPO-SITE-LIFECYCLE-001` (low priority).

### 3.5 Site collection administrator visibility

**Intent:** Tenant inventory of who has site-collection admin role (the SCA tier — bypasses most CAs and has full site control).
**Coverage:** ✅ `SPO-SITE-003` (informational).

### 3.6 Site sharing within tenant policy

**Intent:** Per-site sharing capability cannot exceed tenant-level setting (Microsoft enforces this; verify state).
**Coverage:** ✅ `SPO-SITE-001`.

## 4. Conditional Access integration

### 4.1 Unmanaged device policy for SPO

**Intent:** Unmanaged devices (no Intune management, no Hybrid Entra Join) get either blocked or restricted to web-only with download prevention (web-only access via app-enforced restrictions).
**Detection:** `Get-SPOTenant.ConditionalAccessPolicy` ∈ {`AllowFullAccess`, `AllowLimitedAccess`, `BlockAccess`}; `LimitedAccess` allows web-only.
**Pitfalls:** App-enforced restrictions only work when CA policy `Use app enforced restrictions` session control is set.
**Coverage:** ✅ partial via `SPO-ACCESS-001` (CA coverage). **Narrative refresh recommended** — explicit `LimitedAccess` flag + CA session-control prerequisite.

### 4.2 SharePoint network location restriction

**Intent:** SharePoint access restricted to trusted IP ranges OR country block via CA named locations.
**Detection:** Cross-reference: CA policy targeting SPO with `conditions.locations` populated.
**Coverage:** **Gap (cross-domain).** Already in #327 §2.8 — cross-link, single CheckID.

### 4.3 Browser session controls on SPO via CA session controls

**Intent:** Persistent browser disabled + sign-in frequency limit on SPO sessions.
**Coverage:** Cross-domain to #331 (token/session). `SPO-SESSION-001` covers idle timeout; broader CA session controls live in #327.

### 4.4 Modern authentication required

**Intent:** Legacy auth blocked for SPO (along with tenant-wide #327 §1.4).
**Coverage:** ✅ `SPO-AUTH-001`.

### 4.5 SharePoint and OneDrive integration with B2B

**Intent:** B2B users can be invited to SPO/OD via the modern B2B integration (vs legacy OneDrive-specific external sharing).
**Detection:** `Get-SPOTenant.EnableAzureADB2BIntegration = $true`.
**Coverage:** ✅ `SPO-B2B-001`.

## 5. OneDrive specifics

### 5.1 OneDrive default storage quota

**Intent:** Default per-user storage quota set per license tier; users beyond quota get prompted to clean up rather than silently growing.
**Detection:** `Get-SPOTenant.OneDriveStorageQuota` (in MB).
**Coverage:** **Gap (low priority).** File `feat: SPO-OD-QUOTA-001`.

### 5.2 Retain OneDrive content for offboarded users

**Intent:** Offboarded user OneDrive content retained for N days (default 30) so manager / archivist can retrieve before deletion.
**Detection:** `Get-SPOTenant.OrphanedPersonalSitesRetentionPeriod` (in days).
**Coverage:** **Gap.** File `feat: SPO-OD-RETENTION-001`.

### 5.3 OneDrive sync app trusted domain list

**Intent:** OneDrive sync app restricted to allow-list of trusted Entra tenant IDs — prevents personal-tenant OneDrive sync from corporate device.
**Detection:** `Get-SPOTenantSyncClientRestriction.TenantRestrictionEnabled = $true` AND `AllowedDomainList` populated.
**Coverage:** ✅ partial via `SPO-SYNC-001` (unmanaged device restriction). **Narrative refresh recommended** — explicit tenant-domain-allow-list framing.

### 5.4 Block macOS / unmanaged device sync

**Intent:** macOS or unmanaged-OS devices blocked from sync (or sync restricted to managed devices).
**Detection:** `Get-SPOTenantSyncClientRestriction.ExcludedFileExtensions` (block specific file types) + `BlockMacSync` (legacy OneDrive setting).
**Coverage:** ✅ `SPO-SYNC-002` (Mac sync), partial via `SPO-SYNC-001`. **Note** — `SPO-SYNC-002` is "Mac Sync App Enabled" which sounds like it confirms Mac sync is enabled (could be intent inversion — should be checking it's restricted, not enabled). Worth narrative-refresh review.

## 6. Anti-patterns (deliberate detection)

### 6.1 Tenant SharePoint = "Anyone" + default link type "Anyone"

**Intent:** This combination = anyone can share anonymous links to anyone, defaulting to anonymous. Data exfil ready by default.
**Detection:** `SharingCapability = ExternalUserAndGuestSharing` AND `DefaultSharingLinkType = AnonymousAccess`.
**Coverage:** Folds into 1.1 + 1.3 covered by `SPO-SHARING-001` and `SPO-SHARING-007`.

### 6.2 Anonymous links with no expiration

**Intent:** Anonymous-link without expiration is a forever-token. Easy data exfil if discovered.
**Coverage:** Folds into 1.5 `SPO-ANONYMOUS-EXPIRY-001`.

### 6.3 Guests can re-share items they don't own

**Coverage:** Folds into ✅ `SPO-SHARING-002`.

### 6.4 All sites use tenant default with no override on sensitive sites

**Coverage:** Folds into ✅ `SPO-SITE-002`.

### 6.5 Sync to unmanaged devices unrestricted

**Coverage:** ✅ `SPO-SYNC-001`.

### 6.6 Default link permission = Edit

**Intent:** Default Edit means the most-common-share goes out with mutate-data permission. Should be View by default; users opt up to Edit when intentional.
**Coverage:** Folds into ✅ `SPO-SHARING-007`.

### 6.7 "Allow access requests" disabled

**Intent:** Access requests disabled means users denied access have no path to request — they ask owners through other channels (Slack, email) which fragments audit trail. Should be enabled (default).
**Detection:** `Get-SPOSite -Limit All` per-site `RequestFilesLinkEnabled` AND `IsHubSite`-related access-request settings.
**Coverage:** **Gap.** File `feat: SPO-ACCESS-REQUESTS-001` (low priority).

### 6.8 Custom scripts allowed on site collections

**Coverage:** ✅ `SPO-SCRIPT-001`, `SPO-SCRIPT-002`.

### 6.9 Sway external sharing not restricted

**Coverage:** ✅ `SPO-SWAY-001`.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| Tenant-level sharing | 6 | 4 | 0 | 2 (1.5, 1.6) |
| External user controls | 5 | 4 | 1 | 1 (2.1) |
| Site-level overrides | 6 | 3 | 1 | 2 (3.2 cross-spike, 3.4 low-pri); 3.3 out-of-scope |
| CA integration | 5 | 3 | 1 | 2 cross-domain (4.2, 4.3 — both single CheckID with #327/#331) |
| OneDrive specifics | 4 | 1 partial | 2 | 2 (5.1 low-pri, 5.2) |
| Anti-patterns | 9 | 5 | 0 | 1 unique (6.7); others fold |
| **Total** | **35 (30 unique after folds)** | **15** | **5** | **8 net to file** |

## Threat-pattern map

| Compromise pattern | Primary control |
|---|---|
| Anonymous link → public-search exposure | Anonymous links require expiration + View-only (1.5, 1.6) |
| Link forwarding bypass | Email verification (2.3); anonymous link expiration (1.5) |
| Invitation phishing-and-redirect | Accepting account must match invited email (2.1) |
| Guest re-share to unattributed parties | Prevent external re-share (2.2) |
| Personal-tenant sync from corporate device | Sync app tenant allow list (5.3) |
| Offboarded user data orphaning | OneDrive retention period (5.2) |
| Site-collection admin bypass | SCA visibility + review (3.5) |
| Custom-script-injection on user content | Custom script restrictions (6.8) |
| Data exfil via "Anyone" default link | Default link type "Internal" (1.3, 1.4) + tenant sharing capability ≤ "New and existing guests" (1.1) |
| Compromised internal user → mass external share | Per-user sharing restricted by security group (2.5) |

## Detection method appendix

### Primary: SharePoint Online PowerShell

This audit's detection contract is split between **SharePoint Online PowerShell** (primary, comprehensive) and **Microsoft Graph beta** (`/admin/sharepoint/settings`, partial coverage). Like #332 (MDO), Graph doesn't yet expose the full SPO admin surface; PS is required for thorough detection.

| Cmdlet | Used for |
|---|---|
| `Get-SPOTenant` | Tenant-level sharing settings (the bulk: SharingCapability, OneDriveSharingCapability, DefaultSharingLinkType, DefaultLinkPermission, RequireAnonymousLinksExpireInDays, FileAnonymousLinkType, RequireAcceptingAccountMatchInvitedAccount, PreventExternalUsersFromResharing, OrphanedPersonalSitesRetentionPeriod, OneDriveStorageQuota, ConditionalAccessPolicy, EnableAzureADB2BIntegration, …) |
| `Get-SPOSite -Limit All` | Per-site sharing capability + lifecycle data (`LastContentModifiedDate`, `Template`, `SensitivityLabel`, `RequestFilesLinkEnabled`) |
| `Get-SPOTenantSyncClientRestriction` | Sync app tenant allow list, OS exclusions |
| `Get-SPOUser -Site $site` | Site-level admin enumeration (3.5) |

### Microsoft Graph beta complement

```
GET /admin/sharepoint/settings                             → tenant settings (subset of Get-SPOTenant)
GET /sites?search=                                         → site inventory + metadata
GET /sites/{site-id}/permissions                          → per-site permission grants (sparse)
```

### Edge cases

1. **`SharingCapability` enum confusion.** The enum names don't match the UI labels: `Disabled` = "Only people in your org", `ExistingExternalUserSharingOnly` = "Existing guests", `ExternalUserSharingOnly` = "New and existing guests", `ExternalUserAndGuestSharing` = "Anyone." Don't trust display names — always read the enum value.

2. **Per-site iteration is paged + slow.** Tenants with 10k+ sites need pagination + sampling. Don't assume `Get-SPOSite -Limit All` is fast.

3. **OneDrive vs SharePoint distinction.** `SharingCapability` is the SharePoint-side default; OneDrive has its own `OneDriveSharingCapability` that's independent. Detection must read both.

4. **Tenant sharing is the ceiling.** Per-site sharing CAN be more restrictive than tenant; CANNOT be more permissive. Microsoft enforces this. Detection should still verify the invariant holds (defensive).

5. **`ConditionalAccessPolicy` enum semantics.** `LimitedAccess` value is "web-only access; download blocked" — only effective when paired with a CA policy using `Use app enforced restrictions` session control. Without that pairing, `LimitedAccess` is a property change with no effect.

6. **Anonymous link enums.** `FileAnonymousLinkType` and `FolderAnonymousLinkType` independent enums; both should be reviewed.

7. **Sensitivity label site protection.** `Get-SPOSite.SensitivityLabel` returns the label GUID; must cross-reference `Get-Label` to interpret what protections it applies. Cross-domain to #335.

8. **Sync restriction enums.** `Get-SPOTenantSyncClientRestriction` has multiple knobs: `TenantRestrictionEnabled`, `AllowedDomainList`, `BlockMacSync`, `ExcludedFileExtensions`. Effective state requires reading all four.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 8):**

1. `feat: SPO-ANONYMOUS-EXPIRY-001` — anonymous link expiration ≤30 days (1.5)
2. `feat: SPO-ANONYMOUS-PERMISSION-001` — anonymous link View-only cap (1.6)
3. `feat: SPO-INVITE-MATCH-001` — accepting account must match invited email (2.1)
4. `feat: SPO-SENSITIVITY-LABEL-001` — sensitivity-label-based site protection (3.2) — *cross-domain with #335 (Purview)*
5. `feat: SPO-SITE-LIFECYCLE-001` — orphaned site detection (3.4) — *low priority*
6. `feat: SPO-OD-QUOTA-001` — OneDrive default storage quota (5.1) — *low priority*
7. `feat: SPO-OD-RETENTION-001` — orphaned OneDrive retention period (5.2)
8. `feat: SPO-ACCESS-REQUESTS-001` — site-level access requests enabled (6.7) — *low priority*

**Cross-spike (single CheckID, document overlap):**

- `CA-NAMEDLOC-001/-002` from #327 cover §4.2 (SharePoint network location) — same control surface
- Token/session controls on SPO covered by #331; this audit's `SPO-SESSION-001` is the SPO-specific surface

**Narrative refresh (`chore:` issues, 4):**

- `chore: refresh SPO-SHARING-006 narrative` — explicit anti-link-leakage framing
- `chore: refresh SPO-SITE-002 narrative` — recommend sensitivity-label-based site grouping (modern path)
- `chore: refresh SPO-ACCESS-001 narrative` — explicit `LimitedAccess` flag + CA session-control prerequisite
- `chore: refresh SPO-SYNC-001 narrative` — explicit tenant-domain-allow-list framing
- *Possible inversion check on `SPO-SYNC-002`* — name "Mac Sync App Enabled" sounds like it's checking that Mac sync IS enabled. Audit verdict should be checking it's RESTRICTED. Worth re-reading the implementation; if inversion confirmed, file as a bug rather than narrative refresh.

## Out of scope (handled by sibling spikes)

- Sensitivity labels themselves (definition + auto-labeling) — #335 (Purview)
- Teams external file sharing — #340 (Teams) — `TEAMS-CLIENT-001` already noted there
- B2B identity-plane (cross-tenant access settings) — #333
- Token/session security beyond SPO — #331
- File-level permissions (out of scope for tenant configuration audit; per-file ACL is org-runtime)
