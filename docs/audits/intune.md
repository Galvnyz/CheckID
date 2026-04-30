# Microsoft Intune — Domain Audit (v3.4.0)

**Status:** Eleventh domain audit under umbrella [#326](https://github.com/Galvnyz/CheckID/issues/326). Resolves spike [#334](https://github.com/Galvnyz/CheckID/issues/334).
**Source priorities:** Microsoft Learn primary (Microsoft Intune deployment guide, Compliance policy basics, Microsoft Intune security baselines, App Protection Policies overview, Windows Autopilot deployment, Conditional Access integration with Intune), CIS Microsoft Intune Benchmark, MSRC blog (endpoint compromise patterns, mass-wipe attack indicators).

## Summary

CheckID has **20 INTUNE-* checks** covering compliance, encryption, enrollment, baselines, app control, network, audit, RBAC, and Multi-Admin Approval. This audit catalogs **31 canonical patterns** across 6 sub-domains (compliance policy fundamentals, configuration profiles + baselines, App Protection Policies / MAM, Conditional Access integration, Autopilot + enrollment, anti-patterns) and maps them against the registry.

**11 coverage gaps** to file as `feat:` issues, **3 narrative-refresh candidates**. Notable structural finding: **MAM (App Protection Policies) is severely underrepresented** in the existing registry — most BYOD scenarios are gated by MAM, and CheckID has zero dedicated MAM coverage today. Six gap CheckIDs in this single area.

This audit pairs with **#330 (authentication methods)** for the **WHfB cloud trust** cross-spike and **#327 (Conditional Access)** for the **device compliance integration** that connects this domain to identity.

## Existing CheckID inventory (20 INTUNE-*)

| CheckId | Severity | Pattern category |
|---|---|---|
| `INTUNE-APPCONTROL-001` | High | Application control |
| `INTUNE-AUTODISC-001` | Medium | Automated discovery + enrollment |
| `INTUNE-COMPLIANCE-001` | High | Devices without policy marked non-compliant |
| `INTUNE-ENCRYPTION-001` | High | Device encryption policy |
| `INTUNE-ENROLL-001` | Medium | Personal device enrollment blocked by default |
| `INTUNE-ENROLLMENT-001` | Medium | Device enrollment restrictions |
| `INTUNE-FIPS-001` | High | FIPS-validated cryptography enforced |
| `INTUNE-INVENTORY-001` | Medium | Authoritative inventory + categories |
| `INTUNE-MAA-001` | Medium | Multi-Admin Approval for destructive operations |
| `INTUNE-MOBILECODE-001` | High | PowerShell execution policy restricts |
| `INTUNE-MOBILEENCRYPT-001` | High | Mobile encryption required |
| `INTUNE-PORTSTORAGE-001` | High | Portable storage restricted on external |
| `INTUNE-RBAC-001` | Low | RBAC role assignments scope tags |
| `INTUNE-REMOTEVPN-001` | Medium | Always-On VPN configured |
| `INTUNE-REMOVABLEMEDIA-001` | High | Removable media blocked |
| `INTUNE-SECURITY-001` | High | Device compliance policy baseline |
| `INTUNE-UPDATE-001` | Medium | Windows Update ring config |
| `INTUNE-VPNCONFIG-001` | High | VPN split tunneling prevented |
| `INTUNE-WIFI-001` | High | WiFi enterprise auth + encryption |
| `INTUNE-WIPEAUDIT-001` | High | Mass device wipe attack indicator |

## 1. Compliance policy fundamentals

### 1.1 Per-platform compliance policies

**Intent:** Compliance policies exist for every platform the tenant supports (Windows, iOS, Android, macOS, Linux). Missing platform = devices in that platform don't get a compliance verdict and pass CA "device compliance" without actual evaluation.
**Detection:** `GET /deviceManagement/deviceCompliancePolicies` — group by `@odata.type` to confirm coverage:
- `#microsoft.graph.windows10CompliancePolicy`
- `#microsoft.graph.iosCompliancePolicy`
- `#microsoft.graph.androidCompliancePolicy` / `androidWorkProfileCompliancePolicy`
- `#microsoft.graph.macOSCompliancePolicy`
- `#microsoft.graph.linuxCompliancePolicy`

**Pitfalls:** Tenants enrolled in Intune for Windows-only often skip iOS/Android compliance, leaving mobile devices ungated. CA's "Require compliant device" passes for those devices = effective bypass.
**Coverage:** ✅ partial via `INTUNE-SECURITY-001` (general baseline). **Gap on per-platform completeness** — file `feat: INTUNE-COMPLIANCE-PLATFORM-001`.

### 1.2 Assignment to all-users (or "all licensed users")

**Intent:** Compliance policy assigned to a broad-coverage group. Per-user-group assignment leaves coverage gaps.
**Detection:** `GET /deviceManagement/deviceCompliancePolicies/{id}/assignments` — flag policies assigned to no users / specific small groups when tenant intent is broad.
**Coverage:** **Gap.** File `feat: INTUNE-COMPLIANCE-ASSIGNMENT-001`.

### 1.3 Encryption required (per platform)

**Intent:** BitLocker on Windows, FileVault on macOS, device encryption on iOS/Android.
**Detection:** Per-platform compliance policy with encryption requirement:
- Windows: `bitLockerEnabled = true`
- macOS: `fileVaultEnabled = true` (in custom policy)
- iOS: `passcodeRequired = true` AND `passcodeBlockSimple = true` (encryption is automatic when passcode is set)

**Coverage:** ✅ `INTUNE-ENCRYPTION-001` (Windows-flavored), ✅ `INTUNE-MOBILEENCRYPT-001` (mobile).

### 1.4 Minimum OS version enforced + grace period

**Intent:** Compliance policy enforces minimum OS version with grace period (typically 7-30 days). Forces patching cadence.
**Detection:** Per-platform compliance policy `osMinimumVersion` and `gracePeriod` set.
**Coverage:** **Gap.** File `feat: INTUNE-COMPLIANCE-OS-VERSION-001`.

### 1.5 Jailbreak / root detection

**Intent:** Mobile compliance policies flag jailbroken / rooted devices as non-compliant.
**Detection:** `iosCompliancePolicy.deviceThreatProtectionEnabled` AND `passcodeRequired`; `androidCompliancePolicy.deviceThreatProtectionEnabled` AND root detection.
**Coverage:** **Gap.** File `feat: INTUNE-COMPLIANCE-JAILBREAK-001`.

### 1.6 Antivirus + firewall required (Windows)

**Intent:** Windows compliance policy requires AV + firewall enabled.
**Detection:** `windows10CompliancePolicy.antiVirusRequired` + `firewallEnabled` + `defenderEnabled`.
**Coverage:** Folds into `INTUNE-SECURITY-001` (general baseline). **Narrative refresh recommended** — explicit AV + firewall + Defender enumeration.

### 1.7 Devices without policy marked non-compliant

**Intent:** When no compliance policy is assigned to a device, default verdict is "non-compliant" (NOT "compliant by default" which is the historic insecure default).
**Detection:** Tenant setting `MarkDevicesWithNoComplianceAsCompliant = false`.
**Coverage:** ✅ `INTUNE-COMPLIANCE-001`.

## 2. Configuration profiles + baselines

### 2.1 Microsoft security baselines applied

**Intent:** Microsoft baselines (Windows 10/11, Edge, Microsoft 365 Apps, Intune Configuration Manager) applied for managed device populations.
**Detection:** `GET /deviceManagement/intents` — verify baseline templates assigned + applied.
**Pitfalls:** Default enrollment doesn't auto-apply baselines; explicit assignment required.
**Coverage:** **Gap.** File `feat: INTUNE-BASELINE-APPLIED-001`.

### 2.2 Baseline drift monitored

**Intent:** Default vs current state of applied baselines tracked. Microsoft updates baselines (typically annually); applied-but-not-updated baselines drift.
**Detection:** Per-intent `templateVersion` vs latest available; `recommendedSettings` vs current.
**Coverage:** **Gap (low priority).** File `feat: INTUNE-BASELINE-DRIFT-001`.

### 2.3 Settings catalog used for granular control

**Intent:** Modern tenants use Settings Catalog (`/deviceManagement/configurationPolicies`) over legacy templates (`/deviceManagement/deviceConfigurations`) for granular control.
**Detection:** Inventory both surfaces; flag tenants exclusively on legacy templates.
**Coverage:** **Gap (low priority).** File `feat: INTUNE-SETTINGS-CATALOG-001`.

### 2.4 Profiles assigned + reporting clean

**Intent:** Configuration profiles have assignments + recent device-state reports show no widespread "error" or "conflict" status.
**Detection:** Per-profile `assignments` populated; `deviceConfigurationDeviceStateSummaries` confirms clean status.
**Coverage:** **Gap.** File `feat: INTUNE-CONFIG-PROFILE-HEALTH-001`.

### 2.5 FIPS-validated cryptography enforced

**Coverage:** ✅ `INTUNE-FIPS-001`.

### 2.6 PowerShell execution policy restricted

**Coverage:** ✅ `INTUNE-MOBILECODE-001`.

### 2.7 WiFi enterprise authentication

**Coverage:** ✅ `INTUNE-WIFI-001`.

## 3. App Protection Policies (MAM)

The most under-covered area in the existing CheckID Intune namespace. Six gaps in this section.

### 3.1 MAM for unmanaged devices (BYOD without enrollment)

**Intent:** Users on personal (un-enrolled) devices accessing corporate data go through App Protection Policies that wrap Office apps with corporate data controls (PIN, save-as restrictions, copy-paste restrictions).
**Detection:** `GET /deviceAppManagement/managedAppPolicies` and per-platform protections:
- `iosManagedAppProtections` — iOS-specific MAM
- `androidManagedAppProtections` — Android-specific MAM
- `windowsManagedAppProtections` — emerging Windows MAM
- Per-policy `assignments` + `apps` populated

**Pitfalls:** MAM is the modern solution for "managed apps on unmanaged devices." Tenants often configure MDM (full device management) and skip MAM, leaving BYOD scenarios uncovered.
**Coverage:** **Gap.** File `feat: INTUNE-MAM-PRESENCE-001`.

### 3.2 PIN required + complexity + retry limits

**Intent:** MAM-protected apps require PIN with complexity (4+ digits, no simple sequences) and finite retry attempts before app data wipe.
**Detection:** Per-MAM-policy:
- `pinRequired = true`
- `minimumPinLength` ≥ 4
- `simplePinBlocked = true`
- `pinRetryLimit` ≤ 5

**Coverage:** **Gap.** File `feat: INTUNE-MAM-PIN-001`.

### 3.3 Conditional launch (jailbreak / OS version / threat level)

**Intent:** MAM-protected apps enforce conditional launch checks: block app launch if device is jailbroken, OS below minimum, or device threat level too high.
**Detection:** Per-MAM-policy `deviceComplianceRequired` + `disableAppPinIfDevicePinIsSet` + `deviceThreatProtectionRequiredSecurityLevel`.
**Coverage:** **Gap.** File `feat: INTUNE-MAM-CONDITIONAL-LAUNCH-001`.

### 3.4 Data transfer restrictions (block save-as, block paste)

**Intent:** MAM-protected apps cannot save corporate data outside managed apps; cannot paste corporate data to non-managed apps.
**Detection:** Per-MAM-policy:
- `saveAsBlocked = true`
- `allowedOutboundDataTransferDestinations = managedApps`
- `allowedInboundDataTransferSources = managedApps`
- `allowedOutboundClipboardSharingLevel = managedAppsWithPasteIn` (or stricter)

**Coverage:** **Gap.** File `feat: INTUNE-MAM-DATA-TRANSFER-001`.

### 3.5 Selective wipe on offboarding

**Intent:** When a user offboards, MAM corporate data on personal device is selectively wiped (without affecting personal data).
**Detection:** Procedural — confirm process exists and uses `wipeManagedAppRegistrationsByDeviceTag` or similar.
**Coverage:** **Gap (procedural-flavored).** File `feat: INTUNE-MAM-SELECTIVE-WIPE-001` with documented "best-effort detection" caveat.

### 3.6 Required apps for MAM enrollment

**Intent:** Tenant defines which apps must be MAM-enrolled (typically Office apps + Outlook + OneDrive) — not just available, but required.
**Detection:** Per-MAM-policy `apps` block — verify required apps are listed.
**Coverage:** Folds into 3.1 — same control surface.

## 4. Conditional Access integration

### 4.1 "Require device compliance" CA control

**Intent:** CA policies bind to Intune compliance evaluation via `grantControls.builtInControls = ['compliantDevice']`. Without this CA, Intune compliance has no enforcement teeth.
**Coverage:** Cross-domain to #327 §1.7 (`CA-DEVICE-001`, `CA-DEVICE-002`, `CA-REMOTEDEVICE-001`). Single CheckID; documented overlap.

### 4.2 "Require Hybrid Entra Join" for desktop scenarios

**Intent:** Tenants using hybrid AD federation can require Hybrid Entra Joined devices for desktop access.
**Coverage:** Cross-domain to #327 §1.7.

### 4.3 "Require approved client app" for mobile

**Intent:** Mobile CA targets `grantControls.builtInControls = ['approvedApplication']` — only Microsoft-approved apps (Outlook, OneDrive, Teams, Office mobile) can authenticate. Native iOS Mail blocked.
**Detection:** CA policy targeting iOS/Android with `approvedApplication` grant control.
**Coverage:** Cross-domain to #327 §2.1 — single CheckID `CA-MOBILE-MAM-001`.

### 4.4 "Require app protection policy" alternative

**Intent:** Modern alternative to "Require approved client app" — same intent, finer-grained. Tenants choose one OR the other; not both.
**Coverage:** Folds into 4.3.

## 5. Autopilot + enrollment

### 5.1 Autopilot deployment profiles configured

**Intent:** Windows new-device provisioning uses Autopilot profiles, ensuring enrollment + baseline application happen automatically at first boot.
**Detection:** `GET /deviceManagement/windowsAutopilotDeploymentProfiles` populated.
**Coverage:** ✅ partial via `INTUNE-AUTODISC-001` (automated enrollment). **Narrative refresh recommended** — explicit Autopilot framing.

### 5.2 Enrollment Status Page (ESP) configured

**Intent:** ESP shows users provisioning progress + blocks user sign-in until baseline apps + policies install. Without ESP, users can sign in to a half-provisioned device.
**Detection:** `GET /deviceManagement/deviceEnrollmentConfigurations` — filter `@odata.type` = `windows10EnrollmentCompletionPageConfiguration`.
**Coverage:** **Gap.** File `feat: INTUNE-AUTOPILOT-ESP-001`.

### 5.3 Device enrollment manager accounts inventoried

**Intent:** DEM accounts (single account that enrolls many devices) are inventoried + role-restricted. Shared DEM accounts are anti-pattern.
**Detection:** `/deviceManagement/deviceEnrollmentConfigurations` for DEM-related entries; cross-reference with role assignments.
**Coverage:** **Gap (low priority).** File `feat: INTUNE-DEM-001`.

### 5.4 Co-management policies (hybrid SCCM + Intune)

**Intent:** Tenants in hybrid SCCM + Intune topology have explicit co-management policy defining workload ownership (Intune for compliance, SCCM for legacy app deployment, etc.).
**Detection:** `comanagementSettings` properties.
**Coverage:** **Gap (low priority — most modern tenants are cloud-only).** File `feat: INTUNE-COMANAGEMENT-001`.

### 5.5 Personal device enrollment blocked by default

**Coverage:** ✅ `INTUNE-ENROLL-001`, ✅ `INTUNE-ENROLLMENT-001`.

### 5.6 Multi-Admin Approval for destructive operations

**Intent:** Multi-Admin Approval (MAA) for irreversible operations (mass device wipe, mass policy delete) — adds approval-flow gate to prevent rogue admin damage.
**Coverage:** ✅ `INTUNE-MAA-001`.

### 5.7 Mass device wipe detection

**Intent:** Detection of unusual mass device wipe activity (could be admin error, could be attacker post-compromise).
**Coverage:** ✅ `INTUNE-WIPEAUDIT-001`.

## 6. Anti-patterns (deliberate detection)

### 6.1 Compliance policy assigned to "no users"

**Intent:** Policy with no assignments is dead config. Effectively unassigned.
**Coverage:** Folds into 1.2 narrative.

### 6.2 "Mark as compliant if no policy assigned" enabled

**Intent:** Tenant default that bypasses every device's compliance evaluation. Effectively makes "Require compliant device" CA control useless.
**Coverage:** ✅ `INTUNE-COMPLIANCE-001` (verifies the inverse).

### 6.3 MAM policy without "Block save as" while allowing managed apps to access corporate data

**Coverage:** Folds into 3.4 narrative.

### 6.4 Configuration profile in "report-only" but expected to enforce

**Intent:** Profiles with reporting-only flag set persist beyond test-window. Should be enforcing.
**Detection:** Per-profile flags — flag profiles set to report-only > 30 days.
**Coverage:** **Gap (low priority).** File `feat: INTUNE-CONFIG-REPORT-ONLY-STALE-001`.

### 6.5 Security baselines un-applied

**Coverage:** Folds into 2.1.

### 6.6 Autopilot deployment profile permitting "Allow user to skip OOBE pages"

**Intent:** Autopilot profiles that allow skipping crucial OOBE pages (privacy review, EULA) leave users in inconsistent provisioning state.
**Detection:** Per-profile `outOfBoxExperienceSettings` — flag permissive skip settings.
**Coverage:** **Gap (low priority).** File `feat: INTUNE-AUTOPILOT-OOBE-SKIP-001`.

### 6.7 RBAC role assignments without scope tags

**Intent:** Intune RBAC role assignments without scope tags grant broad cross-environment access. Scope tags constrain admin reach to specific device populations.
**Coverage:** ✅ `INTUNE-RBAC-001`.

### 6.8 VPN split tunneling

**Coverage:** ✅ `INTUNE-VPNCONFIG-001`.

### 6.9 Removable media unrestricted

**Coverage:** ✅ `INTUNE-REMOVABLEMEDIA-001`, ✅ `INTUNE-PORTSTORAGE-001`.

### 6.10 Always-On VPN missing for remote managed devices

**Coverage:** ✅ `INTUNE-REMOTEVPN-001`.

## Coverage matrix summary

| Pattern category | Total | Covered | Refresh | Gaps |
|---|---:|---:|---:|---:|
| Compliance policy fundamentals | 7 | 4 | 1 (1.6) | 4 (1.1, 1.2, 1.4, 1.5) |
| Configuration profiles + baselines | 7 | 3 | 0 | 3 (2.1, 2.2 low-pri, 2.4); 2.3 low-pri |
| App Protection Policies (MAM) | 6 | 0 | 0 | 5 (3.1-3.5); 3.6 folds |
| Conditional Access integration | 4 | 0 | 0 | 0 unique (all cross-domain to #327) |
| Autopilot + enrollment | 7 | 4 | 1 (5.1) | 3 (5.2, 5.3 low-pri, 5.4 low-pri) |
| Anti-patterns | 10 | 6 | 0 | 2 unique (6.4 low-pri, 6.6 low-pri); others fold |
| **Total** | **41 (31 unique)** | **17** | **2** | **11 net to file** |

(Plus 4 cross-spike CheckIDs already covered by #327's CA device-compliance / mobile-MAM checks.)

## Threat-pattern map

| Compromise pattern | Tradecraft | Primary control |
|---|---|---|
| Unmanaged BYOD data exfil | User saves corporate data to personal cloud / pastes to personal app | MAM data-transfer restrictions (3.4) + PIN + conditional launch (3.2, 3.3) |
| Jailbroken device with corporate data | Compromised mobile gains shell access; corporate data accessible | MAM conditional launch + jailbreak detection (3.3, 1.5) |
| Stale compliance policy → CA bypass | "Compliant by default" tenant setting; no policy = no signal | Mark-no-policy-as-non-compliant (1.7) ✅ |
| Per-platform coverage gap | Windows-only Intune deployment leaves mobile devices ungated by CA | Per-platform compliance policy completeness (1.1) |
| Half-provisioned device sign-in | User signs in to fresh device before baselines applied | Autopilot ESP blocks until provisioning complete (5.2) |
| Mass wipe by rogue admin | Insider threat or credential compromise → mass device wipe | Multi-Admin Approval + audit (5.6, 5.7) ✅ |
| OS-version-gated CVE exploitation | Old OS version compromised; user is on it | Minimum OS version + grace period (1.4) |
| Stale baseline drift | Microsoft updates baseline; tenant doesn't reapply | Baseline drift monitoring (2.2) |
| Counterfeit / unauthorized peripheral | USB malware delivery, removable storage exfil | Removable media + portable storage restrictions (6.9) ✅ |
| Personal account on corporate device → exfil | (cross-spike to #333 Tenant Restrictions v2) | Tenant Restrictions v2 from #327/#333 |

## Detection method appendix

### Primary: Microsoft Graph (`/deviceManagement` + `/deviceAppManagement`)

| Endpoint | Used for |
|---|---|
| `GET /deviceManagement/deviceCompliancePolicies` | Per-platform compliance policies (1.x) |
| `GET /deviceManagement/deviceCompliancePolicies/{id}/assignments` | Compliance assignment scope (1.2) |
| `GET /deviceManagement/configurationPolicies` | Settings Catalog policies (2.3) |
| `GET /deviceManagement/deviceConfigurations` | Legacy configuration profiles (2.x) |
| `GET /deviceManagement/intents` | Security baseline intents (2.1, 2.2) |
| `GET /deviceManagement/templates` | Built-in baseline templates |
| `GET /deviceAppManagement/managedAppPolicies` | MAM policies root |
| `GET /deviceAppManagement/iosManagedAppProtections` | iOS MAM (3.x) |
| `GET /deviceAppManagement/androidManagedAppProtections` | Android MAM (3.x) |
| `GET /deviceManagement/deviceEnrollmentConfigurations` | ESP, enrollment restrictions (5.2, 5.3) |
| `GET /deviceManagement/windowsAutopilotDeploymentProfiles` | Autopilot profiles (5.1) |
| `GET /deviceManagement/managedDevices?$select=complianceState,osVersion,encryption...` | Device-state sample (1.x verification) |

### Edge cases

1. **Per-platform `@odata.type` discrimination.** Policies are returned in a single collection but typed by `@odata.type`. Detection must filter by type to evaluate per-platform coverage. Easy to miss platforms when policy count > 0 but specific platform absent.

2. **Most-restrictive-wins for multiple compliance policies per platform.** Intune evaluates "most restrictive" so all compliance policies must be reasonable. Detection should evaluate the EFFECTIVE policy, not just the existence of any policy.

3. **`MarkDevicesWithNoComplianceAsCompliant` is the foundational tenant gate.** When `true`, every other compliance check is partially defeated (devices without policy get free pass). When `false`, no-policy = non-compliant + CA blocks. This is the most consequential single bit in the Intune compliance picture.

4. **Configuration policy / device config profile / intent.** Three different shapes for similar concepts:
   - Settings Catalog (`configurationPolicies`) — modern, granular
   - Legacy templates (`deviceConfigurations`) — legacy, limited
   - Intents (`intents`) — security baselines
   Reconciliation requires reading all three.

5. **Security baseline state requires version comparison.** Applied template ID vs latest available — drift = old template. Microsoft updates baselines (typically annually for Windows 10/11). Detection should compare `templateVersion` against `availableTemplateVersions`.

6. **MAM vs MDM decision is org-strategy.** MAM (App Protection) for unmanaged devices; MDM (full enrollment) for managed. Some scenarios use BOTH (corporate-issued device with MDM + MAM for extra app-level controls). Detection should answer: "given the org's BYOD posture, is the right path covered."

7. **Autopilot ESP blocking timeout.** ESP can be configured to allow sign-in after timeout even if provisioning incomplete. Detection should check `blockDeviceSetupRetryByUser = true` (force completion).

8. **Multi-Admin Approval scope.** MAA covers a defined set of operations (mass wipe, mass delete). Doesn't cover individual-device wipe by default. Detection should verify scoped-operations list includes destructive operations.

## Spawned issues to file

**Gap CheckIDs (`feat:` issues, 11 net):**

1. `feat: INTUNE-COMPLIANCE-PLATFORM-001` — per-platform compliance policy completeness (1.1)
2. `feat: INTUNE-COMPLIANCE-ASSIGNMENT-001` — compliance policy assigned to broad-coverage group (1.2)
3. `feat: INTUNE-COMPLIANCE-OS-VERSION-001` — minimum OS version + grace period (1.4)
4. `feat: INTUNE-COMPLIANCE-JAILBREAK-001` — jailbreak / root detection (1.5)
5. `feat: INTUNE-BASELINE-APPLIED-001` — Microsoft security baselines applied (2.1)
6. `feat: INTUNE-BASELINE-DRIFT-001` — baseline drift detection (2.2) — *low priority*
7. `feat: INTUNE-SETTINGS-CATALOG-001` — Settings Catalog vs legacy templates (2.3) — *low priority*
8. `feat: INTUNE-CONFIG-PROFILE-HEALTH-001` — profiles assigned + reporting clean (2.4)
9. `feat: INTUNE-MAM-PRESENCE-001` — MAM policies for unmanaged devices (3.1, 3.6 fold-in)
10. `feat: INTUNE-MAM-PIN-001` — MAM PIN required + complexity + retry (3.2)
11. `feat: INTUNE-MAM-CONDITIONAL-LAUNCH-001` — MAM conditional launch (3.3)
12. `feat: INTUNE-MAM-DATA-TRANSFER-001` — MAM data transfer restrictions (3.4)
13. `feat: INTUNE-MAM-SELECTIVE-WIPE-001` — selective wipe on offboarding (3.5) — *procedural-flavored*
14. `feat: INTUNE-AUTOPILOT-ESP-001` — Enrollment Status Page configured (5.2)
15. `feat: INTUNE-DEM-001` — Device Enrollment Manager accounts inventoried (5.3) — *low priority*
16. `feat: INTUNE-COMANAGEMENT-001` — co-management policies (5.4) — *low priority*
17. `feat: INTUNE-CONFIG-REPORT-ONLY-STALE-001` — report-only profiles > 30 days (6.4) — *low priority*
18. `feat: INTUNE-AUTOPILOT-OOBE-SKIP-001` — Autopilot OOBE skip restrictions (6.6) — *low priority*

**Cross-spike (single CheckID, document overlap):**

- `CA-DEVICE-001/-002/-REMOTEDEVICE-001` from #327 §1.7 covers 4.1 + 4.2 — device compliance integration
- `CA-MOBILE-MAM-001` from #327 §2.1 covers 4.3 + 4.4 — approved app / MAM CA control

**Narrative refresh (`chore:` issues, 2):**

- `chore: refresh INTUNE-SECURITY-001 narrative` — explicit AV + firewall + Defender enumeration; per-platform-completeness pairing
- `chore: refresh INTUNE-AUTODISC-001 narrative` — explicit Autopilot framing

## Out of scope (handled by sibling spikes)

- Defender for Endpoint integration (separate product, not Intune-native)
- Windows Update for Business policies (touched lightly via `INTUNE-UPDATE-001`)
- macOS / Linux Intune deeper specifics (touched lightly; primary focus is Windows + iOS + Android)
- Conditional Access for device compliance — #327
- WHfB cloud trust deployment cross-spike — #330 §1.4 (`ENTRA-AUTHMETHOD-WHFB-001` proposed there)
- Tenant Restrictions v2 client-agent enforcement — #333 (proposed in audit)
- Sign-in log analytics for device-compliance failure patterns — runtime telemetry, future track
