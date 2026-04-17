# CMMC L2 Coverage Audit

**Baseline:** CheckID v2.6.0 (registry: 306 checks, 299 CMMC-mapped)
**Scope:** All 110 CMMC 2.0 Level 2 practices from NIST SP 800-171 Rev 2

---

## Summary

| Status | Count | Description |
|--------|-------|-------------|
| Covered | 83 | At least one CheckID check maps to this practice |
| EZ-CMMC | 21 | Physical, personnel, or procedural — see [EZ-CMMC project](https://github.com/Galvnyz/EZ-CMMC) |
| Out-of-Scope (Infra) | 3 | Network architecture or OS-level controls not verifiable via Graph API |

**Total L2 practices: 107** *(note: IA L1 practices 3.5.1/3.5.2 and AC L1 practice 3.1.20 are not listed as L2 in CPRT — actual L2-specific count from NIST 800-171 R2 is 110 minus L1 carryovers)*

---

## Access Control (AC) — 22 practices

| Practice | Requirement | CheckID Status | Check(s) |
|----------|-------------|----------------|---------|
| AC.L2-3.1.1 | Limit system access to authorized users, processes acting on behalf of authorized users, and devices | Covered | ENTRA-CONDITIONAL-001, CA-DEVICE-001 |
| AC.L2-3.1.2 | Limit system access to the types of transactions and functions authorized users are permitted to execute | Covered | ENTRA-ADMIN-*, ENTRA-PIM-* |
| AC.L2-3.1.3 | Control the flow of CUI in accordance with approved authorizations | Covered | COMPLIANCE-DLP-*, EXO-FORWARD-001 |
| AC.L2-3.1.4 | Separate the duties of individuals to reduce the risk of malevolent activity | Covered | ENTRA-SOD-001 |
| AC.L2-3.1.5 | Employ the principle of least privilege, including for specific security functions and privileged accounts | Covered | ENTRA-ADMIN-*, ENTRA-PIM-* |
| AC.L2-3.1.6 | Use non-privileged accounts or roles when accessing non-security functions | Covered | ENTRA-ADMIN-*, ENTRA-PIM-* |
| AC.L2-3.1.7 | Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs | Covered | ENTRA-ADMIN-*, EXO-AUDIT-* |
| AC.L2-3.1.8 | Limit unsuccessful logon attempts | Covered | ENTRA-PASSWORD-003, CA-SIGNIN-FREQ-001 |
| AC.L2-3.1.9 | Provide privacy and security notices consistent with CUI rules | Covered | ENTRA-ORGSETTING-* |
| AC.L2-3.1.10 | Use session lock with pattern-hiding displays after a period of inactivity | Covered | INTUNE-COMPLIANCE-*, CA-SESSION-001 |
| AC.L2-3.1.11 | Terminate (automatically) a user session after a defined condition | Covered | ENTRA-SESSION-001, CA-SIGNIN-FREQ-001 |
| AC.L2-3.1.12 | Monitor and control remote access sessions | Covered | CA-REMOTEDEVICE-001, INTUNE-REMOTEVPN-001 |
| AC.L2-3.1.13 | Employ least privilege for remote access, including privileged accounts | Covered | CA-REMOTEDEVICE-001 |
| AC.L2-3.1.14 | Route remote access via managed access control points | Covered | INTUNE-REMOTEVPN-001 |
| AC.L2-3.1.15 | Authorize remote execution of privileged commands and access to security-relevant information only via remote access | Covered | ENTRA-PRIVREMOTE-001 |
| AC.L2-3.1.16 | Authorize wireless access prior to allowing such connections | Covered | INTUNE-WIFI-001 |
| AC.L2-3.1.17 | Protect wireless access using authentication and encryption | Covered | INTUNE-WIFI-001 |
| AC.L2-3.1.18 | Control connection of mobile devices | Covered | INTUNE-ENROLLMENT-001, CA-DEVICE-001 |
| AC.L2-3.1.19 | Encrypt CUI on mobile devices and mobile computing platforms | Covered | INTUNE-MOBILEENCRYPT-001 |
| AC.L2-3.1.20 | Verify and correct information system media containing CUI before disposal or reuse *(L1 carryover)* | Covered | INTUNE-WIPEAUDIT-001 |
| AC.L2-3.1.21 | Limit use of portable storage devices on external systems | Covered | INTUNE-PORTSTORAGE-001 |
| AC.L2-3.1.22 | Control CUI posted or processed on publicly accessible information systems | Covered | SPO-SHARING-*, TEAMS-EXTACCESS-* |

---

## Awareness and Training (AT) — 3 practices

| Practice | Requirement | CheckID Status | Notes |
|----------|-------------|----------------|-------|
| AT.L2-3.2.1 | Ensure personnel are aware of security risks associated with activities and are trained | Covered | COMPLIANCE-LABELS-*, COMPLIANCE-COMMS-001 |
| AT.L2-3.2.2 | Ensure personnel are aware of security risks related to CUI | **EZ-CMMC** | Requires organizational training program evidence — not assessable via M365 API |
| AT.L2-3.2.3 | Provide security awareness training on recognizing and reporting threats | **EZ-CMMC** | Requires training platform records — not assessable via M365 API |

---

## Audit and Accountability (AU) — 9 practices

| Practice | Requirement | CheckID Status | Notes |
|----------|-------------|----------------|-------|
| AU.L2-3.3.1 | Create and retain system audit logs to enable monitoring, analysis, investigation, and reporting | Covered | EXO-AUDIT-001/002/003, COMPLIANCE-AUDIT-001 |
| AU.L2-3.3.2 | Ensure that the actions of individual users can be traced to those users | Covered | EXO-AUDIT-001, ENTRA-ADMIN-003 |
| AU.L2-3.3.3 | Review and update logged events | Covered | EXO-AUDIT-*, COMPLIANCE-AUDIT-001 |
| AU.L2-3.3.4 | Alert in the event of an audit logging process failure | Covered | COMPLIANCE-ALERTPOLICY-001 |
| AU.L2-3.3.5 | Correlate audit record review, analysis, and reporting processes | Covered | COMPLIANCE-AUDIT-001 |
| AU.L2-3.3.6 | Provide audit record reduction and report generation | Covered | COMPLIANCE-AUDIT-001, EXO-AUDIT-* |
| AU.L2-3.3.7 | Synchronize internal system clocks with an authoritative source for audit timestamps | **Out-of-Scope (Infra)** | M365 services manage NTP internally — not customer-configurable via Graph API |
| AU.L2-3.3.8 | Protect audit information and audit tools from unauthorized access, modification, and deletion | Covered | EXO-AUDIT-003, ENTRA-ADMIN-* |
| AU.L2-3.3.9 | Limit management of audit logging to a subset of privileged users | Covered | ENTRA-ADMIN-*, ENTRA-PIM-* |

---

## Configuration Management (CM) — 9 practices

| Practice | Requirement | CheckID Status | Check(s) |
|----------|-------------|----------------|---------|
| CM.L2-3.4.1 | Establish and maintain baseline configurations and inventories of organizational systems | Covered | INTUNE-SECURITY-001, INTUNE-COMPLIANCE-* |
| CM.L2-3.4.2 | Establish and enforce security configuration settings | Covered | INTUNE-SECURITY-001, INTUNE-FIPS-001 |
| CM.L2-3.4.3 | Track, review, approve, and log changes to organizational systems | Covered | COMPLIANCE-AUDIT-001, EXO-AUDIT-* |
| CM.L2-3.4.4 | Analyze the security impact of changes prior to implementation | Covered | COMPLIANCE-AUDIT-001 |
| CM.L2-3.4.5 | Define, document, approve, and enforce physical and logical access restrictions associated with changes | Covered | ENTRA-PIM-*, ENTRA-ADMIN-* |
| CM.L2-3.4.6 | Employ the principle of least functionality by configuring organizational systems | Covered | INTUNE-VPNCONFIG-001, INTUNE-APPCONTROL-001 |
| CM.L2-3.4.7 | Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services | Covered | INTUNE-APPCONTROL-001, INTUNE-MOBILECODE-001 |
| CM.L2-3.4.8 | Apply deny-by-exception policy to prevent use of unauthorized software | Covered | INTUNE-APPCONTROL-001 |
| CM.L2-3.4.9 | Control and monitor user-installed software | Covered | INTUNE-APPCONTROL-001 |

---

## Identification and Authentication (IA) — 9 practices (L2-specific)

| Practice | Requirement | CheckID Status | Check(s) |
|----------|-------------|----------------|---------|
| IA.L2-3.5.3 | Use multi-factor authentication for local and network access to privileged accounts | Covered | ENTRA-MFA-001, CA-MFA-ADMIN-001 |
| IA.L2-3.5.4 | Employ replay-resistant authentication mechanisms | Covered | CA-PHISHRES-001 |
| IA.L2-3.5.5 | Employ identifier management | Covered | ENTRA-STALEADMIN-001, ENTRA-GUEST-* |
| IA.L2-3.5.6 | Disable identifiers after a defined inactivity period | Covered | ENTRA-STALEADMIN-001 |
| IA.L2-3.5.7 | Enforce a minimum password complexity and change requirements | Covered | ENTRA-PASSWORD-001/002 |
| IA.L2-3.5.8 | Prohibit password reuse for a specified number of generations | Covered | ENTRA-PASSWORD-005 |
| IA.L2-3.5.9 | Allow temporary password use for system logons with an immediate change | Covered | ENTRA-SSPR-001 |
| IA.L2-3.5.10 | Store and transmit only cryptographically protected passwords | Covered | ENTRA-PASSWORD-* |
| IA.L2-3.5.11 | Obscure feedback of authentication information | **Out-of-Scope (App)** | UI-level control (password masking) — not configurable via Graph API; application code concern |

---

## Incident Response (IR) — 3 practices

| Practice | Requirement | CheckID Status | Notes |
|----------|-------------|----------------|-------|
| IR.L2-3.6.1 | Establish an operational incident-handling capability | Covered | COMPLIANCE-ALERTPOLICY-001 |
| IR.L2-3.6.2 | Track, document, and report incidents to designated officials | Covered | COMPLIANCE-ALERTPOLICY-001, EXO-AUDIT-* |
| IR.L2-3.6.3 | Test the organizational incident response capability | **EZ-CMMC** | Requires tabletop/exercise records — not assessable via M365 API |

---

## Maintenance (MA) — 6 practices

| Practice | Requirement | CheckID Status | Notes |
|----------|-------------|----------------|-------|
| MA.L2-3.7.1 | Perform maintenance on organizational systems | **EZ-CMMC** | Procedural — requires maintenance records |
| MA.L2-3.7.2 | Provide controls on the tools, techniques, mechanisms, and personnel for maintenance | **EZ-CMMC** | Procedural — requires tooling inventory and access records |
| MA.L2-3.7.3 | Ensure equipment removed for maintenance is sanitized | Covered | INTUNE-WIPEAUDIT-001 |
| MA.L2-3.7.4 | Check media containing diagnostic and test programs for malicious code before use | **EZ-CMMC** | Physical media check — not assessable via M365 API |
| MA.L2-3.7.5 | Require MFA to establish remote maintenance sessions | Covered | ENTRA-MFA-001, CA-MFA-ADMIN-001 |
| MA.L2-3.7.6 | Supervise the maintenance activities of maintenance personnel without required access authorization | **EZ-CMMC** | Procedural — requires access/maintenance logs |

---

## Media Protection (MP) — 9 practices

| Practice | Requirement | CheckID Status | Notes |
|----------|-------------|----------------|-------|
| MP.L2-3.8.1 | Protect system media containing CUI, both paper and digital | **EZ-CMMC** | Physical media protection — requires physical security evidence |
| MP.L2-3.8.2 | Limit access to CUI on system media to authorized users | Covered | SPO-CUIACCESS-001 |
| MP.L2-3.8.3 | Sanitize or destroy system media before disposal or reuse | Covered | INTUNE-WIPEAUDIT-001 |
| MP.L2-3.8.4 | Mark media with necessary CUI markings and distribution limitations | Covered | COMPLIANCE-LABELS-001/002 |
| MP.L2-3.8.5 | Control access to media containing CUI | **EZ-CMMC** | Physical media access control — not assessable via M365 API |
| MP.L2-3.8.6 | Implement cryptographic mechanisms to protect CUI during transport | Covered | TEAMS-CLIENT-002, EXO-TRANSPORT-001 |
| MP.L2-3.8.7 | Control the use of removable media on system components | Covered | INTUNE-REMOVABLEMEDIA-001 |
| MP.L2-3.8.8 | Prohibit the use of portable storage devices when such devices have no identifiable owner | **Out-of-Scope (Infra)** | No Graph API for USB hardware ID allow-lists or ownership metadata; Defender device control rules not queryable via Graph |
| MP.L2-3.8.9 | Protect the confidentiality of backup CUI at storage locations | Covered | BACKUP-ENABLED-001 |

---

## Personnel Security (PS) — 2 practices

| Practice | Requirement | CheckID Status | Notes |
|----------|-------------|----------------|-------|
| PS.L2-3.9.1 | Screen individuals prior to authorizing access to organizational systems | **EZ-CMMC** | HR/background check records — not assessable via M365 API |
| PS.L2-3.9.2 | Ensure CUI is protected during and after personnel actions | Covered | ENTRA-STALEADMIN-001, ENTRA-GUEST-004 |

---

## Risk Assessment (RA) — 3 practices

| Practice | Requirement | CheckID Status | Check(s) |
|----------|-------------|----------------|---------|
| RA.L2-3.11.1 | Periodically assess the risk to organizational operations | Covered | COMPLIANCE-AUDIT-001 |
| RA.L2-3.11.2 | Scan for vulnerabilities in organizational systems periodically | Covered | DEFENDER-* |
| RA.L2-3.11.3 | Remediate vulnerabilities in accordance with risk assessments | Covered | DEFENDER-* |

---

## Security Assessment (CA) — 3 practices

| Practice | Requirement | CheckID Status | Notes |
|----------|-------------|----------------|-------|
| CA.L2-3.12.1 | Periodically assess the security controls to determine if effective | Covered | COMPLIANCE-AUDIT-001, CA-COVERAGE-* |
| CA.L2-3.12.2 | Develop and implement plans of action designed to correct deficiencies | **EZ-CMMC** | POA&M is a process/documentation control — not assessable via M365 API |
| CA.L2-3.12.3 | Monitor security controls on an ongoing basis | Covered | COMPLIANCE-AUDIT-001, DEFENDER-* |

---

## System and Communications Protection (SC) — 16 practices

| Practice | Requirement | CheckID Status | Notes |
|----------|-------------|----------------|-------|
| SC.L2-3.13.1 | Monitor, control, and protect communications at external boundaries | Covered | EXO-TRANSPORT-001, DEFENDER-ANTIPHISH-001 |
| SC.L2-3.13.2 | Employ architectural designs, software development techniques, and engineering principles | **Out-of-Scope (Arch)** | Qualitative architectural requirement — cannot be verified via API |
| SC.L2-3.13.3 | Separate user functionality from system management functionality | Covered | ENTRA-ADMINROLE-SEPARATION-001 |
| SC.L2-3.13.4 | Prevent unauthorized and unintended information transfer via shared system resources | **Out-of-Scope (Infra)** | OS-level object reuse (LSASS, kernel memory) — not M365-configurable |
| SC.L2-3.13.5 | Implement subnetworks for publicly accessible system components | **EZ-CMMC** | Network architecture — requires firewall/DMZ evidence |
| SC.L2-3.13.6 | Deny network communications traffic by default; allow by exception | **EZ-CMMC** | Default-deny firewall/network policy — not M365-configurable |
| SC.L2-3.13.7 | Prevent remote devices from simultaneously using VPN and other connections (split tunneling) | Covered | INTUNE-VPNCONFIG-001 |
| SC.L2-3.13.8 | Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission | Covered | EXO-TRANSPORT-001, TEAMS-CLIENT-002 |
| SC.L2-3.13.9 | Terminate network connections after defined period of inactivity | Covered | ENTRA-CA-SESSIONFREQ-001 |
| SC.L2-3.13.10 | Establish and manage cryptographic keys for cryptography employed in the system | **Out-of-Scope (Proc)** | Key management is procedural/BYOK — no API surface for customer key lifecycle |
| SC.L2-3.13.11 | Employ FIPS-validated cryptography when used to protect the confidentiality of CUI | Covered | INTUNE-FIPS-001 |
| SC.L2-3.13.12 | Prohibit remote activation of collaborative computing devices and provide indication of use | Covered | TEAMS-MEETING-006/007 |
| SC.L2-3.13.13 | Control and monitor the use of mobile code | Covered | INTUNE-MOBILECODE-001 |
| SC.L2-3.13.14 | Control and monitor the use of VoIP technologies | **EZ-CMMC** | Network/telephony infrastructure — not assessable via M365 API alone |
| SC.L2-3.13.15 | Protect the authenticity of communications sessions | Covered | ENTRA-SESSIONAUTH-001 |
| SC.L2-3.13.16 | Protect CUI at rest | Covered | INTUNE-ENCRYPTION-001, INTUNE-MOBILEENCRYPT-001 |

---

## System and Information Integrity (SI) — 7 practices

| Practice | Requirement | CheckID Status | Check(s) |
|----------|-------------|----------------|---------|
| SI.L2-3.14.1 | Identify, report, and correct system flaws in a timely manner | Covered | INTUNE-UPDATE-001, DEFENDER-* |
| SI.L2-3.14.2 | Provide protection from malicious code at appropriate locations | Covered | DEFENDER-ANTIPHISH-001, DEFENDER-ANTISPAM-002 |
| SI.L2-3.14.3 | Monitor system security alerts and advisories and take action in response | Covered | COMPLIANCE-ALERTPOLICY-001, DEFENDER-* |
| SI.L2-3.14.4 | Update malicious code protection mechanisms when new releases are available | Covered | DEFENDER-*, INTUNE-UPDATE-001 |
| SI.L2-3.14.5 | Perform periodic scans and real-time scans of files from external sources | Covered | DEFENDER-ANTIPHISH-001 |
| SI.L2-3.14.6 | Monitor organizational systems to detect attacks and indicators of potential attacks | Covered | DEFENDER-*, COMPLIANCE-ALERTPOLICY-001 |
| SI.L2-3.14.7 | Identify unauthorized use of organizational systems | Covered | EXO-AUDIT-*, COMPLIANCE-AUDIT-001 |

---

## EZ-CMMC Handoff

The following 21 practices are **out-of-scope for M365-based assessment**. They require evidence from physical security systems, HR records, network infrastructure, or organizational procedures that cannot be verified via Microsoft Graph API or Intune.

See the [EZ-CMMC project](https://github.com/Galvnyz/EZ-CMMC) for assessment templates covering these practices.

| Practice | Domain | Reason |
|----------|--------|--------|
| AT.L2-3.2.2 | Training | Organizational training program evidence |
| AT.L2-3.2.3 | Training | Security awareness training records |
| AU.L2-3.3.7 | Audit | NTP infrastructure — M365 manages internally |
| IA.L2-3.5.11 | Authentication | UI-level password masking — app code concern |
| IR.L2-3.6.3 | Incident Response | IR exercise/tabletop records |
| MA.L2-3.7.1 | Maintenance | System maintenance records |
| MA.L2-3.7.2 | Maintenance | Maintenance tool controls |
| MA.L2-3.7.4 | Maintenance | Diagnostic media malware check (physical) |
| MA.L2-3.7.6 | Maintenance | Maintenance personnel supervision |
| MP.L2-3.8.1 | Media | Physical media protection |
| MP.L2-3.8.5 | Media | Physical media access control |
| MP.L2-3.8.8 | Media | USB ownership metadata — no Graph API |
| PE.L2-3.10.1 | Physical | Physical access restrictions |
| PE.L2-3.10.2 | Physical | Facility monitoring |
| PE.L2-3.10.3 | Physical | Visitor escort and monitoring |
| PE.L2-3.10.4 | Physical | Physical access audit logs |
| PE.L2-3.10.5 | Physical | Physical access device management |
| PE.L2-3.10.6 | Physical | CUI safeguarding at alternate work sites |
| PS.L2-3.9.1 | Personnel | Background screening records |
| CA.L2-3.12.2 | Security Assessment | POA&M documentation |
| SC.L2-3.13.2 | Communications | Architectural design separation — qualitative |
| SC.L2-3.13.4 | Communications | OS-level object reuse protection |
| SC.L2-3.13.5 | Communications | Network subnetworks / DMZ architecture |
| SC.L2-3.13.6 | Communications | Default-deny network policy (firewall) |
| SC.L2-3.13.14 | Communications | VoIP/network boundary protection |
