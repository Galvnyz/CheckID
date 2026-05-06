# Discovery report: ENTRA-SSPR-001 (#399) and the systemic stale-portal-path / false-automation classes of bug

**Date:** 2026-05-04
**Method:** Phase 1 inventory before any code changes or remediation decisions.
**Status:** Discovery complete. **No code changes made.** Decision points listed at end for direction.

---

## Data-flow context (added after secframe authority confirmed)

Per `scripts/Build-Registry.ps1` and `scripts/Build-Registry.py`:

```
data/scf-check-mapping.json       (source-of-truth: per-CheckID metadata, including portal paths for non-AZ checks)
       +
C:/git/secframe/SCF/scf.db        (source-of-truth: SCF + framework derivation)
       +
data/scf-framework-map.json       (which frameworks to include)
       +
data/framework-titles.json        (human-readable titles)
       +
data/az-assess-source-checks.json (source-of-truth: per-CheckID metadata for AZ-* checks)
       ↓
   data/registry.json              (BUILD OUTPUT — regenerated each build, do not hand-edit)
```

**Implications:**
- Hand-editing `data/registry.json` is wrong — it gets overwritten on next `Build-Registry.ps1` run.
- The 31 stale `Protection >` paths originate in **`data/scf-check-mapping.json`**.
- The 14 stale `Security >` paths and 4 stale `Users > Password reset` paths originate in **`data/az-assess-source-checks.json`** (concentrated in the `AZ-IDENTITY-*` namespace).
- The CIS M365 v6.0.1 benchmark in secframe (`Combined Profiles-CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.csv`) is the canonical upstream for portal paths in CIS-mapped checks. CIS itself uses `Entra ID > Authentication methods` 53 times vs `Protection >` only 2 times — so the stale paths in CheckID are mostly CheckID-side staleness, not faithful transcription of an outdated benchmark.

---

## Why this report exists

#399 was filed as a small follow-up to PR #397 (ENTRA-SSPR-001 rebadge). On first read, the research turned up two larger systemic issues that #399 is just one symptom of:

1. **Stale portal-path navigation** affecting **49 entries across two source files** (which propagate to `data/registry.json` on build).
2. **False `hasAutomatedCheck: true` claims** that the schema cannot detect, of which the original ENTRA-SSPR-001 was one example and at least one currently-shipping entry (`ENTRA-SSPR-002`) appears to be another.

This report inventories both classes of bug, ties them to known issues already in the backlog, and lists decision points without recommending an answer. **No remediation has been committed to.**

---

## Phase 1 — Inventory

### 1.1 Entra admin center navigation: ground truth (2026-05-04)

Per Microsoft Learn `entra-admin-center.md` (`updated_at: 2026-04-06`), the Entra admin center has **exactly five top-level product areas**:

| Top-level node | What's underneath |
|---|---|
| **Entra ID** | Users, groups, devices, applications, **Conditional Access**, **Multifactor authentication**, **Authentication methods**, **Password reset**, identity secure score, custom security attributes |
| **ID Protection** | Identity Protection dashboard, risk-based access policies, risky users, risky workload identities |
| **Identity Governance** | Entitlement management, access reviews, PIM, lifecycle workflows |
| **Verified ID** | Credentials |
| **Global Secure Access** | Private Access, Internet Access |

There is **no `Protection`** top-level node (only `ID Protection`, which scopes to risk-based policies).
There is **no `Security`** top-level node.
There is **no `Users` top-level node** (Users is under `Entra ID`).

Verified per-blade paths from Microsoft Learn (all docs `updated_at: 2026-02-13` to `2026-04-06`):

| Blade | Current path |
|---|---|
| Authentication methods → Registration campaign | `Entra admin center > Entra ID > Authentication methods > Registration campaign` |
| Authentication methods → Policies (auth method enablement) | `Entra admin center > Entra ID > Authentication methods > Policies` |
| Conditional Access → Policies | `Entra admin center > Entra ID > Conditional Access > Policies` |
| Conditional Access → Templates | `Entra admin center > Entra ID > Conditional Access > Create new policy from templates` |
| Password reset → Properties (None/Selected/All toggle) | `Entra admin center > Entra ID > Password reset > Properties` |
| Password reset → Authentication methods (legacy) | `Entra admin center > Entra ID > Password reset > Authentication methods` (deprecated for method enablement post-2025-09-30) |
| Password protection (banned passwords) | Under Authentication methods (the screenshot caption in Microsoft's doc shows it under "Authentication Methods") |

### 1.2 Stale-parent inventory (precise breakdown by source file)

Counts derived by parsing each JSON file directly (not regex against text):

| Source file | Stale `Protection >` | Stale `Security >` | Stale `Users > Password reset` | Deprecated MFA Service Settings blade | Total stale |
|---|---|---|---|---|---|
| `data/scf-check-mapping.json` | **31** | 0 | 0 | 0 | 31 |
| `data/az-assess-source-checks.json` | 0 | **14** | **4** | **1** (AZ-IDENTITY-031) | 19 |
| `data/registry.json` (build output) | 33 | 14 | 1 | 1 | 49 |

Source-file fix surface: **50 entries** total. (The slight count difference between source and registry — e.g., 31 vs 33 Protection in `scf-check-mapping.json` vs `registry.json` — likely reflects 2 entries where the build script adds derived fields containing the literal "Protection" string outside the `path`. To verify before any fix.)

**Pattern A — `Entra admin center > Protection > ...` (in `scf-check-mapping.json`):**
- 14 entries with `cisM365ControlId` (CIS-derived — should follow CIS M365 v6.0.1 source which uses `Entra ID >`)
- 17 entries without `cisM365ControlId` (CheckID-authored — needs manual verification)
- Sub-blades: Conditional Access (most), Authentication methods, Password protection, Password reset

**Pattern B — `Microsoft Entra admin center > Security > ...` (in `az-assess-source-checks.json`):**
- All 14 are `AZ-IDENTITY-*` (the population #386 wants to reconcile)
- Sub-blades: Conditional Access (10), Password protection (3), Authentication methods (1)

**Pattern C — `Microsoft Entra admin center > Users > Password reset > ...` (in `az-assess-source-checks.json`):**
- 4 entries, all `AZ-IDENTITY-*`
- Points at the legacy SSPR Authentication Methods page, which survives post-deprecation but lives under `Entra ID > Password reset > Authentication methods`, not `Users > ...`

**Pattern D — Deprecated blade (in `az-assess-source-checks.json`):**
- 1 entry: `AZ-IDENTITY-031` (`Microsoft Entra admin center > Security > Multifactor authentication > Service settings`) — both stale parent AND deprecated blade. Needs blade rework, not just a path fix.

**Same data also lives in the `steps` array** alongside `path`. Any fix needs to touch both fields per entry; the schema doesn't enforce consistency between them.

**CIS source comparison (secframe `Combined Profiles-CIS_Microsoft_365_Foundations_Benchmark_v6.0.1.csv`):**
- 53 occurrences of `expand 'Entra ID'` (current/correct)
- 2 occurrences of `expand 'Protection'` (stale, both within the same recommendation as `Entra ID >` audit instructions — internal CIS inconsistency)

So CIS itself is 96% current. CheckID's 31 stale `Protection >` paths are mostly CheckID-side staleness (carried over from older CIS versions or manually authored), not faithful transcription of an outdated benchmark.

### 1.3 Legacy MFA / SSPR deprecation exposure

**Background:** Microsoft announced in March 2023 that legacy MFA + legacy SSPR policies would be deprecated for managing authentication-method enablement on **2025-09-30** — that deadline has passed. After it, the legacy blades still render (so the navigation paths still resolve), but they no longer manage method enablement; the Auth Methods Policy is the source of truth.

**What survives in the legacy SSPR policy after migration** (per Microsoft Learn `concept-authentication-methods-manage.md`):

> - The **Number of methods required to reset** control (admins can continue to change this).
> - The SSPR administrator policy (admins can continue to register and use any methods listed under this policy).
> - Security questions (until a migration control is available).

**Registry entries pointing at deprecated legacy blades:**

| CheckID | What it claims to measure | Current portal path | Status of underlying blade post-2025-09-30 |
|---|---|---|---|
| AZ-IDENTITY-031 | "Allow users to remember MFA on devices they trust" | `Microsoft Entra admin center > Security > Multifactor authentication > Service settings` | **Deprecated** — this setting moved to Auth Methods Policy. Stale parent (`Security >`) AND stale blade. |
| AZ-IDENTITY-005 | "Number of methods required to reset" (set to 2) | `Microsoft Entra admin center > Users > Password reset > Authentication methods` | **Survives** post-deprecation per Microsoft (one of the explicitly-preserved controls). But stale parent (`Users >` is not a top-level node — Users is under Entra ID). |
| ENTRA-SSPR-001 (post-#397) | MFA Registration Campaign | `Entra admin center > Protection > Authentication methods > Registration campaign > Enable and target All Users` | The blade itself is current; only the parent (`Protection >`) is stale. |
| ENTRA-SSPR-002 (existing) | "SSPR enabled for admin accounts" | `Entra admin center > Protection > Password reset > Properties > set scope to Selected and exclude accounts holding directory roles` | The blade itself is current; only the parent (`Protection >`) is stale. **But see §1.4 — automation claim is suspect.** |

### 1.4 False-automation claims (the same class of bug as ENTRA-SSPR-001 pre-#397)

**Schema reality (per `data/registry.schema.json`):**
- `hasAutomatedCheck: true` is a single boolean; the schema requires only that `collector` be set to one of the enum values when true.
- The schema does NOT require a `remediation.graph` block, a `remediation.powershell` block, or any other documentation of the automation mechanism when `hasAutomatedCheck: true`.
- 1,101 of 1,105 CheckIDs claim `hasAutomatedCheck: true`. Only 4 declare `false`.

This means the registry can claim a check is automated without anywhere documenting how. ENTRA-SSPR-001 pre-#397 was one example. The fact that there's a separate `cisRecommendationStructured.cisAuditPolicy: enum [Manual, Automated]` field with description *"distinct from CheckID's hasAutomatedCheck (which is OUR automation status); this is the upstream framework's stance"* suggests divergence is anticipated as a feature, not a bug — but in practice it appears to mask false claims.

**`ENTRA-SSPR-002` — concrete false-automation candidate:**
- `name`: "SSPR enabled for admin accounts"
- `category`: SSPR
- `collector`: Entra
- `hasAutomatedCheck`: **true**
- `remediation`: only `portal` + `notes` — **no `graph` or `powershell` block** documenting how it would be detected.
- Per Phase 1.5 below, **the SSPR enablement toggle (None/Selected/All) has no supported Microsoft Graph endpoint as of 2026-05-04**. The only programmatic surface is the undocumented `https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies` internal endpoint. So this entry is structurally identical to ENTRA-SSPR-001 pre-#397: `hasAutomatedCheck: true` for something not actually measurable via supported Graph.

**Other AUTHMETHOD entries — not yet audited.** A full audit of all 9 ENTRA-AUTHMETHOD-* entries plus 2 ENTRA-MFA-* entries would require checking each against current Graph documentation. Out of scope for this report.

### 1.5 Microsoft Graph API surface for auth-method-related checks (2026-05-04)

| Setting | Supported Graph endpoint? | Notes |
|---|---|---|
| MFA Registration Campaign (current ENTRA-SSPR-001 semantics) | **Yes** — `GET /v1.0/policies/authenticationMethodsPolicy` → `registrationEnforcement.authenticationMethodsRegistrationCampaign` | Read + PATCH supported. |
| Authentication-method enablement (post-migration source of truth) | **Yes** — same `authenticationMethodsPolicy` endpoint, `authenticationMethodConfigurations` collection | This is the unified source after the 2025-09-30 deprecation |
| **SSPR enablement toggle (None/Selected/All)** — both for All users and for Admin users | **No supported endpoint** | Only `https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies` (undocumented, unsupported). Microsoft Q&A confirms no v1.0 or beta surface. APIs "supposedly coming under /authentication/methods" with no announced ETA. |
| `Number of methods required to reset` (legacy SSPR strength setting) | **No supported endpoint** | Same internal-only situation |
| `Allow users to remember MFA on devices they trust` (legacy MFA service settings) | **Mixed** — setting is being migrated to Auth Methods Policy; the legacy blade may persist but is no longer authoritative | Verification needed |
| Per-user registered methods (read-only) | **Yes** — `/users/{id}/authentication/methods` | Useful for inventory checks like ENTRA-MFA-001/002 |

### 1.6 Schema and validation gap

`data/registry.schema.json` defines `remediation.portal` as:

```json
"portal": {
  "type": "object",
  "required": ["path"],
  "additionalProperties": false,
  "properties": {
    "path": { "type": "string", "minLength": 1 },
    "steps": { "type": "array", "items": { "type": "string", "minLength": 1 } }
  }
}
```

**Validation gaps:**
1. No constraint on `path` content — any non-empty string passes. No allow-list of valid top-level navigation parents. No deny-list of obsolete parents.
2. No constraint that `steps` matches the tokens in `path`. They're independent fields and can drift.
3. No constraint linking `hasAutomatedCheck: true` to `remediation.graph` or any other documented automation mechanism.
4. The Pester test suite (`tests/*.Tests.ps1`) has no test that asserts portal path freshness. The only `portal.path` reference in tests is in `migration-helper.Tests.ps1`, which only checks that the field is preserved during migration.

**This is why the stale `Protection >` paths have been in the registry undetected**, and why #397 (the SSPR rebadge) shipped with the assertion that the path was "already correct" — there's no automated check that would have flagged it.

---

## Phase 2 — Decision points (no recommendations)

### Decision A: Scope of remediation for stale portal paths

**Resolved data-flow question:** `data/registry.json` is build output. Source files are `data/scf-check-mapping.json` (31 stale `Protection >` paths) and `data/az-assess-source-checks.json` (14 stale `Security >` + 4 stale `Users > Password reset` + 1 deprecated MFA Service Settings blade = 19 stale paths). Total source-side: **50 entries to touch.**

**Question:** Within the source-of-truth files, what scope?

| Option | What changes | Pros | Cons |
|---|---|---|---|
| **A1.** Fix only ENTRA-SSPR-001 in `scf-check-mapping.json`, rebuild | 1 entry | Smallest possible change, satisfies #399 literally | Leaves 49 other stale entries; bug class persists silently |
| **A2.** Fix all 31 `Protection >` paths in `scf-check-mapping.json`, rebuild | 31 entries | Closes one entire bug class; affects ENTRA-* and CA-* | Doesn't touch the AZ-IDENTITY-* exposure |
| **A3.** Fix everything in both source files, rebuild | 50 entries | Closes the stale-portal-path bug class entirely | Larger PR; cross-cuts AZ-namespace which #386 also touches — coordination question |
| **A4.** A2 + flag #386 to absorb the AZ-side fix as part of namespace reconciliation | 31 entries now + deferred | Respects existing milestone scope; AZ paths stay broken short-term but get fixed once with namespace work | Requires #386 to actually happen; AZ-* portal paths stay broken until then |

### Decision B: Path-correction policy for ambiguous blades

**Question:** For blades that legitimately migrated (not just renamed parents), what should the path say?

**Concrete cases requiring per-entry decision (not mechanical rename):**

| CheckID | Current path | Issue |
|---|---|---|
| AZ-IDENTITY-031 | `Microsoft Entra admin center > Security > Multifactor authentication > Service settings` | Legacy MFA Service Settings blade is **deprecated** for managing methods post-2025-09-30. The "remember MFA on trusted devices" setting moved to Auth Methods Policy. Path needs more than a parent rename — needs blade rework. |
| AZ-IDENTITY-005 (and 3 other `AZ-IDENTITY-*`) | `Microsoft Entra admin center > Users > Password reset > Authentication methods` | Legacy SSPR Authentication Methods page. Per Microsoft Learn, `Number of methods required to reset` survives in this page post-deprecation, so path is reachable. But "Users >" parent is wrong (Users is a sub-node of Entra ID). Mechanical rename is OK if blade survives; check each one. |
| 14 × AZ-IDENTITY-* | `Microsoft Entra admin center > Security > Authentication methods/Conditional Access/Password protection > ...` | Just a stale parent (`Security >`). Mechanical rename to `Entra ID >`. |
| 31 × ENTRA-* / CA-* | `Entra admin center > Protection > Authentication methods/Conditional Access/Password protection/Password reset > ...` | Just a stale parent (`Protection >`). Mechanical rename to `Entra ID >`. (Pattern matches what CIS M365 v6.0.1 itself uses 53 times in the source.) |

**Options:**
- **B1.** Mechanical parent rename for all 49, fix the 1 deprecated-blade entry (AZ-IDENTITY-031) separately — cleanest split
- **B2.** Per-entry verification of every path against current Microsoft Learn docs — most accurate, slowest
- **B3.** Auto-sync from secframe's CIS M365 v6.0.1 CSV for CIS-mapped checks (14 of the 31 Protection-stale checks have `cisM365ControlId`), mechanical rename for the rest, manual triage for AZ-IDENTITY-031

### Decision C: ENTRA-SSPR-002 — fix or leave alone?

**Question:** `ENTRA-SSPR-002` ("SSPR enabled for admin accounts") claims `hasAutomatedCheck: true` for something with no supported Graph endpoint. This is the same class of bug as ENTRA-SSPR-001 pre-#397.

**Options:**
- **C1.** Flip to `hasAutomatedCheck: false` and document as manual-only (consistent with framework-data-completeness rule: don't claim what we can't deliver)
- **C2.** Investigate further — maybe the M365-Assess collector implements detection via a different mechanism (e.g., user inventory + MS Graph for role assignment cross-checked against an inferred SSPR scope). Cross-reference Galvnyz/M365-Assess for an existing SSPR-002 collector.
- **C3.** Leave alone — out of scope for #399, file a separate issue
- **C4.** If we keep `hasAutomatedCheck: true`, require a `remediation.graph` block (or equivalent) so reviewers can verify the claim — this is a schema change, not just a data fix

**Data needed to decide:** Does Galvnyz/M365-Assess have a collector for ENTRA-SSPR-002? If yes, what does it actually read?

### Decision D: Missing CIS M365 v6 §5.2.4.1 coverage

**Question:** PR #397 explicitly removed CIS M365 v6 §5.2.4.1 from `ENTRA-SSPR-001` and said "A future ENTRA-SSPR-002 will measure actual SSPR enablement." But `ENTRA-SSPR-002` already exists with a different purpose (admin accounts only, not the All-users CIS 5.2.4.1 control). So:

- **D1.** Repurpose `ENTRA-SSPR-002` to cover CIS 5.2.4.1 (All-users SSPR enablement) — breaking change, ID is already shipped
- **D2.** File a new `ENTRA-SSPR-003` for the CIS 5.2.4.1 gap — non-breaking; aligns with #387 (namespace duplication reconciliation milestone)
- **D3.** Leave the gap — accept that CIS 5.2.4.1 is uncovered upstream until Microsoft ships a Graph endpoint
- **D4.** File the new ENTRA-SSPR-003 as `hasAutomatedCheck: false` (manual-only) so the CIS mapping is restored without false-automation claim

### Decision E: Schema hardening — should validation be added now or later?

**Question:** Should we extend the schema / Pester suite to detect this class of bug going forward, or just fix the data?

**Options:**
- **E1.** Data-only fix — fix the 50 paths, move on. Bug class can recur on next data drift.
- **E2.** Add a Pester test that asserts `path` and `steps[0..1]` use one of the current top-level navigation parents (allow-list: `Entra admin center` / `Microsoft Entra admin center > Entra ID|ID Protection|Identity Governance|Verified ID|Global Secure Access`, plus `Azure Portal`, `Exchange admin center`, `Microsoft 365 admin center`, `Purview portal`, `Power BI Admin portal`). Deny-list of obsolete parents: `Protection`, `Security`, `Users` (directly under Entra admin center).
- **E3.** CI job that fetches Microsoft Learn pages and validates paths against current docs (heavier, more brittle, ongoing drift detection)
- **E4.** Extend the schema's conditional rule for `hasAutomatedCheck: true` to require either `remediation.graph` or `remediation.powershell` (would catch false-automation claims like ENTRA-SSPR-002)
- **E5.** Build an auto-sync script that pulls portal paths from secframe's CIS M365 v6.0.1 CSV into `scf-check-mapping.json` for the 14 CIS-mapped Protection-stale checks. Future CIS benchmark refreshes propagate without manual transcription. Aligns with the "framework data completeness" rule and reduces the surface that needs E2's allow-list to police.

### Decision F: Connection to existing milestone backlog

**Question:** Does any of this work fold into existing v3.5 work?

**Already-filed-related issues:**
- **#386**: "v3.5: AZ-namespace boundary reconciliation — Entra controls misclassified under AZ-IDENTITY-*" — **all 19 stale paths in `az-assess-source-checks.json` are in `AZ-IDENTITY-*`** entries, which is the exact population this issue addresses. Fixing those portal paths is naturally bundled with the namespace work.
- **#387**: "v3.5: namespace duplication reconciliation" — relevant if we rename ENTRA-SSPR-002 to ENTRA-AUTHMETHOD-XXX or restructure the SSPR namespace
- **#406**: "docs: refresh REFERENCES.md" — already flags Microsoft Learn URL rot as a known systemic issue (#362). This stale-portal-path bug is the same root cause class.

**Options:**
- **F1.** Roll the AZ-side portal-path fixes into #386 (since they overlap exactly), ship the 31 `scf-check-mapping.json` fixes standalone
- **F2.** Ship all 50 portal-path fixes standalone now, leave #386 to its broader namespace scope
- **F3.** Defer everything to v3.5
- **F4.** New issue: file the 50-path-fix as its own issue (separate from #399 which is now scoped to its original CheckID), close #399 when ENTRA-SSPR-001 is fixed inside the larger PR

---

## What I'm NOT doing

This report deliberately:
- Does not propose specific edits to data files
- Does not draft commits or PRs
- Does not close or comment on #399 on GitHub
- Does not file new issues
- Does not run `Build-Registry.ps1` or any data transformations
- Does not assume which path-correction policy (B1/B2/B3) is right

The next move is yours. Suggested directions:
1. Pick a combination of options (A/B/C/D/E/F) — they're not all mutually exclusive (e.g., A2+B3+E5 = fix `scf-check-mapping.json` via auto-sync from secframe CIS for the 14 CIS-mapped entries, mechanical for the 17 non-CIS, and add the sync script for future drift)
2. Or ask follow-up research questions on any specific area (e.g., "verify the 2-entry discrepancy between source and registry counts")
3. Or course-correct the framing if I've misread the situation

## Sources

- Microsoft Learn — [Microsoft Entra admin center](https://learn.microsoft.com/en-us/entra/fundamentals/entra-admin-center) (`updated_at: 2026-04-06`) — canonical top-level nav
- Microsoft Learn — [How to run a registration campaign](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign) (`updated_at: 2026-02-13`) — confirms `Entra ID > Authentication methods > Registration campaign`
- Microsoft Learn — [Conditional Access policy templates](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common) (`updated_at: 2026-03-27`) — confirms `Entra ID > Conditional Access`
- Microsoft Learn — [Tutorial: Enable SSPR](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr) (`updated_at: 2026-03-27`) — confirms `Entra ID > Password reset > Properties`
- Microsoft Learn — [Manage authentication methods](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage) (`updated_at: 2026-03-27`) — 2025-09-30 deprecation, what survives
- Microsoft Learn — [Password protection in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad) (`updated_at: 2026-02-13`) — Password protection lives under Authentication Methods
- Microsoft Learn — [authenticationMethodsRegistrationCampaign resource type](https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodsregistrationcampaign?view=graph-rest-1.0) — Graph endpoint confirmed for Registration Campaign
- Microsoft Q&A — [Tenant-level SSPR status via Graph](https://learn.microsoft.com/en-us/answers/questions/5805131/how-to-retrieve-tenant-level-self-service-password) — confirms no supported Graph surface for SSPR enablement
