# Schema Migration — v2.x → v3.0.0

> **Audience:** maintainers of downstream consumers (M365-Assess, M365-Remediate, StrykerScan, and anyone else reading `registry.json`).
>
> **TL;DR:** `remediation` is now a structured object instead of a string. Two override files are gone — their data lives on each check with provenance. New optional fields tag where every framework mapping came from. Pin to `v2.23.0` until you've migrated; we ship a backward-compat cmdlet for the transition window.

---

## What changed

Three breaking changes, one schema strengthening, and several additive fields.

### 1. `remediation` is now a structured object (was: string)

**Was (v2.23.0 and earlier):**
```jsonc
"remediation": "Run: Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly. SharePoint admin center > Policies > Sharing."
```

**Now (v3.0.0):**
```jsonc
"remediation": {
  "powershell": {
    "command": "Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly"
  },
  "portal": {
    "path": "SharePoint admin center > Policies > Sharing",
    "steps": ["SharePoint admin center", "Policies", "Sharing"]
  }
}
```

Channels: `powershell`, `portal`, `graph`, `cli`, `notes`. **Null channels are omitted**, not stored as null. At least one channel is always present (enforced by schema `minProperties: 1`).

### 2. `data/framework-overrides.json` is deleted

Its data moved onto each check's `frameworks.<id>` entry, tagged with `source: "manual-override"` and an optional `reason` describing why the curator added it. See section "Provenance: how to use it" below.

### 3. `data/effort-overrides.json` is deleted

Its data moved onto each check's `effort` object. The previously-stripped `_rationale` annotation is now preserved as `effort.overrideReason`.

### 4. New optional fields (additive)

- `frameworks.<id>.source` — enum: `scf-derived` (default if absent), `manual-override`, `cis-paraphrased`, `stig-manual`, `eidsca-crosswalk`.
- `frameworks.<id>.reason` — free-text explanation, populated on overrides where the curator left a note.
- `effort.overrideReason` — string, captures why this check's effort was hand-set (was `_rationale` in v2.x, silently stripped from output).

### 5. Schema-strict gate (already in v2.23.0, reinforced here)

Every check in `registry.json` is now schema-validated for required fields, including `impactRating` and `remediation`. Consumers that produce derived registries should expect their tooling to fail fast on missing required fields.

---

## Before / after — full check example (`ENTRA-SECDEFAULT-001`)

### v2.23.0 shape
```jsonc
{
  "checkId": "ENTRA-SECDEFAULT-001",
  "name": "Security Defaults Enabled",
  "frameworks": {
    "nist-csf": { "controlId": "PR.AA-01", "title": "..." },
    "soc2":     { "controlId": "CC6.1" }
  },
  "effort": {
    "complexity": 3,
    "isPhased": false,
    "phaseCount": 1,
    "disruptionRisk": false
  },
  "remediation": "Run: Update-MgPolicyIdentitySecurityDefaultsEnforcementPolicy -IsEnabled $true. Entra admin center > Properties > Manage security defaults."
}
```

### v3.0.0 shape
```jsonc
{
  "checkId": "ENTRA-SECDEFAULT-001",
  "name": "Security Defaults Enabled",
  "frameworks": {
    "nist-csf": { "controlId": "PR.AA-01", "title": "..." },
    "soc2":     { "controlId": "CC6.1" }
  },
  "effort": {
    "complexity": 3,
    "isPhased": false,
    "phaseCount": 1,
    "disruptionRisk": false
  },
  "remediation": {
    "powershell": {
      "command": "Update-MgPolicyIdentitySecurityDefaultsEnforcementPolicy -IsEnabled $true"
    },
    "portal": {
      "path": "Entra admin center > Properties > Manage security defaults",
      "steps": ["Entra admin center", "Properties", "Manage security defaults"]
    }
  }
}
```

The other fields (`scf`, `frameworks`, `effort`, etc.) are unchanged in shape.

---

## PowerShell consumer guide

### Reading structured remediation directly (recommended)

```pwsh
Import-Module ./CheckID.psd1
$check = Get-CheckById 'SPO-SHARING-001'

# v3.0+ structured access
if ($check.remediation.powershell) {
    Write-Host "Run this:"
    Write-Host "  $($check.remediation.powershell.command)"
}
if ($check.remediation.portal) {
    Write-Host "Or navigate:"
    Write-Host "  $($check.remediation.portal.path)"
}
if ($check.remediation.cli) {
    Write-Host "Or via CLI:"
    Write-Host "  $($check.remediation.cli.command)"
}
if ($check.remediation.notes) {
    Write-Host "Notes:"
    Write-Host "  $($check.remediation.notes)"
}
```

### Backward-compat bridge (deprecated)

If your existing renderer expects a v2.x string and you can't update it immediately, the module ships `ConvertTo-LegacyRemediationString`:

```pwsh
$legacyString = ConvertTo-LegacyRemediationString $check.remediation
# WARNING: ConvertTo-LegacyRemediationString is deprecated; will be removed in v3.3.0...
# → "Run: Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly. SharePoint admin center > Policies > Sharing."
```

Use this as a **bridge during your migration window**, not as a destination. The cmdlet emits a deprecation warning once per session.

### Local testing against a v2.x registry (rare)

If you have a v2.23.0 registry checked into your repo and want to test v3.0 conversion locally, ship the standalone helper:

```pwsh
pwsh -File tools/migrate-checkid-3.0.ps1 -InputPath ./fixtures/v2.23-registry.json -OutputPath ./fixtures/v3.0-registry.json
```

---

## Provenance: how to use it

The new `frameworks.<id>.source` field tells you where a mapping came from. Most consumers can ignore it. Three cases where it matters:

1. **Audit reports.** Display `source: "manual-override"` differently from `source: "scf-derived"` to acknowledge curator judgment ("This NIST 800-171 mapping was manually added because SCF lacks coverage for sign-in frequency").

2. **Drift detection.** When SCF eventually publishes a control that overlaps a manual override, you may want to consolidate. Filtering by `source` lets you find candidates.

3. **Trust signaling.** `cis-paraphrased` and `stig-manual` indicate authored content; `eidsca-crosswalk` indicates a third-party benchmark crosswalk. Surfacing these in tooltips builds reader trust.

### Reason field

`frameworks.<id>.reason` is populated when the curator left an explanatory note (rare in v3.0.0 — the v2.x override file had no per-entry rationale). Future overrides should always include a reason for posterity.

`effort.overrideReason` is populated on all 59 hand-overridden effort entries (preserved from the v2.x `_rationale` annotations that were silently stripped).

---

## Migration checklist for consumer repos

1. **Pin to v2.23.0 immediately.** Buy yourself time:
   ```bash
   git submodule set-branch --branch v2.23.0 lib/CheckID
   # or for cache-sync consumers:
   curl -O https://raw.githubusercontent.com/Galvnyz/CheckID/v2.23.0/data/registry.json
   ```

2. **Audit your renderer.** Search for code that reads `check.remediation` as a string. Each call site needs a decision:
   - Quick path: wrap with `ConvertTo-LegacyRemediationString` (works today; deprecated).
   - Right path: migrate the renderer to consume the structured shape.

3. **Test against v3.0** in a sandbox before pulling production. Set up a CI matrix that consumes both v2.23.0 and v3.0.0 to ensure your renderer handles both during the transition.

4. **Update internal docs and release notes** to reflect the breaking change for *your* consumers.

5. **Drop the bridge** before v3.3.0. The `ConvertTo-LegacyRemediationString` cmdlet will be removed (#295). After that release, code paths still using it will fail at runtime.

---

## Removal timeline

| Version | What changes |
|---|---|
| **v3.0.0** (this release) | Schema flip. Backward-compat cmdlet ships, marked deprecated. |
| **v3.1.0** | CIS M365 v6 enrichment pilot. No remediation-shape changes. |
| **v3.2.0** | Critical/High content backfill. No remediation-shape changes. |
| **v3.3.0** | `ConvertTo-LegacyRemediationString` and `tools/migrate-checkid-3.0.ps1` are **removed** (#295). Plan to be off them by this release. |

You have approximately three minor versions (v3.0 → v3.1 → v3.2) to migrate before the bridge disappears.

---

## Questions or surprises?

If your renderer breaks in a way this doc doesn't predict, file an issue at https://github.com/Galvnyz/CheckID/issues with:
- Your consumer repo
- A snippet of the failing code
- Expected vs. observed behavior

Cross-repo coordination for v3.0 lives at:
- M365-Assess#738
- M365-Remediate#239
- StrykerScan#17

---

_Last reviewed 2026-04-25 (v3.0.0 release)._
