# CheckID References

## Upstream: SecFrame

[SecFrame](https://github.com/Galvnyz/SecFrame) is the authoritative source
for security framework reference data. Since v2.0.0, CheckID uses the SCF
(Secure Controls Framework) database as its primary source of truth:

| SecFrame File | What It Provides |
|---------------|-----------------|
| `SCF/scf.db` | **Primary source** — Normalized SQLite database (13 tables, 261 frameworks, 66K+ mappings) |
| `SCF/secure-controls-framework-scf-2025-4.csv` | Master cross-framework mapping (SCF 2025.4) |
| `NIST/NIST_SP-800-53_rev5_catalog.json` | NIST 800-53 OSCAL catalog (for title resolution) |
| `NIST/NIST_CSF_v2.0_catalog.json` | NIST CSF 2.0 OSCAL catalog (for title resolution) |

### Update Workflow (Automated)

When SecFrame merges changes to framework data directories, the CI cascade triggers:

1. **SecFrame** `notify-checkid.yml` dispatches `secframe-updated` to CheckID
2. **CheckID** `rebuild-from-secframe.yml` fetches latest data, rebuilds registry, opens PR
3. After PR merge and tag, `notify-downstream.yml` dispatches `checkid-released` to consumers
4. Consumers receive dispatch and auto-create sync PRs

Manual workflow: edit `data/scf-check-mapping.json` → `python scripts/Build-Registry.py` → `Test-RegistryData.ps1` → commit → tag

**Build pipeline inputs:**
- `data/scf-check-mapping.json` — check → SCF control assignments (human-curated)
- `data/scf-framework-map.json` — which SCF frameworks to include
- `data/framework-overrides.json` — manual mappings for SCF coverage gaps
- `SecFrame/SCF/scf.db` — SCF SQLite database (upstream)

## Downstream Consumers

| Project | Repository | Integration | Sync Method |
|---------|-----------|-------------|-------------|
| **M365-Assess** | [Galvnyz/M365-Assess](https://github.com/Galvnyz/M365-Assess) | CI cache (`controls/registry.json`) | `sync-checkid.yml` auto-PR on dispatch |
| **M365-Remediate** | [Galvnyz/M365-Remediate](https://github.com/Galvnyz/M365-Remediate) | Submodule (`lib/CheckID/`) | `sync-checkid.yml` auto-PR on dispatch |
| **StrykerScan** | [Galvnyz/StrykerScan](https://github.com/Galvnyz/StrykerScan) | Mapping file (`checks/checkid-mapping.json`) | Metadata only, not runtime |
| **Stitch-M365** | Private | Submodule (`Engine/lib/CheckID/`) | Manual submodule update |
| **Darn** | [Galvnyz/Darn](https://github.com/Galvnyz/Darn) | Planned | — |

### Canonical Reference Data

Beyond `registry.json` and `frameworks/*.json`, CheckID is the single source of truth for cross-consumer reference data. Consumers fetch these from the tagged release instead of maintaining per-repo copies (which drift):

| File | Purpose | Consumed by |
|------|---------|-------------|
| `data/mitre-technique-map.json` | ATT&CK technique-to-tactic lookup (technique IDs do not encode the tactic) | `mitre-attack` framework grouping by tactic |

Each canonical data file has a sibling `*.schema.json` and Pester coverage under `tests/`.

### CI Cascade Flow

```
SecFrame merge → notify-checkid.yml → repository_dispatch
    ↓
CheckID rebuild-from-secframe.yml → PR → merge → tag
    ↓
CheckID notify-downstream.yml → repository_dispatch to:
    ├── M365-Assess sync-checkid.yml → fetch registry + frameworks → PR
    ├── M365-Remediate sync-checkid.yml → update submodule → PR
    └── StrykerScan (receives dispatch, validates mapping)
```

### Consumer Integration Guide

**CI cache sync** (recommended for PowerShell tools like M365-Assess):
- Add `sync-checkid.yml` workflow that receives `checkid-released` dispatch
- Fetch `data/registry.json`, `data/frameworks/*.json`, and the canonical reference data files (see [Canonical Reference Data](#canonical-reference-data)) from the tagged version
- Store in a local `controls/` directory

**Git submodule** (recommended for .NET apps like M365-Remediate):
```bash
git submodule add https://github.com/Galvnyz/CheckID.git lib/CheckID
```

**Mapping file** (recommended for standalone scanners like StrykerScan):
- Create `checkid-mapping.json` mapping local check IDs to CheckID universal IDs
- Metadata only — no runtime dependency on CheckID

### Secrets Required

Cross-repo dispatch requires a `CROSS_REPO_TOKEN` secret (classic GitHub PAT with `repo` + `workflow` scopes) configured in CheckID, SecFrame, and each consumer repo.
