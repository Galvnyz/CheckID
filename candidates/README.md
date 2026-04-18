# candidates/

Auto-generated candidate check entries produced by `scripts/Build-CisAzureCandidates.py`.

## Workflow

1. `az-candidates.json` is regenerated whenever SecFrame fires a `secframe-azure-updated` dispatch
2. Open the file and fill all `"TODO"` fields for each entry you want to promote:
   - `scf.primaryControlId` — SCF control ID (e.g. `IAC-14`)
   - `scf.domain`, `scf.controlName`, `scf.controlDescription`, `scf.csfFunction`
   - `impactRating.severity` — Critical / High / Medium / Low / Informational
   - `impactRating.rationale`
3. Remove the `_source` helper object from each finalised entry
4. Append the entry to `data/az-assess-source-checks.json`
5. Run `pwsh -NoProfile -File scripts/Build-Registry.ps1` to rebuild `registry.json`

Files in this directory are **never auto-merged** into the registry.
