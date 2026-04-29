# CIS Benchmark Content — Consumer-Side Licensing Posture

## Summary

CheckID does **not** redistribute CIS-authored Benchmark prose (Description, Rationale Statement, Impact Statement, Remediation Procedure, Audit Procedure, Additional Information). The public repository ships the **structure** to accept this content (the `frameworks.cis-m365-v6.cisAuthored` block in `data/registry.schema.json`) and a **consumer-side importer** ([`tools/import-cis-prose.py`](../tools/import-cis-prose.py)) that imports prose from a consumer's own licensed CIS spreadsheet into a gitignored local artifact (`data/cis-m365-v6-authored.local.json`).

This document records *why* — what the relevant CIS terms say, what they permit, and what they forbid — and *how* — the technical mechanism that respects the constraint.

## Why

### CIS Benchmarks license summary

CIS Benchmark PDFs are licensed under [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode) for non-members.

Non-members operate under [the CIS Terms of Use for Non-Member CIS Products](https://www.cisecurity.org/terms-of-use-for-non-member-cis-products), which adds a restriction layered on top of CC BY-NC-SA: clause (E) forbids creating *"any derivative work based directly on a Non-Member CIS Product or any component thereof."* This effectively narrows non-member rights from CC BY-NC-SA toward CC BY-NC-ND — verbatim non-commercial redistribution with attribution is allowed, but adaptation is not.

CIS SecureSuite **members** operate under the [End User Organization Membership Agreement](https://www.cisecurity.org/terms-and-conditions-table-of-contents/end-user-organization-membership-agreement). Members get *internal* customization rights (Section II.B):

> *"The ability to edit/modify CIS Benchmarks, solely for internal use by Customer and its Affiliates, based upon Customer's unique internal specifications and requirements"*

But the same agreement explicitly forbids public redistribution:

> *"Customer and its Affiliates may not sell, resell, or distribute any CIS SecureSuite Product or Customized Benchmark, whether in part or in whole, on its own or as part of an offering, product or service."*

### The implication for CheckID

CheckID is a public open-source repository. Both non-member and member rights forbid the kind of redistribution CheckID would have to do to ship CIS-authored prose centrally:

- **As non-members:** clause (E) forbids derivatives. Restructuring prose into JSON fields could plausibly be characterized as a "derivative work based directly on a Non-Member CIS Product."
- **As members:** Section II.B.1 forbids any public distribution, even of unmodified content.

Either way, central public redistribution of CIS-authored prose is contractually unavailable to CheckID without an explicit per-project waiver from CIS — which would require an outbound permission request and is not pursued at this phase.

### What the consumer-side approach achieves

By placing the importer in `tools/` and gitignoring the output, CheckID:

1. **Provides the structure.** The `cisAuthored` schema block in `data/registry.schema.json` accepts the data when populated. Downstream consumers (M365-Assess, Az-Assess, EZ-CMMC, future) can render CIS-authored prose alongside CheckID-authored narrative without either consumer reinventing the ingestion logic.

2. **Never carries the prose itself.** The public CheckID registry has zero CIS-authored prose. The CC BY-NC-SA + member-agreement constraints are honored by construction.

3. **Lets each consumer choose.** A consumer with a CIS membership runs the importer once against their licensed XLSX; each consumer's local registry build merges in the prose. A consumer without a membership leaves the field absent — the registry still validates and works, just without the prose layer.

4. **Stays compatible with future permission.** If CIS later grants explicit redistribution permission for CheckID, the central data swap is straightforward — the schema is unchanged.

## How

### Files involved

| File | Role | Tracked? |
|---|---|---|
| `tools/import-cis-prose.py` | Consumer-side importer (reads licensed XLSX, emits local prose JSON) | ✅ Public |
| `data/registry.schema.json` `$defs.cisAuthoredProse` | Schema for the prose block | ✅ Public |
| `data/cis-m365-v6-authored.local.json` | Local prose artifact populated by the importer | ❌ Gitignored |
| `data/registry.json` | Canonical registry — **never** carries CIS prose, regardless of whether the local artifact is present | ✅ Public |
| `data/registry.local.json` | Prose-enriched registry built alongside `registry.json` when the local artifact is present | ❌ Gitignored |
| `scripts/Build-Registry.py` | Always writes the canonical `registry.json` prose-free; additionally writes `registry.local.json` with prose merged when consumer artifact is present | ✅ Public |
| `.gitignore` | Excludes `*.local.json` and both specific paths | ✅ Public |

### Output-separation architecture

`scripts/Build-Registry.py` always writes two files when the consumer artifact is present:

1. **`data/registry.json`** — canonical registry. **Never** contains CIS-authored prose, regardless of consumer state. This is what gets committed and what CI validates against.
2. **`data/registry.local.json`** — prose-enriched variant. Same shape, but every CIS-mapped check that has matching prose in the local artifact gets a populated `frameworks.cis-m365-v6.cisAuthored` block. Gitignored.

When the consumer artifact is absent (the normal CI flow, or any consumer who hasn't run the importer), `Build-Registry.py` writes only `registry.json`. The architecture means **a developer can rebuild locally without contaminating their committable diff** — `registry.json` always reflects what's safe to commit.

Downstream consumers who want the prose layer load `data/registry.local.json` if it exists, falling back to `data/registry.json` otherwise. This is a one-line check in their loader.

### Constraint enforcement layers

The "don't accidentally commit the prose" outcome is enforced at multiple layers:

1. **Output separation** — `Build-Registry.py` writes prose to `registry.local.json`, never to `registry.json`. The committable artifact is structurally separate from the prose-bearing artifact.
2. **`.gitignore`** — `*.local.json`, `data/cis-m365-v6-authored.local.json`, and `data/registry.local.json` are explicitly excluded.
3. **Output `_warning` field** — every generated artifact carries a `_warning` reminding the consumer of the constraint at the data layer.
4. **`tools/README.md`** — documents the constraint at the tool docs.
5. **Importer stdout** — the script prints a licensing notice to stdout on every run.
6. **Pester invariant guard** — `tests/registry-integrity.Tests.ps1` fails CI if `data/registry.json` ever contains a `cisAuthored` block. Unconditional — fires regardless of consumer state, since the canonical registry should never carry prose.
7. **This file** — the canonical reference for the licensing posture.

If you discover a CheckID branch or PR that has accidentally committed `*.local.json` content, file an issue immediately (label `licensing`); the file should be removed from history.

### Attribution requirements when consumer-side artifacts are rendered

When downstream tooling renders the prose from `cisAuthored` blocks, the rendering surface should display:

1. CIS attribution: *"Source: CIS Microsoft 365 Foundations Benchmark v6.0.1 (© Center for Internet Security, Inc.)."*
2. Link to the CIS Benchmarks page: `https://www.cisecurity.org/cis-benchmarks/`
3. License notice when the consumer is a non-member rendering content for a non-internal audience.

Member consumers rendering for internal use have less stringent attribution requirements but should still cite the source for clarity in compliance reports.

## Future work

If CIS grants CheckID explicit per-project redistribution permission, the central-data swap requires:

1. Replace the `*.local.json` consumer-side workflow with a centrally-shipped `data/cis-m365-v6-authored.json` artifact.
2. Update `scripts/Build-Registry.py` to read from the central path.
3. Document attribution requirements in this file.
4. Coordinate with downstream consumers on the migration.

Schema changes would be minimal — the `cisAuthored` block shape is identical between consumer-side and centrally-shipped postures.

## Related

- [`tools/README.md`](../tools/README.md) — importer usage
- [`tools/import-cis-prose.py`](../tools/import-cis-prose.py) — importer source
- Issue [#347](https://github.com/Galvnyz/CheckID/issues/347) — phase 2 of CIS M365 v6 enrichment (Path A)
- [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode)
- [CIS Terms of Use for Non-Member CIS Products](https://www.cisecurity.org/terms-of-use-for-non-member-cis-products)
- [CIS End User Organization Membership Agreement](https://www.cisecurity.org/terms-and-conditions-table-of-contents/end-user-organization-membership-agreement)
