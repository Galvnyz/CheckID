# CheckID Architecture

Visual documentation of CheckID's core functionality, data pipeline, and integrations.

## System Context

How CheckID fits between its upstream data source (SecFrame/SCF) and downstream consumers.

```mermaid
flowchart TB
    subgraph upstream["Upstream: SecFrame"]
        SCF_XLSX["SCF XLSX<br/>(1,451 controls x 261 frameworks)"]
        SCF_DB[("scf.db<br/>SQLite — 13 tables<br/>66K+ mappings")]
        SCF_XLSX -->|Build-ScfDatabase.py| SCF_DB
    end

    subgraph checkid["CheckID Registry"]
        MAPPING["scf-check-mapping.json<br/>222 checks → SCF controls"]
        FW_MAP["scf-framework-map.json<br/>12 SCF frameworks + 3 manual"]
        OVERRIDES["framework-overrides.json<br/>59 manual gap fills"]
        TITLES["framework-titles.json<br/>Human-readable titles"]
        BUILD["Build-Registry.py"]
        REGISTRY[("registry.json<br/>222 checks · 15 frameworks<br/>Schema v2.0.0")]
        SCHEMA["registry.schema.json"]

        MAPPING --> BUILD
        FW_MAP --> BUILD
        OVERRIDES --> BUILD
        TITLES --> BUILD
        BUILD --> REGISTRY
        SCHEMA -.->|validates| REGISTRY
    end

    subgraph downstream["Downstream Consumers"]
        M365A["M365-Assess<br/>CI cache sync"]
        M365R["M365-Remediate<br/>Git submodule"]
        STRYKER["StrykerScan<br/>Mapping file"]
        STITCH["Stitch-M365<br/>Git submodule"]
    end

    SCF_DB -->|queried by| BUILD
    REGISTRY --> M365A
    REGISTRY --> M365R
    REGISTRY --> STRYKER
    REGISTRY --> STITCH

    style upstream fill:#1e3a5f,color:#93c5fd
    style checkid fill:#1a3320,color:#86efac
    style downstream fill:#3b1a45,color:#d8b4fe
```

## Registry Build Pipeline

Detailed data flow showing how `registry.json` is assembled from multiple sources.

```mermaid
flowchart LR
    subgraph inputs["Input Files"]
        SCM["scf-check-mapping.json<br/>─────────────────<br/>checkId, name, category<br/>collector, licensing<br/>scfPrimary, scfAdditional<br/>cisM365ControlId<br/>cisaScubaControlId<br/>stigControlId"]
        SFM["scf-framework-map.json<br/>─────────────────<br/>12 SCF framework IDs<br/>NIST baseline IDs<br/>3 manual-only keys"]
        OVR["framework-overrides.json<br/>─────────────────<br/>59 NIST CSF overrides<br/>13 SOC 2 overrides"]
        TTL["framework-titles.json"]
    end

    subgraph scfdb["SCF Database (scf.db)"]
        CTL["controls<br/>1,451 rows"]
        AOS["assessment_objectives<br/>5,736 rows"]
        RSK["control_risks<br/>42,004 rows"]
        THR["control_threats<br/>30,993 rows"]
        CMP["control_mappings<br/>66,957 rows"]
    end

    subgraph build["Build-Registry.py"]
        direction TB
        S1["1. Load check definitions"]
        S2["2. Query SCF metadata<br/>(domain, name, weighting,<br/>CMM levels, CSF function)"]
        S3["3. Query AOs, risks, threats"]
        S4["4. Derive framework mappings<br/>(with parent control fallback)"]
        S5["5. Resolve NIST baselines<br/>(Low/Moderate/High/Privacy)"]
        S6["6. Overlay manual frameworks<br/>(CIS M365, CISA ScuBA, STIG)"]
        S7["7. Apply coverage overrides<br/>(NIST CSF, SOC 2 gaps)"]
        S8["8. Resolve titles"]
        S9["9. Sort by SCF domain → ID"]
        S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9
    end

    subgraph output["Output"]
        REG[("registry.json<br/>v2.0.0")]
    end

    SCM --> S1
    SFM --> S4
    OVR --> S7
    TTL --> S8
    CTL --> S2
    AOS --> S3
    RSK --> S3
    THR --> S3
    CMP --> S4
    S9 --> REG
```

## Check Object Structure

Anatomy of a single check in `registry.json`.

```mermaid
flowchart TB
    CHECK["<b>Check Object</b><br/>checkId · name · category<br/>collector · hasAutomatedCheck · licensing"]

    CHECK --> SCF_OBJ
    CHECK --> FW_OBJ
    CHECK --> IMPACT

    subgraph SCF_OBJ["scf { }"]
        direction TB
        PRI["primaryControlId<br/><i>e.g., IAC-21.3</i>"]
        ADD["additionalControlIds[]"]
        DOM["domain<br/><i>e.g., Identification & Authentication</i>"]
        META["controlName · controlDescription<br/>relativeWeighting · csfFunction"]
        CMM["maturityLevels {}<br/>cmm0..cmm5 booleans"]
        AO["assessmentObjectives[]<br/>aoId + text"]
        RISK["risks[]<br/><i>R-AC-1, R-AM-2, ...</i>"]
        THREAT["threats[]<br/><i>NT-7, MT-1, ...</i>"]
    end

    subgraph FW_OBJ["frameworks { }"]
        direction TB
        FW1["nist-800-53<br/>controlId · title · profiles[]"]
        FW2["cis-m365-v6<br/>controlId · title · profiles[]"]
        FW3["iso-27001<br/>controlId · title"]
        FW4["... 12 more frameworks"]
    end

    subgraph IMPACT["impactRating { }"]
        SEV["severity<br/><i>Critical/High/Medium/Low</i>"]
        RAT["rationale"]
        WGT["scfWeighting<br/><i>1-10</i>"]
    end

    style SCF_OBJ fill:#1e3a5f,color:#93c5fd
    style FW_OBJ fill:#1a3320,color:#86efac
    style IMPACT fill:#3b1a45,color:#d8b4fe
```

## CI Cascade

Automated pipeline from upstream data changes through to downstream consumer sync.

```mermaid
sequenceDiagram
    participant SF as SecFrame
    participant GH as GitHub Actions
    participant CID as CheckID
    participant M365A as M365-Assess
    participant M365R as M365-Remediate
    participant STK as StrykerScan

    Note over SF: SCF data updated<br/>(new framework version, mapping fixes)
    SF->>GH: push to main (SCF/ path)
    GH->>GH: notify-checkid.yml
    GH->>CID: repository_dispatch<br/>(secframe-updated)

    Note over CID: Automated rebuild
    CID->>CID: Fetch scf.db from SecFrame
    CID->>CID: python Build-Registry.py
    CID->>CID: Test-RegistryData.ps1
    CID->>CID: git diff → create PR

    Note over CID: Human reviews & merges PR
    CID->>CID: Tag release (vX.Y.Z)
    CID->>GH: notify-downstream.yml
    GH->>M365A: repository_dispatch (checkid-released)
    GH->>M365R: repository_dispatch (checkid-released)
    GH->>STK: repository_dispatch (checkid-released)

    Note over M365A: CI cache sync
    M365A->>M365A: Fetch registry.json + frameworks/
    M365A->>M365A: Auto-create sync PR

    Note over M365R: Submodule update
    M365R->>M365R: Update lib/CheckID submodule ref
    M365R->>M365R: Auto-create sync PR

    Note over STK: Validation only
    STK->>STK: Validate mapping compatibility
```

## Framework Derivation

How framework mappings flow from a single SCF control to 15+ compliance frameworks.

```mermaid
flowchart LR
    subgraph check["CheckID Check"]
        CK["ENTRA-ADMIN-001"]
    end

    subgraph scf["SCF Control"]
        PRIMARY["IAC-21.3<br/><i>(primary)</i>"]
        PARENT["IAC-21<br/><i>(parent fallback)</i>"]
        ADDITIONAL["IAC-15, IAC-07.2<br/><i>(additional)</i>"]
        PRIMARY -.->|fallback| PARENT
    end

    subgraph derived["SCF-Derived Frameworks"]
        NIST["nist-800-53<br/>AC-6(5)"]
        FED["fedramp<br/>AC-6(5)"]
        ISO["iso-27001<br/>5.18; 8.2"]
        PCI["pci-dss<br/>7.2.3"]
        CMMC2["cmmc<br/>AC.L2-3.1.5"]
        HIPAA["hipaa<br/>164.312(a)(2)(ii)"]
        SOC2["soc2<br/>CC6.1; CC6.3"]
        CSF["nist-csf<br/>PR.AA-05"]
        ATT["mitre-attack<br/>T1078"]
        MORE["+ 3 more..."]
    end

    subgraph manual["Manual Overlays"]
        CIS["cis-m365-v6<br/>1.1.3"]
        SCUBA["cisa-scuba<br/>MS.AAD.7.1v1"]
        STIG["stig<br/>V-260335"]
    end

    subgraph overrides["Gap Overrides"]
        OVR_CSF["nist-csf override<br/><i>(when SCF lacks mapping)</i>"]
        OVR_SOC["soc2 override<br/><i>(when SCF lacks mapping)</i>"]
    end

    CK --> PRIMARY
    CK --> ADDITIONAL
    PRIMARY --> NIST & FED & ISO & PCI & CMMC2 & HIPAA
    PARENT --> SOC2 & CSF & ATT
    ADDITIONAL --> MORE
    CK --> CIS & SCUBA & STIG
    OVR_CSF -.->|fills gap| CSF
    OVR_SOC -.->|fills gap| SOC2

    style derived fill:#1a3320,color:#86efac
    style manual fill:#3b1a45,color:#d8b4fe
    style overrides fill:#3b2a1a,color:#fcd34d
```

## SCF Domain Distribution

How CheckID's 222 checks map across SCF domains.

```mermaid
pie title CheckID Checks by SCF Domain
    "Identification & Auth (IAC)" : 79
    "Configuration Mgmt (CFG)" : 34
    "Network Security (NET)" : 33
    "Endpoint Security (END)" : 30
    "Continuous Monitoring (MON)" : 17
    "Asset Management (AST)" : 7
    "Data Classification (DCH)" : 4
    "Other (9 domains)" : 18
```

## PowerShell Module API

Public cmdlets exposed by `CheckID.psm1` (v2.0.0).

```mermaid
flowchart TB
    subgraph core["Core Registry"]
        GCR["Get-CheckRegistry<br/><i>Load all checks (cached)</i>"]
        GCB["Get-CheckById<br/><i>O(1) lookup by checkId</i>"]
        SC["Search-Check<br/><i>-Framework -ControlId -Keyword<br/>-ScfId -ScfDomain</i>"]
    end

    subgraph scfcmds["SCF Queries"]
        GSC["Get-ScfControl<br/><i>SCF metadata for a check</i>"]
        SCBS["Search-CheckByScf<br/><i>-ScfId or -Domain</i>"]
    end

    subgraph analytics["Analytics"]
        GFC["Get-FrameworkCoverage<br/><i>Coverage stats per framework</i>"]
        GAG["Get-CheckAutomationGaps<br/><i>Non-automated checks</i>"]
    end

    subgraph output["Output"]
        ECM["Export-ComplianceMatrix<br/><i>XLSX multi-framework report</i>"]
        TCR["Test-CheckRegistryData<br/><i>Data quality validation</i>"]
    end

    REG[("registry.json")] --> GCR
    GCR --> GCB & SC & GSC & SCBS & GFC & GAG

    style core fill:#1e3a5f,color:#93c5fd
    style scfcmds fill:#1a3320,color:#86efac
    style analytics fill:#3b1a45,color:#d8b4fe
    style output fill:#3b2a1a,color:#fcd34d
```
