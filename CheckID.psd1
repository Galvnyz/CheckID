@{
    # Module metadata
    RootModule        = 'CheckID.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'a3b7c4d5-1e2f-4a5b-8c9d-0e1f2a3b4c5d'
    Author            = 'Galvnyz'
    CompanyName       = 'Galvnyz'
    Copyright         = '(c) Galvnyz. All rights reserved. MIT License.'
    Description       = 'Stable, unique identifiers for security configuration checks mapped across 15 compliance frameworks. Source of truth: SCF (Secure Controls Framework).'

    # Requirements
    PowerShellVersion = '7.0'

    # Exported members
    FunctionsToExport = @(
        'Export-ComplianceMatrix'
        'Get-CheckAutomationGaps'
        'Get-CheckById'
        'Get-CheckRegistry'
        'Get-FrameworkCoverage'
        'Get-ScfControl'
        'Search-Check'
        'Search-CheckByScf'
        'Test-CheckRegistryData'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    # Module data
    FileList = @(
        'CheckID.psd1'
        'CheckID.psm1'
        'data/registry.json'
        'data/registry.schema.json'
        'data/framework-titles.json'
        'data/scf-check-mapping.json'
        'data/scf-framework-map.json'
        'data/frameworks/cis-controls-v8.json'
        'data/frameworks/cis-m365-v6.json'
        'data/frameworks/cisa-scuba.json'
        'data/frameworks/cmmc.json'
        'data/frameworks/essential-eight.json'
        'data/frameworks/fedramp.json'
        'data/frameworks/hipaa.json'
        'data/frameworks/iso-27001.json'
        'data/frameworks/mitre-attack.json'
        'data/frameworks/nist-800-53-r5.json'
        'data/frameworks/nist-csf.json'
        'data/frameworks/pci-dss-v4.json'
        'data/frameworks/soc2-tsc.json'
        'data/frameworks/stig.json'
        'scripts/Build-Registry.ps1'
        'scripts/Build-Registry.py'
        'scripts/Build-FrameworkTitles.py'
        'scripts/Export-ComplianceMatrix.ps1'
        'scripts/Test-RegistryData.ps1'
    )

    PrivateData = @{
        PSData = @{
            LicenseUri   = 'https://github.com/Galvnyz/CheckID/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/Galvnyz/CheckID'
            ReleaseNotes = 'v2.0.0: SCF rebase — every check now has SCF control metadata (domain, maturity levels, assessment objectives, risks, threats). All framework mappings derived from SCF database. New cmdlets: Get-ScfControl, Search-CheckByScf. Schema v2.0.0.'
        }
    }
}
