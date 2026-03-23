<#
.SYNOPSIS
    CheckID PowerShell module — stable identifiers for security checks mapped
    across compliance frameworks.
.DESCRIPTION
    Provides cmdlets to load, query, and validate the CheckID registry.
    Wraps the existing script-based functionality into proper module exports.
#>

# Module-scoped registry cache
$script:RegistryCache = $null
$script:RegistryIndex = $null
$script:ModuleRoot = $PSScriptRoot

function Get-CheckRegistry {
    <#
    .SYNOPSIS
        Loads the CheckID registry and returns all checks.
    .DESCRIPTION
        Reads data/registry.json and returns the full check collection.
        Results are cached for the session — call with -Force to reload.
    .PARAMETER Force
        Bypass the cache and reload from disk.
    .OUTPUTS
        PSCustomObject[] — array of check objects from registry.json.
    .EXAMPLE
        $checks = Get-CheckRegistry
        $checks | Where-Object { $_.hasAutomatedCheck } | Measure-Object
    #>
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    if ($script:RegistryCache -and -not $Force) {
        return $script:RegistryCache
    }

    $registryPath = Join-Path $script:ModuleRoot 'data' 'registry.json'
    if (-not (Test-Path $registryPath)) {
        Write-Error "Registry not found: $registryPath"
        return
    }

    $raw = Get-Content -Path $registryPath -Raw | ConvertFrom-Json
    $script:RegistryCache = $raw.checks

    # Build hash index for O(1) lookups
    $script:RegistryIndex = @{}
    foreach ($check in $script:RegistryCache) {
        $script:RegistryIndex[$check.checkId] = $check
    }

    return $script:RegistryCache
}

function Get-CheckById {
    <#
    .SYNOPSIS
        Looks up a single check by its CheckId.
    .PARAMETER CheckId
        The CheckId to look up (e.g., ENTRA-ADMIN-001).
    .OUTPUTS
        PSCustomObject — the matching check, or $null if not found.
    .EXAMPLE
        Get-CheckById -CheckId ENTRA-ADMIN-001
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$CheckId
    )

    if (-not $script:RegistryIndex) { Get-CheckRegistry | Out-Null }
    return $script:RegistryIndex[$CheckId]
}

function Search-Check {
    <#
    .SYNOPSIS
        Searches the CheckID registry by framework, control ID, keyword, or SCF criteria.
    .PARAMETER Framework
        Filter to checks mapped to this framework key (e.g., hipaa, soc2).
    .PARAMETER ControlId
        Search for checks containing this control ID substring.
    .PARAMETER Keyword
        Search check names for this keyword (case-insensitive).
    .PARAMETER ScfId
        Filter to checks mapped to this SCF control ID (primary or additional).
    .PARAMETER ScfDomain
        Filter to checks in this SCF domain (case-insensitive substring match).
    .OUTPUTS
        PSCustomObject[] — matching check objects.
    .EXAMPLE
        Search-Check -Framework hipaa -Keyword 'password'
    .EXAMPLE
        Search-Check -ControlId 'AC-6'
    .EXAMPLE
        Search-Check -ScfId 'IAC-06'
    .EXAMPLE
        Search-Check -ScfDomain 'Endpoint Security'
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Framework,

        [Parameter()]
        [string]$ControlId,

        [Parameter(Position = 0)]
        [string]$Keyword,

        [Parameter()]
        [string]$ScfId,

        [Parameter()]
        [string]$ScfDomain
    )

    $checks = Get-CheckRegistry

    if ($Framework) {
        $checks = $checks | Where-Object {
            $_.frameworks.PSObject.Properties.Name -contains $Framework
        }
    }

    if ($ControlId) {
        $checks = $checks | Where-Object {
            $found = $false
            foreach ($fwProp in $_.frameworks.PSObject.Properties) {
                if ($Framework -and $fwProp.Name -ne $Framework) { continue }
                if ($fwProp.Value.controlId -like "*$ControlId*") {
                    $found = $true
                    break
                }
            }
            $found
        }
    }

    if ($Keyword) {
        $checks = $checks | Where-Object {
            $_.name -like "*$Keyword*"
        }
    }

    if ($ScfId) {
        $checks = $checks | Where-Object {
            $_.scf.primaryControlId -eq $ScfId -or
            ($_.scf.additionalControlIds -and $_.scf.additionalControlIds -contains $ScfId)
        }
    }

    if ($ScfDomain) {
        $checks = $checks | Where-Object {
            $_.scf.domain -like "*$ScfDomain*"
        }
    }

    return @($checks)
}

function Get-ScfControl {
    <#
    .SYNOPSIS
        Returns SCF control metadata for a given CheckId.
    .DESCRIPTION
        Looks up a check by CheckId and returns its scf{} object containing
        domain, controlName, controlDescription, maturityLevels, assessment
        objectives, risks, and threats.
    .PARAMETER CheckId
        The CheckId to look up (e.g., ENTRA-ADMIN-001).
    .OUTPUTS
        PSCustomObject — the scf object for the check, or $null if not found.
    .EXAMPLE
        Get-ScfControl -CheckId ENTRA-ADMIN-001
    .EXAMPLE
        Get-ScfControl ENTRA-MFA-001 | Select-Object primaryControlId, domain, risks
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$CheckId
    )

    $check = Get-CheckById -CheckId $CheckId
    if (-not $check) {
        Write-Warning "Check not found: $CheckId"
        return $null
    }
    return $check.scf
}

function Search-CheckByScf {
    <#
    .SYNOPSIS
        Searches checks by SCF control ID or domain.
    .DESCRIPTION
        Finds all checks that map to a given SCF control ID (primary or additional)
        or belong to a given SCF domain. Convenience wrapper around Search-Check.
    .PARAMETER ScfId
        SCF control ID to search for (exact match, e.g., IAC-06, END-04.1).
    .PARAMETER Domain
        SCF domain to search for (case-insensitive substring, e.g., 'Endpoint').
    .OUTPUTS
        PSCustomObject[] — matching check objects.
    .EXAMPLE
        Search-CheckByScf -ScfId 'IAC-06'
    .EXAMPLE
        Search-CheckByScf -Domain 'Identification & Authentication'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$ScfId,

        [Parameter()]
        [string]$Domain
    )

    $params = @{}
    if ($ScfId) { $params['ScfId'] = $ScfId }
    if ($Domain) { $params['ScfDomain'] = $Domain }
    return Search-Check @params
}

function Get-FrameworkCoverage {
    <#
    .SYNOPSIS
        Returns coverage statistics per compliance framework.
    .DESCRIPTION
        Calculates how many checks map to each framework, broken down by
        automated vs manual. When a framework definition file exists,
        includes totalControls and coverage percentage.
    .PARAMETER Framework
        Filter to a single framework key (e.g., 'nist-800-53', 'soc2').
    .OUTPUTS
        PSCustomObject[] — one object per framework with coverage stats.
    .EXAMPLE
        Get-FrameworkCoverage
    .EXAMPLE
        Get-FrameworkCoverage -Framework 'nist-800-53'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Framework
    )

    $checks = Get-CheckRegistry

    # Load framework definitions for totalControls
    $fwDefsPath = Join-Path $script:ModuleRoot 'data' 'frameworks'
    $fwDefs = @{}
    if (Test-Path $fwDefsPath) {
        foreach ($file in Get-ChildItem $fwDefsPath -Filter '*.json') {
            $def = Get-Content $file.FullName -Raw | ConvertFrom-Json
            $key = if ($def.frameworkId) { $def.frameworkId } else { $def.framework }
            if ($key) { $fwDefs[$key] = $def }
        }
    }

    # Collect all framework keys
    $allFrameworks = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($check in $checks) {
        foreach ($prop in $check.frameworks.PSObject.Properties) {
            [void]$allFrameworks.Add($prop.Name)
        }
    }

    if ($Framework) {
        $allFrameworks = @($Framework)
    }

    foreach ($fw in ($allFrameworks | Sort-Object)) {
        $mapped = @($checks | Where-Object {
            $_.frameworks.PSObject.Properties.Name -contains $fw
        })
        $automated = @($mapped | Where-Object { $_.hasAutomatedCheck -eq $true })
        $manual = @($mapped | Where-Object { $_.hasAutomatedCheck -eq $false })

        $totalControls = $null
        $coveragePct = $null
        if ($fwDefs.ContainsKey($fw)) {
            $def = $fwDefs[$fw]
            $totalControls = if ($def.totalControls) { $def.totalControls }
                             elseif ($def.controls) { $def.controls }
                             else { $null }
            if ($totalControls -and $totalControls -gt 0) {
                $coveragePct = [math]::Round(($mapped.Count / $totalControls) * 100, 1)
            }
        }

        [PSCustomObject]@{
            Framework      = $fw
            MappedChecks   = $mapped.Count
            Automated      = $automated.Count
            Manual         = $manual.Count
            TotalControls  = $totalControls
            CoveragePct    = $coveragePct
        }
    }
}

function Get-CheckAutomationGaps {
    <#
    .SYNOPSIS
        Returns checks that lack automated assessment.
    .DESCRIPTION
        Identifies checks where hasAutomatedCheck is false, indicating they
        lack automated assessment. Optionally filters by framework.
    .PARAMETER Framework
        Filter to checks mapped to this framework key (e.g., 'hipaa', 'cmmc').
    .OUTPUTS
        PSCustomObject[] - check objects lacking automated assessment.
    .EXAMPLE
        Get-CheckAutomationGaps
    .EXAMPLE
        Get-CheckAutomationGaps -Framework 'hipaa'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Framework
    )

    $checks = Get-CheckRegistry
    $checks = $checks | Where-Object { $_.hasAutomatedCheck -eq $false }

    if ($Framework) {
        $checks = $checks | Where-Object {
            $_.frameworks.PSObject.Properties.Name -contains $Framework
        }
    }

    return @($checks)
}

function Export-ComplianceMatrix {
    <#
    .SYNOPSIS
        Exports a compliance matrix workbook from assessment data.
    .DESCRIPTION
        Wrapper around scripts/Export-ComplianceMatrix.ps1. Reads collector
        CSVs from an assessment folder and generates an XLSX compliance matrix.
    .PARAMETER AssessmentFolder
        Path to the assessment output folder containing collector CSVs.
    .PARAMETER TenantName
        Optional tenant name for the output filename.
    .OUTPUTS
        None - writes an XLSX file to the assessment folder.
    .EXAMPLE
        Export-ComplianceMatrix -AssessmentFolder ./Assessment_20260311
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AssessmentFolder,

        [Parameter()]
        [string]$TenantName
    )

    $scriptPath = Join-Path $script:ModuleRoot 'scripts' 'Export-ComplianceMatrix.ps1'
    $params = @{ AssessmentFolder = $AssessmentFolder }
    if ($TenantName) { $params['TenantName'] = $TenantName }
    & $scriptPath @params
}

function Test-CheckRegistryData {
    <#
    .SYNOPSIS
        Runs data quality validation checks against the registry.
    .DESCRIPTION
        Wrapper around scripts/Test-RegistryData.ps1. Returns $true if all
        checks pass, $false otherwise.
    .OUTPUTS
        Boolean — $true if all validation checks pass.
    .EXAMPLE
        if (-not (Test-CheckRegistryData)) { Write-Error "Registry validation failed" }
    #>
    [CmdletBinding()]
    param()

    $scriptPath = Join-Path $script:ModuleRoot 'scripts' 'Test-RegistryData.ps1'
    if (-not (Test-Path $scriptPath)) {
        Write-Error "Validation script not found: $scriptPath"
        return $false
    }

    & $scriptPath -DataPath (Join-Path $script:ModuleRoot 'data')
    return $LASTEXITCODE -eq 0
}

# Export module members
Export-ModuleMember -Function @(
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
