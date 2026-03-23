<#
.SYNOPSIS
    Validates registry data integrity and encoding.
.DESCRIPTION
    Standalone validation script that checks the control registry and its SCF
    source files for common data quality issues:
      - UTF-8 encoding
      - Duplicate CheckIds
      - Empty required fields
      - SCF mapping consistency

    Returns exit code 0 if all checks pass, 1 if any fail. Suitable for CI and
    local use.
.PARAMETER DataPath
    Path to the data directory containing registry.json and SCF files.
    Defaults to data/ relative to the repository root.
.EXAMPLE
    ./scripts/Test-RegistryData.ps1
.NOTES
    Version: 2.0.0
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$DataPath
)

$ErrorActionPreference = 'Stop'

# Resolve paths
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $DataPath) {
    $DataPath = Join-Path $repoRoot 'data'
}

$registryPath  = Join-Path $DataPath 'registry.json'
$mappingPath   = Join-Path $DataPath 'scf-check-mapping.json'
$fwMapPath     = Join-Path $DataPath 'scf-framework-map.json'

$errors   = [System.Collections.Generic.List[string]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()
$passed   = 0

function Test-Check {
    param([string]$Name, [scriptblock]$Test)
    try {
        $result = & $Test
        if ($result) {
            $script:errors.Add("FAIL: $Name - $result")
            Write-Host "  FAIL: $Name" -ForegroundColor Red
            Write-Host "        $result" -ForegroundColor Red
        } else {
            $script:passed++
            Write-Host "  PASS: $Name" -ForegroundColor Green
        }
    } catch {
        $script:errors.Add("FAIL: $Name - $($_.Exception.Message)")
        Write-Host "  FAIL: $Name" -ForegroundColor Red
        Write-Host "        $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nCheckID Data Quality Validation" -ForegroundColor Cyan
Write-Host "================================`n"

# ------------------------------------------------------------------
# 1. File existence
# ------------------------------------------------------------------
Write-Host "File checks:" -ForegroundColor Yellow
foreach ($file in @($registryPath, $mappingPath, $fwMapPath)) {
    $name = Split-Path $file -Leaf
    Test-Check "File exists: $name" {
        if (-not (Test-Path $file)) { return "File not found: $file" }
    }
}

if (-not (Test-Path $registryPath) -or -not (Test-Path $mappingPath)) {
    Write-Host "`nCritical files missing — cannot continue." -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------------
# 2. JSON validity
# ------------------------------------------------------------------
Write-Host "`nJSON checks:" -ForegroundColor Yellow
$reg = $null
Test-Check "registry.json is valid JSON" {
    try {
        $script:reg = Get-Content $registryPath -Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return "Invalid JSON: $($_.Exception.Message)"
    }
}

if (-not $reg) { Write-Host "`nRegistry JSON invalid — cannot continue." -ForegroundColor Red; exit 1 }

Test-Check "registry.json has schemaVersion 2.0.0" {
    if (-not $reg.schemaVersion) { return "Missing schemaVersion field" }
    if ($reg.schemaVersion -ne '2.0.0') { return "Expected schemaVersion 2.0.0, got '$($reg.schemaVersion)'" }
}

Test-Check "registry.json has dataVersion" {
    if (-not $reg.dataVersion) { return "Missing dataVersion field" }
    if ($reg.dataVersion -notmatch '^\d{4}-\d{2}-\d{2}$') { return "dataVersion '$($reg.dataVersion)' is not YYYY-MM-DD" }
}

# ------------------------------------------------------------------
# 3. Duplicate CheckIds
# ------------------------------------------------------------------
Write-Host "`nUniqueness checks:" -ForegroundColor Yellow
Test-Check "No duplicate CheckIds in registry" {
    $dupes = $reg.checks | ForEach-Object { $_.checkId } | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($dupes) {
        $names = ($dupes | ForEach-Object { "$($_.Name) (x$($_.Count))" }) -join ', '
        return "Duplicate CheckIds: $names"
    }
}

# ------------------------------------------------------------------
# 4. Required fields
# ------------------------------------------------------------------
Write-Host "`nRequired field checks:" -ForegroundColor Yellow
Test-Check "All checks have checkId, name, scf, frameworks" {
    $bad = @()
    foreach ($c in $reg.checks) {
        if (-not $c.checkId) { $bad += "missing checkId" }
        elseif (-not $c.name) { $bad += "$($c.checkId): missing name" }
        elseif (-not $c.scf) { $bad += "$($c.checkId): missing scf" }
        elseif (-not $c.scf.primaryControlId) { $bad += "$($c.checkId): missing scf.primaryControlId" }
        elseif (-not $c.frameworks) { $bad += "$($c.checkId): missing frameworks" }
    }
    if ($bad.Count -gt 0) { return ($bad | Select-Object -First 5) -join '; ' }
}

Test-Check "All automated checks have collector" {
    $bad = @()
    foreach ($c in $reg.checks) {
        if ($c.hasAutomatedCheck -eq $true -and [string]::IsNullOrWhiteSpace($c.collector)) {
            $bad += $c.checkId
        }
    }
    if ($bad.Count -gt 0) { return "Missing collector on: $($bad -join ', ')" }
}

# ------------------------------------------------------------------
# 5. SCF mapping consistency
# ------------------------------------------------------------------
Write-Host "`nSCF consistency checks:" -ForegroundColor Yellow
$mapping = $null
Test-Check "scf-check-mapping.json is valid and matches registry count" {
    try {
        $script:mapping = Get-Content $mappingPath -Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return "Invalid JSON: $($_.Exception.Message)"
    }
    if ($mapping.checks.Count -ne $reg.checks.Count) {
        return "Mapping has $($mapping.checks.Count) checks, registry has $($reg.checks.Count)"
    }
}

Test-Check "All SCF primary IDs have valid format" {
    $bad = @()
    foreach ($c in $reg.checks) {
        if ($c.scf.primaryControlId -notmatch '^[A-Z]{2,4}-\d{2}(\.\d+)?$') {
            $bad += "$($c.checkId): '$($c.scf.primaryControlId)'"
        }
    }
    if ($bad.Count -gt 0) { return "Invalid SCF IDs: $($bad -join ', ')" }
}

# ------------------------------------------------------------------
# 6. Encoding checks
# ------------------------------------------------------------------
Write-Host "`nEncoding checks:" -ForegroundColor Yellow
Test-Check "No garbled encoding in registry JSON" {
    $raw = Get-Content $registryPath -Raw
    if ($raw -match 'Â§') { return "Garbled section symbol (Â§) found in registry.json" }
    if ($raw -match '┬º') { return "Mojibake section symbol found in registry.json" }
}

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "Passed: $passed" -ForegroundColor Green
if ($errors.Count -gt 0) {
    Write-Host "Failed: $($errors.Count)" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All data quality checks passed." -ForegroundColor Green
    exit 0
}
