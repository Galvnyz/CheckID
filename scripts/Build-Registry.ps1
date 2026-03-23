<#
.SYNOPSIS
    Builds the master control registry (registry.json) from SCF as source of truth.

.DESCRIPTION
    Thin wrapper around Build-Registry.py. The Python script queries the SCF
    SQLite database to build registry.json v2.0.0 with full SCF metadata,
    framework mappings, assessment objectives, risks, and threats.

    Inputs:
      - data/scf-check-mapping.json  (check → SCF control assignments)
      - data/scf-framework-map.json  (SCF framework ID → CheckID key)
      - data/framework-titles.json   (human-readable control titles)
      - SecFrame/SCF/scf.db          (SCF SQLite database)

    Output:
      - data/registry.json           (v2.0.0 registry)

.PARAMETER ScfDbPath
    Path to the SCF SQLite database. Defaults to C:/git/SecFrame/SCF/scf.db.

.PARAMETER OutputPath
    Path to write the JSON registry. Defaults to data/registry.json.

.NOTES
    Version:  2.0.0
    Requires: Python 3.10+

.EXAMPLE
    .\scripts\Build-Registry.ps1
    .\scripts\Build-Registry.ps1 -ScfDbPath C:\git\SecFrame\SCF\scf.db
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$ScfDbPath,

    [Parameter()]
    [string]$OutputPath
)

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$pythonScript = Join-Path $repoRoot 'scripts' 'Build-Registry.py'

$args = @($pythonScript)
if ($ScfDbPath) {
    $args += '--scf-db'
    $args += $ScfDbPath
}
if ($OutputPath) {
    $args += '--output'
    $args += $OutputPath
}

& python3 @args
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build-Registry.py failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
