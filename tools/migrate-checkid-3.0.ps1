#Requires -Version 7.0
<#
.SYNOPSIS
    Convert a v2.x-shape CheckID registry.json to the v3.0 structured shape.

.DESCRIPTION
    Helper for downstream consumers (M365-Assess, M365-Remediate, StrykerScan)
    that want to test their v3.0 migration against a known v2.x baseline before
    pulling the actual v3.0 release.

    Reads the input registry.json, parses each check's string `remediation`
    field into the v3.0 structured object via the same heuristic patterns the
    canonical Python parser uses (scripts/Parse-Remediation-3.0.py), and
    writes the result to the output path.

    This is a lightweight PowerShell port of the parser logic. For the
    canonical implementation, see scripts/Parse-Remediation-3.0.py. The two
    are kept compatible by sharing the same regex shapes; behavior differences
    on edge cases land in `notes` rather than mis-classified channels.

.PARAMETER InputPath
    Path to a v2.x CheckID registry.json (where each check has a string
    `remediation` field).

.PARAMETER OutputPath
    Where to write the v3.0-shaped registry.json. Pass '-' to write to stdout.

.EXAMPLE
    pwsh -File tools/migrate-checkid-3.0.ps1 -InputPath ./old-registry.json -OutputPath ./new-registry.json

.NOTES
    Deprecated on arrival — the helper exists to bridge the migration window.
    Once consumers are on v3.0, this script is no longer needed.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $InputPath,
    [Parameter(Mandatory)] [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Portal-name signals — kept in sync with scripts/Parse-Remediation-3.0.py.
$PortalPrefixes = @(
    'Microsoft Entra admin center', 'Entra admin center', 'Azure Portal',
    'Microsoft Purview', 'Microsoft 365 admin center', 'M365 admin center',
    'M365 Admin Center', 'Microsoft 365 Admin Center', 'Exchange admin center',
    'Defender admin center', 'Defender portal', 'Security admin center',
    'Microsoft Defender', 'Defender for Office', 'SharePoint admin center',
    'Teams admin center', 'Teams Admin Center', 'Intune admin center', 'Intune',
    'Power BI Admin portal', 'Power BI', 'Computer Configuration',
    'User Configuration', 'Forms',
    'security\.microsoft\.com\S*', 'compliance\.microsoft\.com\S*',
    'entra\.microsoft\.com\S*', 'portal\.azure\.com\S*', 'admin\.microsoft\.com\S*'
)

$portalAlternation = ($PortalPrefixes -join '|')
$portalPattern  = "(?<portal>(?:$portalAlternation)\s+>\s+.+?)(?=\.\s+[A-Z]|\s+Or(?:\s+use)?:|`$)"
$psPattern      = "(?:^|\s)Run:\s*(?<cmd>.+?)(?=\s+(?:$portalAlternation)|\s+Or(?:\s+use)?:|\s+Connect to|`$)"
$cliPattern     = '(?:Or(?:\s+use)?:\s*)(?<cmd>(?:az|gcloud|aws)\s+\S+(?:\s+[^.]+?))(?:\.\s|\.$|$)'
$gpmcPattern    = 'GPMC:\s*(?<path>[^.]+?)(?:\.\s|\.$|$)'
$graphPattern   = '(?:via\s+)?Microsoft\s+Graph\s+API:?\s*(?<verb>GET|POST|PATCH|PUT|DELETE)\s+(?<endpoint>https?://graph\.microsoft\.com\S+)(?:\s+(?<body>\{[^}]*\}))?'

function ConvertFrom-LegacyRemediationString {
    [CmdletBinding()]
    param([string] $Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return [ordered]@{}
    }

    $remaining = $Text.Trim()
    $result = [ordered]@{}

    # PowerShell first.
    $m = [regex]::Match($remaining, $psPattern, 'IgnoreCase, Singleline')
    if ($m.Success) {
        $cmd = $m.Groups['cmd'].Value.Trim().TrimEnd('.').Trim()
        if ($cmd) { $result['powershell'] = [ordered]@{ command = $cmd } }
        $remaining = ($remaining.Substring(0, $m.Index) + ' ' + $remaining.Substring($m.Index + $m.Length)).Trim()
    }

    # Microsoft Graph API.
    $m = [regex]::Match($remaining, $graphPattern, 'IgnoreCase')
    if ($m.Success) {
        $entry = [ordered]@{
            endpoint = $m.Groups['endpoint'].Value.Trim()
            method   = $m.Groups['verb'].Value.ToUpper()
        }
        $body = $m.Groups['body'].Value
        if ($body) { $entry['body'] = $body.Trim() }
        $result['graph'] = $entry
        $remaining = ($remaining.Substring(0, $m.Index) + ' ' + $remaining.Substring($m.Index + $m.Length)).Trim()
    }

    # CLI (az/gcloud/aws).
    $m = [regex]::Match($remaining, $cliPattern, 'IgnoreCase')
    if ($m.Success) {
        $cmd = $m.Groups['cmd'].Value.Trim().TrimEnd('.').Trim()
        if ($cmd) { $result['cli'] = [ordered]@{ command = $cmd } }
        $remaining = ($remaining.Substring(0, $m.Index) + ' ' + $remaining.Substring($m.Index + $m.Length)).Trim()
    }

    # Windows Group Policy (GPMC).
    $m = [regex]::Match($remaining, $gpmcPattern, 'IgnoreCase')
    if ($m.Success) {
        $rawPath = $m.Groups['path'].Value.Trim()
        $path = "GPMC: $rawPath"
        $steps = ($rawPath -split '\\|\s+>\s+') | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }
        $entry = [ordered]@{ path = $path }
        if ($steps.Count -gt 1) { $entry['steps'] = @($steps) }
        $result['portal'] = $entry
        $remaining = ($remaining.Substring(0, $m.Index) + ' ' + $remaining.Substring($m.Index + $m.Length)).Trim()
    }

    # Generic portal (only if GPMC didn't fire).
    if (-not $result.Contains('portal')) {
        $m = [regex]::Match($remaining, $portalPattern, 'IgnoreCase, Singleline')
        if ($m.Success) {
            $path = $m.Groups['portal'].Value.Trim().TrimEnd('.').Trim()
            $steps = ($path -split '\s+>\s+') | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }
            $entry = [ordered]@{ path = $path }
            if ($steps.Count -gt 1) { $entry['steps'] = @($steps) }
            $result['portal'] = $entry
            $remaining = ($remaining.Substring(0, $m.Index) + ' ' + $remaining.Substring($m.Index + $m.Length)).Trim()
        }
    }

    # Whatever's left → notes.
    $leftover = ($remaining -replace '\s+', ' ').Trim().Trim('.').Trim()
    if ($leftover) { $result['notes'] = $leftover }

    # Normalize key order to match the Python parser's output.
    $ordered = [ordered]@{}
    foreach ($key in 'powershell', 'portal', 'graph', 'cli', 'notes') {
        if ($result.Contains($key)) { $ordered[$key] = $result[$key] }
    }
    return $ordered
}

# --- Main ---

if (-not (Test-Path $InputPath)) {
    throw "Input registry not found: $InputPath"
}

Write-Host "Reading $InputPath..."
$registry = Get-Content -Path $InputPath -Raw | ConvertFrom-Json -AsHashtable

$converted = 0
$alreadyStructured = 0
foreach ($check in $registry.checks) {
    $rem = $check['remediation']
    if ($rem -is [string] -and $rem) {
        $check['remediation'] = ConvertFrom-LegacyRemediationString -Text $rem
        $converted++
    } elseif ($rem -is [System.Collections.IDictionary]) {
        $alreadyStructured++
    }
}

Write-Host "Converted $converted v2.x string remediations to v3.0 structured shape."
if ($alreadyStructured -gt 0) {
    Write-Host "Skipped $alreadyStructured checks that were already structured."
}

$json = $registry | ConvertTo-Json -Depth 32

if ($OutputPath -eq '-') {
    Write-Output $json
} else {
    $json | Set-Content -Path $OutputPath -Encoding utf8
    Write-Host "Wrote $OutputPath"
}
