# Validates the render-taxonomy contract (issue #407 / #318-#323):
# every framework that declares a `groupBy` strategy must declare a group map
# (`groups`, `sections`, or `controls`) whose keys cover EVERY group prefix
# derivable from the controlIds present in data/registry.json. This is what stops
# registry growth from silently landing in a downstream "Other" bucket.

BeforeDiscovery {
    $frameworkDir = Join-Path $PSScriptRoot '..' 'data' 'frameworks'
    $script:groupedFrameworks = foreach ($file in Get-ChildItem -Path $frameworkDir -Filter '*.json') {
        $json = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        if (-not $json.groupBy) { continue }
        $map = if ($json.PSObject.Properties.Name -contains 'groups') { $json.groups }
               elseif ($json.PSObject.Properties.Name -contains 'sections') { $json.sections }
               elseif ($json.PSObject.Properties.Name -contains 'controls') { $json.controls }
               else { $null }
        @{
            Name        = $file.BaseName
            RegistryKey = $json.registryKey
            Strategy    = $json.groupBy
            GroupKeys   = if ($map) { @($map.PSObject.Properties.Name) } else { @() }
        }
    }
}

Describe 'Framework Group Coverage' {

    BeforeAll {
        # Parser per groupBy strategy: controlId -> group key. Mirrors the consumer
        # contract documented on `groupBy` in data/frameworks.schema.json.
        function Get-GroupKey {
            param([string]$Strategy, [string]$ControlId)
            switch ($Strategy) {
                'section-prefix'           { return ($ControlId -split '\.')[0] }
                'dot-prefix'               { return ($ControlId -split '\.')[0] }
                'family-letter-prefix'     { return [regex]::Match($ControlId, '^[A-Za-z]+').Value }
                'soc2-tsc-prefix'          { return [regex]::Match($ControlId, '^[A-Za-z]+').Value }
                'essential-eight-practice' { return [regex]::Match($ControlId, 'P(\d+)').Groups[1].Value }
                'article-prefix'           { return [regex]::Match($ControlId, '^Article\s+(\d+)').Groups[1].Value }
                'scuba-service' {
                    $p = $ControlId -split '\.'
                    return $(if ($p.Count -ge 2) { $p[0..1] -join '.' } else { $ControlId })
                }
                'hipaa-section' {
                    $p = $ControlId -split '\.'
                    return $(if ($p.Count -gt 1) { $p[1] -replace '\D.*$', '' } else { $ControlId })
                }
                'nist-800-171-family' {
                    if ($ControlId.ToUpper().StartsWith('NFO')) { return 'NFO' }
                    $p = $ControlId -split '\.'
                    return $(if ($p.Count -ge 2) { $p[0..1] -join '.' } else { $ControlId })
                }
                default { return $ControlId }
            }
        }

        # Index registry controlIds by framework key (semicolon-split, trimmed).
        $registryPath = Join-Path $PSScriptRoot '..' 'data' 'registry.json'
        $registry = Get-Content -Path $registryPath -Raw | ConvertFrom-Json
        $script:registryControlIds = @{}
        foreach ($check in $registry.checks) {
            foreach ($prop in $check.frameworks.PSObject.Properties) {
                $val = $prop.Value
                $cidString = if ($val -is [string]) { $val } else { $val.controlId }
                if (-not $cidString) { continue }
                if (-not $script:registryControlIds.ContainsKey($prop.Name)) {
                    $script:registryControlIds[$prop.Name] = [System.Collections.Generic.HashSet[string]]::new()
                }
                foreach ($part in ($cidString -split ';')) {
                    $t = $part.Trim()
                    if ($t) { [void]$script:registryControlIds[$prop.Name].Add($t) }
                }
            }
        }
    }

    Context '<Name>' -ForEach $groupedFrameworks {

        It 'declares a non-empty group map' {
            $GroupKeys.Count | Should -BeGreaterThan 0 `
                -Because "framework '$Name' declares groupBy '$Strategy' so it must declare a groups/sections/controls map"
        }

        It 'every registry controlId resolves to a declared group' {
            $declared = [System.Collections.Generic.HashSet[string]]::new([string[]]$GroupKeys)
            $ids = if ($script:registryControlIds.ContainsKey($RegistryKey)) { $script:registryControlIds[$RegistryKey] } else { @() }

            $uncovered = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($cid in $ids) {
                $key = Get-GroupKey -Strategy $Strategy -ControlId $cid
                if (-not $declared.Contains($key)) { [void]$uncovered.Add($key) }
            }

            ($uncovered | Sort-Object) -join ', ' | Should -BeNullOrEmpty `
                -Because "every '$RegistryKey' controlId prefix (strategy '$Strategy') must map to a declared group"
        }
    }
}
