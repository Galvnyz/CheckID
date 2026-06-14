Describe 'Entra Role Tiers Integrity' {
    BeforeAll {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $data = Get-Content -Path "$projectRoot/data/role-tiers.json" -Raw | ConvertFrom-Json
        $registry = Get-Content -Path "$projectRoot/data/registry.json" -Raw | ConvertFrom-Json
        $registryCheckIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($c in $registry.checks) { [void]$registryCheckIds.Add($c.checkId) }

        $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        $tierKeys = @($data.tiers.PSObject.Properties.Name)
    }

    Context 'Top-level structure' {
        It 'Has description, version, tiers' {
            $names = $data.PSObject.Properties.Name
            foreach ($p in @('description', 'version', 'tiers')) { $names | Should -Contain $p }
        }
        It 'Points at the local JSON schema' {
            $data.'$schema' | Should -Be './role-tiers.schema.json'
        }
        It 'Version follows semver' {
            $data.version | Should -Match '^\d+\.\d+\.\d+$'
        }
        It 'Declares the Tier 0 control plane' {
            $tierKeys | Should -Contain '0' -Because 'Tier 0 (control plane) is the whole point'
        }
    }

    Context 'Tier definitions' {
        It 'Every tier has label, description, and at least one role' {
            foreach ($k in $tierKeys) {
                $t = $data.tiers.$k
                $t.label | Should -Not -BeNullOrEmpty -Because "tier '$k' needs a label"
                $t.description | Should -Not -BeNullOrEmpty -Because "tier '$k' needs a description"
                @($t.roles.PSObject.Properties).Count | Should -BeGreaterThan 0 -Because "tier '$k' needs roles"
            }
        }
        It 'Every role key is a GUID with a non-empty name' {
            $bad = @()
            foreach ($k in $tierKeys) {
                foreach ($r in $data.tiers.$k.roles.PSObject.Properties) {
                    if ($r.Name -notmatch $guidPattern) { $bad += "$($r.Name) (tier $k)" }
                    if ([string]::IsNullOrWhiteSpace($r.Value)) { $bad += "$($r.Name) empty name" }
                }
            }
            ($bad -join ', ') | Should -BeNullOrEmpty
        }
        It 'No role appears in more than one tier' {
            $seen = @{}
            $dupes = @()
            foreach ($k in $tierKeys) {
                foreach ($r in $data.tiers.$k.roles.PSObject.Properties) {
                    if ($seen.ContainsKey($r.Name)) { $dupes += "$($r.Value) in tiers $($seen[$r.Name]) and $k" }
                    $seen[$r.Name] = $k
                }
            }
            ($dupes -join '; ') | Should -BeNullOrEmpty -Because 'a role belongs to exactly one tier'
        }
    }

    Context 'Consumer contract' {
        It 'Registry has PIM detection checks that consume tier data' {
            $pim = $registryCheckIds | Where-Object { $_ -like 'ENTRA-PIM-*' }
            @($pim).Count | Should -BeGreaterThan 0 `
                -Because 'role tiers are referenced by PIM detection logic; those checks must exist'
        }
    }
}
