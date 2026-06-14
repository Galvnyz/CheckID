Describe 'Microsoft First-Party AppIds Integrity' {
    BeforeAll {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $dataPath = "$projectRoot/data/microsoft-first-party-appids.json"
        $registryPath = "$projectRoot/data/registry.json"

        $data = Get-Content -Path $dataPath -Raw | ConvertFrom-Json
        $registry = Get-Content -Path $registryPath -Raw | ConvertFrom-Json
        $registryCheckIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($c in $registry.checks) { [void]$registryCheckIds.Add($c.checkId) }

        $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    }

    Context 'Top-level structure' {
        It 'Has required top-level properties' {
            $props = $data.PSObject.Properties.Name
            foreach ($p in @('version', 'lastUpdated', 'purpose', 'sources', 'ownerTenantIds', 'appIds')) {
                $props | Should -Contain $p -Because "'$p' is required"
            }
        }

        It 'Version follows semver format' {
            $data.version | Should -Match '^\d+\.\d+\.\d+$'
        }

        It 'lastUpdated is an ISO date' {
            $data.lastUpdated | Should -Match '^\d{4}-\d{2}-\d{2}$'
        }

        It 'Points at the local JSON schema' {
            $data.'$schema' | Should -Be './microsoft-first-party-appids.schema.json'
        }

        It 'Has at least one owner tenant and many appIds' {
            $data.ownerTenantIds.Count | Should -BeGreaterOrEqual 1
            $data.appIds.Count | Should -BeGreaterOrEqual 1
        }
    }

    Context 'AppId entries' {
        It 'Every appId is a valid GUID' {
            $bad = $data.appIds | Where-Object { $_.appId -notmatch $guidPattern } | ForEach-Object { $_.appId }
            ($bad -join ', ') | Should -BeNullOrEmpty -Because 'every appId must be a GUID'
        }

        It 'Every appId entry has a non-empty name' {
            $bad = $data.appIds | Where-Object { [string]::IsNullOrWhiteSpace($_.name) } | ForEach-Object { $_.appId }
            ($bad -join ', ') | Should -BeNullOrEmpty -Because 'every appId needs a name'
        }

        It 'AppIds are unique (case-insensitive)' {
            $dupes = $data.appIds.appId | ForEach-Object { $_.ToLower() } | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }
            ($dupes -join ', ') | Should -BeNullOrEmpty -Because 'duplicate appIds defeat the allowlist'
        }
    }

    Context 'Owner tenants' {
        It 'Every owner tenant id is a valid GUID' {
            $bad = $data.ownerTenantIds | Where-Object { $_.id -notmatch $guidPattern } | ForEach-Object { $_.id }
            ($bad -join ', ') | Should -BeNullOrEmpty
        }

        It 'Every owner tenant has a non-empty name' {
            $bad = $data.ownerTenantIds | Where-Object { [string]::IsNullOrWhiteSpace($_.name) } | ForEach-Object { $_.id }
            ($bad -join ', ') | Should -BeNullOrEmpty
        }
    }

    Context 'Consumer contract' {
        It 'The consuming check ENTRA-ENTAPP-020 exists in the registry' {
            $registryCheckIds.Contains('ENTRA-ENTAPP-020') | Should -BeTrue `
                -Because 'purpose names ENTRA-ENTAPP-020 as the consumer; it must exist in registry.json'
        }
    }
}
