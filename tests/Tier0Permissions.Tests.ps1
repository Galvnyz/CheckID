Describe 'Tier 0 Graph Permissions Integrity' {
    BeforeAll {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $data = Get-Content -Path "$projectRoot/data/tier0-permissions.json" -Raw | ConvertFrom-Json
        $permPattern = '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$'
        $perms = @($data.permissions)
    }

    Context 'Top-level structure' {
        It 'Has description, version, permissions' {
            $names = $data.PSObject.Properties.Name
            foreach ($p in @('description', 'version', 'permissions')) { $names | Should -Contain $p }
        }
        It 'Points at the local JSON schema' {
            $data.'$schema' | Should -Be './tier0-permissions.schema.json'
        }
        It 'Has at least one permission' {
            $perms.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Permission entries' {
        It 'Every entry has permission, category, and attackPath' {
            $bad = $perms | Where-Object {
                [string]::IsNullOrWhiteSpace($_.permission) -or
                [string]::IsNullOrWhiteSpace($_.category) -or
                [string]::IsNullOrWhiteSpace($_.attackPath)
            } | ForEach-Object { $_.permission }
            ($bad -join ', ') | Should -BeNullOrEmpty
        }
        It 'Every permission name is a well-formed Graph permission' {
            $bad = $perms | Where-Object { $_.permission -notmatch $permPattern } | ForEach-Object { $_.permission }
            ($bad -join ', ') | Should -BeNullOrEmpty
        }
        It 'Permission names are unique' {
            $dupes = $perms.permission | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }
            ($dupes -join ', ') | Should -BeNullOrEmpty
        }
    }

    Context 'Tier 1 data access list' {
        It 'Entries (if any) are unique non-empty Graph permissions' {
            if ($data.tier1DataAccess) {
                $bad = $data.tier1DataAccess | Where-Object { $_ -notmatch $permPattern }
                ($bad -join ', ') | Should -BeNullOrEmpty
                $dupes = $data.tier1DataAccess | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }
                ($dupes -join ', ') | Should -BeNullOrEmpty
            }
        }
    }
}
