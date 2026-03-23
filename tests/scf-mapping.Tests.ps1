Describe 'SCF Mapping Consistency' {
    BeforeAll {
        $registryPath = "$PSScriptRoot/../data/registry.json"
        $mappingPath  = "$PSScriptRoot/../data/scf-check-mapping.json"
        $raw      = Get-Content -Path $registryPath -Raw | ConvertFrom-Json
        $mapping  = Get-Content -Path $mappingPath  -Raw | ConvertFrom-Json
        $checks   = $raw.checks
    }

    # --- Source file consistency ---

    It 'Registry check count matches scf-check-mapping.json count' {
        $checks.Count | Should -Be $mapping.checks.Count `
            -Because "every check in scf-check-mapping.json should produce a registry entry"
    }

    It 'All CheckIds in scf-check-mapping.json appear in registry' {
        $registryIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($c in $checks) { [void]$registryIds.Add($c.checkId) }
        foreach ($mc in $mapping.checks) {
            $registryIds | Should -Contain $mc.checkId `
                -Because "$($mc.checkId) is in scf-check-mapping.json but missing from registry"
        }
    }

    # --- SCF primary control validity ---

    It 'Every scfPrimary in the mapping file has a valid SCF ID format' {
        foreach ($mc in $mapping.checks) {
            $mc.scfPrimary | Should -Match '^[A-Z]{2,4}-\d{2}(\.\d+)?$' `
                -Because "$($mc.checkId) scfPrimary '$($mc.scfPrimary)' must be a valid SCF control ID"
        }
    }

    It 'Registry scf.primaryControlId matches the mapping file' {
        $mappingLookup = @{}
        foreach ($mc in $mapping.checks) {
            $mappingLookup[$mc.checkId] = $mc.scfPrimary
        }
        foreach ($check in $checks) {
            $expected = $mappingLookup[$check.checkId]
            $check.scf.primaryControlId | Should -Be $expected `
                -Because "$($check.checkId) registry SCF primary should match mapping file"
        }
    }

    # --- SCF domain coverage ---

    It 'At least 5 distinct SCF domains are represented' {
        $domains = $checks | ForEach-Object { $_.scf.domain } | Sort-Object -Unique
        $domains.Count | Should -BeGreaterOrEqual 5 `
            -Because "checks should span multiple SCF domains (currently $($domains.Count))"
    }

    # --- No orphaned data ---

    It 'No duplicate CheckIds in scf-check-mapping.json' {
        $ids = $mapping.checks | ForEach-Object { $_.checkId }
        $dupes = $ids | Group-Object | Where-Object { $_.Count -gt 1 }
        $dupes | Should -BeNullOrEmpty -Because "scf-check-mapping.json must not have duplicate CheckIds"
    }

    It 'Manual overlay fields (CIS, CISA ScuBA, STIG) match between mapping and registry' {
        $mappingLookup = @{}
        foreach ($mc in $mapping.checks) {
            $mappingLookup[$mc.checkId] = $mc
        }
        foreach ($check in $checks) {
            $mc = $mappingLookup[$check.checkId]
            if ($mc.cisM365ControlId) {
                $check.frameworks.PSObject.Properties.Name | Should -Contain 'cis-m365-v6' `
                    -Because "$($check.checkId) has CIS mapping in source and should appear in registry"
                $check.frameworks.'cis-m365-v6'.controlId | Should -Be $mc.cisM365ControlId
            }
            if ($mc.cisaScubaControlId) {
                $check.frameworks.PSObject.Properties.Name | Should -Contain 'cisa-scuba' `
                    -Because "$($check.checkId) has CISA ScuBA mapping in source"
                $check.frameworks.'cisa-scuba'.controlId | Should -Be $mc.cisaScubaControlId
            }
            if ($mc.stigControlId) {
                $check.frameworks.PSObject.Properties.Name | Should -Contain 'stig' `
                    -Because "$($check.checkId) has STIG mapping in source"
                $check.frameworks.stig.controlId | Should -Be $mc.stigControlId
            }
        }
    }
}
