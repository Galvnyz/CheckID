Describe 'Control Registry Integrity' {
    BeforeAll {
        $registryPath = "$PSScriptRoot/../data/registry.json"
        $raw = Get-Content -Path $registryPath -Raw | ConvertFrom-Json
        $checks = $raw.checks
    }

    # --- Schema-level tests ---

    It 'Has schemaVersion 2.0.0' {
        $raw.schemaVersion | Should -Be '2.0.0' `
            -Because "registry must be schema version 2.0.0 (SCF-based)"
    }

    It 'Has dataVersion field with valid date format' {
        $raw.dataVersion | Should -Match '^\d{4}-\d{2}-\d{2}$' `
            -Because "dataVersion must be a YYYY-MM-DD date"
    }

    It 'Has generatedFrom field referencing SCF sources' {
        $raw.generatedFrom | Should -Not -BeNullOrEmpty
        $raw.generatedFrom | Should -Match 'scf' `
            -Because "generatedFrom must reference SCF data sources"
    }

    # --- Check count and uniqueness ---

    It 'Has at least 160 entries' {
        $checks.Count | Should -BeGreaterOrEqual 160
    }

    It 'Has no duplicate CheckIds' {
        $ids = $checks | ForEach-Object { $_.checkId }
        $dupes = $ids | Group-Object | Where-Object { $_.Count -gt 1 }
        $dupes | Should -BeNullOrEmpty -Because "CheckIds must be unique"
    }

    # --- Required fields ---

    It 'Every entry has required fields' {
        foreach ($check in $checks) {
            $check.checkId | Should -Not -BeNullOrEmpty
            $check.name | Should -Not -BeNullOrEmpty
            $check.frameworks | Should -Not -BeNullOrEmpty
        }
    }

    It 'Every entry has a licensing.minimum field' {
        foreach ($check in $checks) {
            $check.licensing.minimum | Should -BeIn @('E3', 'E5') `
                -Because "$($check.checkId) must have a valid licensing.minimum (E3 or E5)"
        }
    }

    It 'hasAutomatedCheck is explicitly set for all checks' {
        foreach ($check in $checks) {
            $check.PSObject.Properties.Name | Should -Contain 'hasAutomatedCheck' `
                -Because "$($check.checkId) must have an explicit hasAutomatedCheck field"
        }
    }

    # --- SCF fields (v2.0.0) ---

    It 'Every entry has an scf object' {
        foreach ($check in $checks) {
            $check.PSObject.Properties.Name | Should -Contain 'scf' `
                -Because "$($check.checkId) must have an scf object (schema v2.0.0)"
        }
    }

    It 'Every entry has scf.primaryControlId matching SCF pattern' {
        foreach ($check in $checks) {
            $check.scf.primaryControlId | Should -Match '^[A-Z]{2,4}-\d{2}(\.\d+)?$' `
                -Because "$($check.checkId) scf.primaryControlId must match SCF ID format (e.g., IAC-06, END-04.1)"
        }
    }

    It 'Every entry has scf.domain' {
        foreach ($check in $checks) {
            $check.scf.domain | Should -Not -BeNullOrEmpty `
                -Because "$($check.checkId) must have an scf.domain"
        }
    }

    It 'Every entry has scf.controlName and scf.controlDescription' {
        foreach ($check in $checks) {
            $check.scf.controlName | Should -Not -BeNullOrEmpty `
                -Because "$($check.checkId) must have scf.controlName"
            $check.scf.PSObject.Properties.Name | Should -Contain 'controlDescription' `
                -Because "$($check.checkId) must have scf.controlDescription"
        }
    }

    It 'scf.maturityLevels has all 6 CMM boolean fields when present' {
        $cmmFields = @('cmm0_notPerformed', 'cmm1_informal', 'cmm2_planned', 'cmm3_defined', 'cmm4_controlled', 'cmm5_improving')
        foreach ($check in $checks) {
            if ($check.scf.PSObject.Properties.Name -contains 'maturityLevels') {
                foreach ($field in $cmmFields) {
                    $check.scf.maturityLevels.PSObject.Properties.Name | Should -Contain $field `
                        -Because "$($check.checkId) scf.maturityLevels must include $field"
                }
            }
        }
    }

    It 'scf.risks values match R-XX-N pattern when present' {
        foreach ($check in $checks) {
            if ($check.scf.PSObject.Properties.Name -contains 'risks' -and $check.scf.risks) {
                foreach ($risk in $check.scf.risks) {
                    $risk | Should -Match '^R-[A-Z]{2}-\d+$' `
                        -Because "$($check.checkId) risk '$risk' must match R-XX-N format"
                }
            }
        }
    }

    It 'scf.threats values match NT-N or MT-N pattern when present' {
        foreach ($check in $checks) {
            if ($check.scf.PSObject.Properties.Name -contains 'threats' -and $check.scf.threats) {
                foreach ($threat in $check.scf.threats) {
                    $threat | Should -Match '^[NM]T-\d+$' `
                        -Because "$($check.checkId) threat '$threat' must match NT-N or MT-N format"
                }
            }
        }
    }

    It 'scf.assessmentObjectives have aoId and text when present' {
        foreach ($check in $checks) {
            if ($check.scf.PSObject.Properties.Name -contains 'assessmentObjectives' -and $check.scf.assessmentObjectives) {
                foreach ($ao in $check.scf.assessmentObjectives) {
                    $ao.aoId | Should -Not -BeNullOrEmpty `
                        -Because "$($check.checkId) assessment objective must have an aoId"
                    $ao.text | Should -Not -BeNullOrEmpty `
                        -Because "$($check.checkId) assessment objective $($ao.aoId) must have text"
                }
            }
        }
    }

    It 'scf.relativeWeighting is between 1 and 10 when present' {
        foreach ($check in $checks) {
            if ($check.scf.PSObject.Properties.Name -contains 'relativeWeighting' -and $null -ne $check.scf.relativeWeighting) {
                $check.scf.relativeWeighting | Should -BeGreaterOrEqual 1 `
                    -Because "$($check.checkId) weighting must be >= 1"
                $check.scf.relativeWeighting | Should -BeLessOrEqual 10 `
                    -Because "$($check.checkId) weighting must be <= 10"
            }
        }
    }

    # --- Naming conventions ---

    It 'All CheckIds follow the {SERVICE}-{AREA}-{NNN} naming convention' {
        foreach ($check in $checks) {
            $check.checkId | Should -Match '^[A-Z]+-[A-Z0-9-]+-\d{3}$' `
                -Because "$($check.checkId) must follow {SERVICE}-{AREA}-{NNN} naming convention"
        }
    }

    It 'All automated checks have a collector field' {
        $automated = $checks | Where-Object { $_.hasAutomatedCheck -eq $true }
        foreach ($check in $automated) {
            $check.collector | Should -Not -BeNullOrEmpty `
                -Because "$($check.checkId) is automated and needs a collector"
        }
    }

    It 'Collector values are from the known set' {
        $knownCollectors = @('Entra', 'CAEvaluator', 'ExchangeOnline', 'DNS', 'Defender', 'Compliance', 'Intune', 'SharePoint', 'Teams', 'PowerBI', 'StrykerReadiness', 'Forms', 'PurviewRetention', 'EntApp')
        $automated = $checks | Where-Object { $_.hasAutomatedCheck -eq $true }
        foreach ($check in $automated) {
            $check.collector | Should -BeIn $knownCollectors `
                -Because "$($check.checkId) collector '$($check.collector)' must be a known collector"
        }
    }

    # --- CIS framework ---

    It 'CIS-mapped entries have valid CIS framework data' {
        $cisMapped = $checks | Where-Object { $_.frameworks.PSObject.Properties.Name -contains 'cis-m365-v6' }
        $cisMapped.Count | Should -BeGreaterOrEqual 130 -Because "at least 130 CIS benchmark controls exist"
        foreach ($check in $cisMapped) {
            $check.frameworks.'cis-m365-v6'.controlId | Should -Not -BeNullOrEmpty `
                -Because "$($check.checkId) has CIS mapping and needs a controlId"
        }
    }

    It 'CIS profiles contain only valid values' {
        $validProfiles = @('E3-L1', 'E3-L2', 'E5-L1', 'E5-L2')
        $cisMapped = $checks | Where-Object { $_.frameworks.PSObject.Properties.Name -contains 'cis-m365-v6' }
        foreach ($check in $cisMapped) {
            $profiles = $check.frameworks.'cis-m365-v6'.profiles
            if ($profiles -and $profiles.Count -gt 0) {
                foreach ($p in $profiles) {
                    $p | Should -BeIn $validProfiles `
                        -Because "$($check.checkId) profile '$p' must be a valid CIS profile"
                }
            }
        }
    }

    # --- NIST 800-53 profiles ---

    It 'Most NIST 800-53 entries have profiles array' {
        $nistMapped = $checks | Where-Object { $_.frameworks.PSObject.Properties.Name -contains 'nist-800-53' }
        $nistMapped.Count | Should -BeGreaterOrEqual 1 -Because "at least some checks must map to NIST 800-53"
        $withProfiles = @($nistMapped | Where-Object { $_.frameworks.'nist-800-53'.profiles }).Count
        $withProfiles | Should -BeGreaterOrEqual ($nistMapped.Count * 0.9) `
            -Because "at least 90% of NIST 800-53 entries should have baseline profiles"
    }

    # --- Framework coverage ---

    It 'All 15 frameworks are represented across checks' {
        $expectedFrameworks = @('cis-m365-v6', 'nist-800-53', 'nist-csf', 'iso-27001', 'stig', 'pci-dss', 'cmmc', 'hipaa', 'cisa-scuba', 'soc2', 'fedramp', 'cis-controls-v8', 'essential-eight', 'mitre-attack', 'gdpr')
        $allFrameworks = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($check in $checks) {
            foreach ($prop in $check.frameworks.PSObject.Properties) {
                [void]$allFrameworks.Add($prop.Name)
            }
        }
        foreach ($fw in $expectedFrameworks) {
            $allFrameworks | Should -Contain $fw `
                -Because "framework '$fw' must be present in at least one check"
        }
    }

    It 'Essential Eight control IDs follow ML{n}-P{n} format' {
        $e8Mapped = $checks | Where-Object { $_.frameworks.PSObject.Properties.Name -contains 'essential-eight' }
        $e8Mapped.Count | Should -BeGreaterOrEqual 1 -Because "at least some checks must map to Essential Eight"
        foreach ($check in $e8Mapped) {
            $controlId = $check.frameworks.'essential-eight'.controlId
            $controlId | Should -Not -BeNullOrEmpty `
                -Because "$($check.checkId) has Essential Eight mapping and needs a controlId"
            foreach ($part in ($controlId -split ';')) {
                $part.Trim() | Should -Match '^ML[1-3]-P[1-8]$' `
                    -Because "$($check.checkId) Essential Eight controlId part '$($part.Trim())' must follow ML{1-3}-P{1-8} format"
            }
        }
    }

    It 'Essential Eight framework definition file exists and is valid' {
        $e8Path = "$PSScriptRoot/../data/frameworks/essential-eight.json"
        Test-Path $e8Path | Should -Be $true -Because "Essential Eight framework definition file must exist"
        $e8 = Get-Content -Path $e8Path -Raw | ConvertFrom-Json
        $e8.frameworkId | Should -Be 'essential-eight'
        $e8.scoring.maturityLevels.PSObject.Properties.Name | Should -Contain 'ML1'
        $e8.scoring.maturityLevels.PSObject.Properties.Name | Should -Contain 'ML2'
        $e8.scoring.maturityLevels.PSObject.Properties.Name | Should -Contain 'ML3'
        $e8.strategies.PSObject.Properties.Name.Count | Should -Be 8 `
            -Because "Essential Eight has 8 mitigation strategies"
    }

    # --- Impact rating ---

    It 'impactRating severity values are from the valid enum when present' {
        $validSeverities = @('Critical', 'High', 'Medium', 'Low', 'Informational')
        $withRating = @($checks | Where-Object { $_.PSObject.Properties.Name -contains 'impactRating' })
        $withRating.Count | Should -BeGreaterOrEqual 1 -Because 'at least some checks should have impactRating'
        foreach ($check in $withRating) {
            $check.impactRating.severity | Should -BeIn $validSeverities `
                -Because "$($check.checkId) impactRating.severity must be a valid value"
        }
    }

    # --- SCF domain consistency ---

    It 'Checks are sorted by SCF domain' {
        $domains = $checks | ForEach-Object { $_.scf.domain }
        $uniqueDomainsInOrder = @()
        foreach ($d in $domains) {
            if ($uniqueDomainsInOrder.Count -eq 0 -or $uniqueDomainsInOrder[-1] -ne $d) {
                $uniqueDomainsInOrder += $d
            }
        }
        # Each domain should appear as a contiguous block (no interleaving)
        $domainCounts = $domains | Group-Object | ForEach-Object { $_.Count }
        $blockCounts = $uniqueDomainsInOrder | Group-Object | ForEach-Object { $_.Count }
        $blockCounts | ForEach-Object {
            $_ | Should -Be 1 -Because "each SCF domain should appear as one contiguous block (sorted)"
        }
    }
}
