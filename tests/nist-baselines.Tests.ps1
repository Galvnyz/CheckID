Describe 'NIST 800-53 Baseline Profiles' {
    BeforeAll {
        $registryPath = "$PSScriptRoot/../data/registry.json"
        $raw = Get-Content -Path $registryPath -Raw | ConvertFrom-Json
        $checks = $raw.checks

        $frameworkDefPath = "$PSScriptRoot/../data/frameworks/nist-800-53-r5.json"
        $frameworkDef = Get-Content -Path $frameworkDefPath -Raw | ConvertFrom-Json

        $nistChecks = $checks | Where-Object {
            $_.frameworks.PSObject.Properties.Name -contains 'nist-800-53'
        }
    }

    It 'Framework definition exists and has 4 profiles' {
        $frameworkDef | Should -Not -BeNullOrEmpty
        $frameworkDef.frameworkId | Should -Be 'nist-800-53'
        $frameworkDef.scoring.method | Should -Be 'profile-compliance'
        $profileNames = $frameworkDef.scoring.profiles.PSObject.Properties.Name
        $profileNames.Count | Should -Be 4
        $profileNames | Should -Contain 'Low'
        $profileNames | Should -Contain 'Moderate'
        $profileNames | Should -Contain 'High'
        $profileNames | Should -Contain 'Privacy'
    }

    It 'At least 90% of nist-800-53 entries have a profiles array' {
        $withProfiles = @($nistChecks | Where-Object { $_.frameworks.'nist-800-53'.profiles }).Count
        $total = $nistChecks.Count
        $pct = [math]::Round(($withProfiles / $total) * 100, 1)
        Write-Host "  NIST entries with profiles: $withProfiles / $total ($pct%)"
        $pct | Should -BeGreaterOrEqual 90 `
            -Because "most nist-800-53 entries should have baseline profiles"
    }

    It 'NIST profiles contain only valid values' {
        $validProfiles = @('Low', 'Moderate', 'High', 'Privacy')
        foreach ($check in $nistChecks) {
            $profiles = $check.frameworks.'nist-800-53'.profiles
            if ($profiles -and $profiles.Count -gt 0) {
                foreach ($p in $profiles) {
                    $p | Should -BeIn $validProfiles `
                        -Because "$($check.checkId) profile '$p' must be a valid NIST baseline"
                }
            }
        }
    }

    It 'Low profile entries are a subset of Moderate' {
        foreach ($check in $nistChecks) {
            $profiles = $check.frameworks.'nist-800-53'.profiles
            if ($profiles -contains 'Low') {
                $profiles | Should -Contain 'Moderate' `
                    -Because "$($check.checkId) is in Low baseline and Low is a subset of Moderate"
            }
        }
    }

    It 'Moderate profile entries are a subset of High' {
        foreach ($check in $nistChecks) {
            $profiles = $check.frameworks.'nist-800-53'.profiles
            if ($profiles -contains 'Moderate') {
                $profiles | Should -Contain 'High' `
                    -Because "$($check.checkId) is in Moderate baseline and Moderate is a subset of High"
            }
        }
    }

    It 'ID format is uppercase with valid NIST notation' {
        foreach ($check in $nistChecks) {
            $controlId = $check.frameworks.'nist-800-53'.controlId
            $parts = $controlId -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            foreach ($part in $parts) {
                # Allow: AC-2, AC-2(1), AC-6(5)
                $part | Should -Match '^[A-Z]{2}-\d+(\(\d+\))?$' `
                    -Because "$($check.checkId) NIST control '$part' must be uppercase with valid NIST notation"
            }
        }
    }
}
