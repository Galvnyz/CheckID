BeforeDiscovery {
    $frameworkDir = Join-Path $PSScriptRoot '..' 'data' 'frameworks'
    $frameworkFiles = Get-ChildItem -Path $frameworkDir -Filter '*.json'
    $script:frameworks = foreach ($file in $frameworkFiles) {
        $json = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        @{ Name = $file.BaseName; Path = $file.FullName; Data = $json }
    }
}

Describe 'Framework Definition Schema' {

    Context '<Name>' -ForEach $frameworks {

        It 'Has frameworkId as a non-empty string' {
            $Data.frameworkId | Should -Not -BeNullOrEmpty
            $Data.frameworkId | Should -BeOfType [string]
        }

        It 'Has label as a non-empty string' {
            $Data.label | Should -Not -BeNullOrEmpty
            $Data.label | Should -BeOfType [string]
        }

        It 'Has version as a non-empty string' {
            $Data.version | Should -Not -BeNullOrEmpty
            $Data.version | Should -BeOfType [string]
        }

        It 'Has css as a non-empty string' {
            $Data.css | Should -Not -BeNullOrEmpty
            $Data.css | Should -BeOfType [string]
        }

        It 'Has totalControls as a positive integer' {
            $Data.totalControls | Should -BeOfType [long]
            $Data.totalControls | Should -BeGreaterThan 0
        }

        It 'Has registryKey as a non-empty string' {
            $Data.registryKey | Should -Not -BeNullOrEmpty
            $Data.registryKey | Should -BeOfType [string]
        }

        It 'Has csvColumn as a non-empty string' {
            $Data.csvColumn | Should -Not -BeNullOrEmpty
            $Data.csvColumn | Should -BeOfType [string]
        }

        It 'Has displayOrder as an integer' {
            $Data.displayOrder | Should -BeOfType [long]
        }

        It 'Has scoring.method as a valid value' {
            $validMethods = @('coverage', 'profile-compliance', 'criteria-coverage', 'maturity-level', 'function-coverage', 'control-coverage', 'requirement-compliance', 'severity-coverage', 'policy-compliance', 'technique-coverage')
            $Data.scoring | Should -Not -BeNullOrEmpty
            $Data.scoring.method | Should -Not -BeNullOrEmpty
            $Data.scoring.method | Should -BeIn $validMethods
        }

        It 'Has colors.light with background and color keys' {
            $Data.colors | Should -Not -BeNullOrEmpty
            $Data.colors.light | Should -Not -BeNullOrEmpty
            $Data.colors.light.background | Should -Not -BeNullOrEmpty
            $Data.colors.light.color | Should -Not -BeNullOrEmpty
        }

        It 'Has colors.dark with background and color keys' {
            $Data.colors.dark | Should -Not -BeNullOrEmpty
            $Data.colors.dark.background | Should -Not -BeNullOrEmpty
            $Data.colors.dark.color | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Framework Definition Cross-Validation' {

    BeforeAll {
        $frameworkDir = Join-Path $PSScriptRoot '..' 'data' 'frameworks'
        $frameworkFiles = Get-ChildItem -Path $frameworkDir -Filter '*.json'
        $script:allFrameworks = foreach ($file in $frameworkFiles) {
            $json = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
            @{ Name = $file.BaseName; Path = $file.FullName; Data = $json }
        }
    }

    It 'All displayOrder values are unique' {
        $orders = $allFrameworks | ForEach-Object { $_.Data.displayOrder }
        $dupes = $orders | Group-Object | Where-Object { $_.Count -gt 1 }
        $dupes | Should -BeNullOrEmpty -Because 'displayOrder values must be unique'
    }

    It 'All frameworkId values are unique' {
        $ids = $allFrameworks | ForEach-Object { $_.Data.frameworkId }
        $dupes = $ids | Group-Object | Where-Object { $_.Count -gt 1 }
        $dupes | Should -BeNullOrEmpty -Because 'frameworkId values must be unique'
    }

    It 'All registryKey values are unique' {
        $keys = $allFrameworks | ForEach-Object { $_.Data.registryKey }
        $dupes = $keys | Group-Object | Where-Object { $_.Count -gt 1 }
        $dupes | Should -BeNullOrEmpty -Because 'registryKey values must be unique'
    }

    It 'Has at least 18 framework definition files' {
        $allFrameworks.Count | Should -BeGreaterOrEqual 18 `
            -Because '3 new frameworks (iso-27017, nist-800-171, nis2) should be present'
    }

    It 'Registry framework keys have corresponding definition files' -Tag 'RegistryCoverage' {
        $registryPath = Join-Path $PSScriptRoot '..' 'data' 'registry.json'
        $registry = Get-Content -Path $registryPath -Raw | ConvertFrom-Json

        $registryKeys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($check in $registry.checks) {
            foreach ($prop in $check.frameworks.PSObject.Properties) {
                [void]$registryKeys.Add($prop.Name)
            }
        }

        $definitionKeys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($fw in $allFrameworks) {
            [void]$definitionKeys.Add($fw.Data.registryKey)
        }

        $missing = @()
        foreach ($key in $registryKeys) {
            if (-not $definitionKeys.Contains($key)) {
                $missing += $key
            }
        }

        if ($missing.Count -gt 0) {
            Write-Warning "Registry framework keys without definition files ($($missing.Count)): $($missing -join ', ')"
        }

        $missing.Count | Should -Be 0 -Because 'all registry framework keys should have corresponding definition files'
    }
}
