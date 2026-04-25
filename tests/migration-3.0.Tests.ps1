# Migration round-trip test for v3.0.0 schema restructure (#266).
#
# Asserts that every entry from the pre-migration override files
# (data/framework-overrides.json, data/effort-overrides.json) survives
# verbatim onto each check in registry.json — with source provenance
# set to "manual-override" and effort overrideReason capturing the
# original _rationale annotations.
#
# TDD ordering (per plan): this test was committed BEFORE the migration
# (#262 + #263). On main pre-migration the override files still existed
# in data/ and the assertion blocks SKIPPED automatically. When #262/#263
# lands and removes the override files, the skip flips and the assertions
# gate the merge.
#
# To force-run during migration development (bypass skip), simply remove
# the data/framework-overrides.json and data/effort-overrides.json files
# locally before running Pester.

# Discovery-time evaluation: skip the round-trip Describes when override
# files are still present on disk. Resolved via $PSScriptRoot, which is
# the only path available reliably during discovery.
$script:migrationComplete = -not (Test-Path "$PSScriptRoot/../data/framework-overrides.json") -and `
                            -not (Test-Path "$PSScriptRoot/../data/effort-overrides.json")

Describe 'Migration v3.0 — informational state' {

    BeforeAll {
        $script:repoRoot = (Resolve-Path "$PSScriptRoot/..").Path
        $script:fxDir = Join-Path $script:repoRoot 'tests/fixtures/v2.23-overrides'
        $script:fwOverridesPath = Join-Path $script:repoRoot 'data/framework-overrides.json'
        $script:effortOverridesPath = Join-Path $script:repoRoot 'data/effort-overrides.json'
        $script:migrationCompleteRuntime = -not (Test-Path $script:fwOverridesPath) -and `
                                           -not (Test-Path $script:effortOverridesPath)
    }

    It 'Reports current migration state' {
        if ($script:migrationCompleteRuntime) {
            Write-Host "v3.0 migration COMPLETE — round-trip assertions active."
        } else {
            Write-Host "v3.0 migration PENDING — assertions SKIPPED until override files are removed (see #262/#263)."
        }
        $true | Should -Be $true
    }

    It 'Pre-migration fixtures exist' {
        Test-Path (Join-Path $script:fxDir 'framework-overrides.json') | Should -Be $true `
            -Because "snapshot of v2.23.0 framework-overrides.json must be captured for the round-trip test"
        Test-Path (Join-Path $script:fxDir 'effort-overrides.json') | Should -Be $true `
            -Because "snapshot of v2.23.0 effort-overrides.json must be captured for the round-trip test"
    }
}

Describe 'Migration v3.0 — framework-overrides round-trip' -Skip:(-not $script:migrationComplete) {

    BeforeAll {
        $script:repoRoot = (Resolve-Path "$PSScriptRoot/..").Path
        $fixturePath = Join-Path $script:repoRoot 'tests/fixtures/v2.23-overrides/framework-overrides.json'
        $registryPath = Join-Path $script:repoRoot 'data/registry.json'

        $script:fxOverrides = (Get-Content $fixturePath -Raw | ConvertFrom-Json).overrides
        $registry = Get-Content $registryPath -Raw | ConvertFrom-Json
        $script:checksById = @{}
        foreach ($c in $registry.checks) { $script:checksById[$c.checkId] = $c }
    }

    It 'Every override entry maps to a check that exists in registry.json' {
        foreach ($checkId in $script:fxOverrides.PSObject.Properties.Name) {
            $script:checksById.ContainsKey($checkId) | Should -Be $true `
                -Because "override entry for '$checkId' must correspond to an actual check post-migration"
        }
    }

    It 'Every override mapping is present on its check with source=manual-override and includes the override controlId' {
        foreach ($checkId in $script:fxOverrides.PSObject.Properties.Name) {
            $check = $script:checksById[$checkId]
            if (-not $check) { continue }
            $overrideEntry = $script:fxOverrides.$checkId

            foreach ($fwId in $overrideEntry.PSObject.Properties.Name) {
                $expected = $overrideEntry.$fwId
                $actual = $check.frameworks.$fwId
                $actual | Should -Not -BeNullOrEmpty `
                    -Because "$checkId.frameworks.$fwId must exist after migration"

                # Inclusion semantics handles all three cases uniformly:
                # - Pure addition (key absent): actual.controlId == override.controlId
                # - Replace with SCF collision: override.controlId is one of actual's IDs
                # - Append mode: override.controlId is appended to existing IDs
                $actual.controlId | Should -Match ([regex]::Escape($expected.controlId)) `
                    -Because "$checkId.frameworks.$fwId.controlId must include the override id (got '$($actual.controlId)', expected to contain '$($expected.controlId)')"

                $actual.source | Should -Be 'manual-override' `
                    -Because "$checkId.frameworks.$fwId must carry source=manual-override post-migration"
            }
        }
    }

    It 'data/framework-overrides.json no longer exists in the repo' {
        $path = Join-Path (Resolve-Path "$PSScriptRoot/..").Path 'data/framework-overrides.json'
        Test-Path $path | Should -Be $false `
            -Because "the override file is the bug-class breeding ground; v3.0 removes it"
    }
}

Describe 'Migration v3.0 — effort-overrides round-trip' -Skip:(-not $script:migrationComplete) {

    BeforeAll {
        $script:repoRoot = (Resolve-Path "$PSScriptRoot/..").Path
        $fixturePath = Join-Path $script:repoRoot 'tests/fixtures/v2.23-overrides/effort-overrides.json'
        $registryPath = Join-Path $script:repoRoot 'data/registry.json'

        $script:fxEffort = (Get-Content $fixturePath -Raw | ConvertFrom-Json).overrides
        $registry = Get-Content $registryPath -Raw | ConvertFrom-Json
        $script:checksById = @{}
        foreach ($c in $registry.checks) { $script:checksById[$c.checkId] = $c }
    }

    It 'Every effort-override _rationale survives as effort.overrideReason' {
        foreach ($checkId in $script:fxEffort.PSObject.Properties.Name) {
            $expected = $script:fxEffort.$checkId
            if (-not $expected._rationale) { continue }
            $check = $script:checksById[$checkId]
            $check | Should -Not -BeNullOrEmpty `
                -Because "$checkId from effort-overrides must exist in registry"
            $check.effort.overrideReason | Should -Be $expected._rationale `
                -Because "_rationale annotation for $checkId must survive as effort.overrideReason (preserved tribal knowledge)"
        }
    }

    It 'Every effort override field is reflected on the check' {
        $effortFields = @('complexity', 'isPhased', 'phaseCount', 'disruptionRisk', 'disruptionScope')
        foreach ($checkId in $script:fxEffort.PSObject.Properties.Name) {
            $expected = $script:fxEffort.$checkId
            $check = $script:checksById[$checkId]
            if (-not $check) { continue }
            foreach ($field in $effortFields) {
                if ($null -ne $expected.$field) {
                    $check.effort.$field | Should -Be $expected.$field `
                        -Because "$checkId effort.$field must match the override fixture"
                }
            }
        }
    }

    It 'data/effort-overrides.json no longer exists in the repo' {
        $path = Join-Path (Resolve-Path "$PSScriptRoot/..").Path 'data/effort-overrides.json'
        Test-Path $path | Should -Be $false `
            -Because "v3.0 dissolves effort-overrides into the check itself"
    }
}
