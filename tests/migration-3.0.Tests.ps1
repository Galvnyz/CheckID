# Migration round-trip test for v3.0.0 schema restructure (#266).
#
# Asserts that every entry from the pre-migration override files
# (data/framework-overrides.json, data/effort-overrides.json) survives
# verbatim onto each check in registry.json — with source provenance
# set to "manual-override" and effort overrideReason capturing the
# original _rationale annotations.
#
# TDD ordering (per plan): this test is committed BEFORE the migration
# (#262 + #263). On main today, the override files still exist in data/
# and the migration has not been performed; the assertion blocks SKIP
# automatically until the override files are removed (the migration's
# completion signal). When #262/#263 land in the same PR that deletes
# data/framework-overrides.json and data/effort-overrides.json, this
# test starts running and gates the merge.
#
# To force-run this test during migration development (bypass skip):
#   pwsh -NoProfile -Command "Invoke-Pester -Path ./tests/migration-3.0.Tests.ps1 -ExcludeTagFilter pending-migration"
# That tag is set by the skip condition; clearing it forces the asserts.

$script:repoRoot = (Resolve-Path "$PSScriptRoot/..").Path
$script:fwOverridesPath = Join-Path $script:repoRoot 'data/framework-overrides.json'
$script:effortOverridesPath = Join-Path $script:repoRoot 'data/effort-overrides.json'

# Migration-complete sentinel: override files have been removed from data/.
# Until that's true, the assertion blocks below are SKIPPED. Discovery-time
# evaluation requires the variable to be available before BeforeAll.
$script:migrationComplete = -not (Test-Path $script:fwOverridesPath) -and `
                            -not (Test-Path $script:effortOverridesPath)

Describe 'Migration v3.0 — informational state' {

    BeforeAll {
        $script:repoRootLocal = (Resolve-Path "$PSScriptRoot/..").Path
        $script:fxDir = Join-Path $script:repoRootLocal 'tests/fixtures/v2.23-overrides'
    }

    It 'Reports current migration state' {
        if ($script:migrationComplete) {
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

    It 'Every override mapping is present on its check with source=manual-override and matching controlId' {
        foreach ($checkId in $script:fxOverrides.PSObject.Properties.Name) {
            $check = $script:checksById[$checkId]
            if (-not $check) { continue }
            $overrideEntry = $script:fxOverrides.$checkId

            foreach ($fwId in $overrideEntry.PSObject.Properties.Name) {
                $expected = $overrideEntry.$fwId
                $actual = $check.frameworks.$fwId
                $actual | Should -Not -BeNullOrEmpty `
                    -Because "$checkId.frameworks.$fwId must exist after migration"
                $actual.controlId | Should -Be $expected.controlId `
                    -Because "$checkId.frameworks.$fwId.controlId must match override"
                $actual.source | Should -Be 'manual-override' `
                    -Because "$checkId.frameworks.$fwId must carry source=manual-override post-migration"
            }
        }
    }

    It 'data/framework-overrides.json no longer exists in the repo' {
        Test-Path $script:fwOverridesPath | Should -Be $false `
            -Because "the override file is the bug-class breeding ground; v3.0 removes it"
    }
}

Describe 'Migration v3.0 — effort-overrides round-trip' -Skip:(-not $script:migrationComplete) {

    BeforeAll {
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
        Test-Path $script:effortOverridesPath | Should -Be $false `
            -Because "v3.0 dissolves effort-overrides into the check itself"
    }
}
