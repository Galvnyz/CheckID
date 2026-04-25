Describe 'Mapping-Count Regression Gate' {

    BeforeAll {
        $script:repoRoot     = (Resolve-Path "$PSScriptRoot/..").Path
        $script:comparator   = Join-Path $repoRoot 'scripts/Compare-MappingCounts.py'
        $script:fixturesDir  = Join-Path $repoRoot 'tests/fixtures/mapping-counts'
        $script:baseline     = Join-Path $fixturesDir 'baseline.json'
        $script:drop1pct     = Join-Path $fixturesDir 'drop-1pct.json'
        $script:drop5pct     = Join-Path $fixturesDir 'drop-5pct.json'
        $script:fwAdded      = Join-Path $fixturesDir 'framework-added.json'
        $script:registry     = Join-Path $repoRoot 'data/registry.json'
    }

    It 'Comparator script exists' {
        Test-Path $comparator | Should -Be $true `
            -Because "scripts/Compare-MappingCounts.py must exist"
    }

    It 'All fixtures exist' {
        @($baseline, $drop1pct, $drop5pct, $fwAdded) | ForEach-Object {
            Test-Path $_ | Should -Be $true -Because "fixture $_ must exist"
        }
    }

    It 'Baseline vs baseline: zero change, exit 0' {
        $output = python $comparator $baseline $baseline 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "identical registries must produce no regression: $($output -join "`n")"
    }

    It 'Baseline vs drop-1pct: 1% drop is below 2% threshold, exit 0' {
        $output = python $comparator $baseline $drop1pct 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "1% drop is under default 2% threshold, must not fail: $($output -join "`n")"
    }

    It 'Baseline vs drop-5pct: 5% drop exceeds threshold, exit 1' {
        $output = python $comparator $baseline $drop5pct 2>&1
        $LASTEXITCODE | Should -Be 1 `
            -Because "5% drop must fail the 2% gate"
        ($output -join "`n") | Should -Match 'fw-e' `
            -Because "error must name the regressed framework"
    }

    It 'Baseline vs drop-5pct with --allow-drop fw-e: passes with warning' {
        $output = python $comparator $baseline $drop5pct --allow-drop fw-e 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "explicit --allow-drop must waive the gate: $($output -join "`n")"
    }

    It 'Baseline vs framework-added: additive change, exit 0' {
        $output = python $comparator $baseline $fwAdded 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "additive change (fw-f from 0 to 100) is not a regression: $($output -join "`n")"
    }

    It 'Comparator handles real registry vs itself with exit 0' {
        $output = python $comparator $registry $registry 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "real registry compared to itself must show zero deltas: $($output -join "`n")"
    }

    It 'Markdown output flag writes a delta table' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "mapping-delta-$(New-Guid).md"
        try {
            $null = python $comparator $baseline $drop5pct --markdown $tmp 2>&1
            Test-Path $tmp | Should -Be $true `
                -Because "--markdown flag must write the file even when the gate fails"
            $contents = Get-Content $tmp -Raw
            $contents | Should -Match 'mapping-count-delta' `
                -Because "markdown must contain the sticky-comment marker"
            $contents | Should -Match 'fw-e' `
                -Because "markdown must show the regressed framework"
        } finally {
            if (Test-Path $tmp) { Remove-Item $tmp -Force }
        }
    }
}
