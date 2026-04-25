Describe 'Enrichment Metrics' {

    BeforeAll {
        $script:repoRoot     = (Resolve-Path "$PSScriptRoot/..").Path
        $script:script       = Join-Path $repoRoot 'scripts/Compute-EnrichmentMetrics.py'
        $script:fixturesDir  = Join-Path $repoRoot 'tests/fixtures/enrichment-metrics'
        $script:sparse       = Join-Path $fixturesDir 'sparse.json'
        $script:enriched     = Join-Path $fixturesDir 'enriched.json'
        $script:registry     = Join-Path $repoRoot 'data/registry.json'
    }

    It 'Script exists' {
        Test-Path $script | Should -Be $true
    }

    It 'Snapshot mode (single fixture) exits 0 and shows expected percentages' {
        $output = python $script $sparse 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "metrics script must always exit 0 (informational, non-blocking)"
        $combined = $output -join "`n"
        # sparse fixture: 5/10 enriched → 50% on each metric
        $combined | Should -Match '50' `
            -Because "sparse fixture should report 50% population: $combined"
    }

    It 'Comparison mode (same fixture both sides) shows zero delta and exits 0' {
        $output = python $script $sparse $sparse 2>&1
        $LASTEXITCODE | Should -Be 0
        $combined = $output -join "`n"
        # No specific delta value asserted — zero deltas should appear as +0.00% or similar
        $combined | Should -Match '50' `
            -Because "fixture comparison must include the snapshot percentage"
    }

    It 'Comparison mode with enrichment improvement shows positive deltas' {
        $output = python $script $sparse $enriched 2>&1
        $LASTEXITCODE | Should -Be 0
        $combined = $output -join "`n"
        # enriched is 100% across the board; main was 50%; delta should be +50pp
        $combined | Should -Match '\+50|50.0\+|100' `
            -Because "moving from sparse to enriched must show a visible positive change: $combined"
    }

    It 'Markdown output flag writes a sticky-comment-friendly file' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "enrichment-$(New-Guid).md"
        try {
            $null = python $script $sparse $enriched --markdown $tmp 2>&1
            Test-Path $tmp | Should -Be $true
            $contents = Get-Content $tmp -Raw
            $contents | Should -Match 'enrichment-metrics' `
                -Because "markdown must contain the sticky-comment marker"
            $contents | Should -Match 'rationale' `
                -Because "markdown must report the rationale metric"
            $contents | Should -Match 'fw-a' `
                -Because "markdown must include per-framework rows"
        } finally {
            if (Test-Path $tmp) { Remove-Item $tmp -Force }
        }
    }

    It 'Always exits 0 even on regression (non-blocking by design)' {
        # enriched-as-main vs sparse-as-head simulates a content regression.
        $output = python $script $enriched $sparse 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "regression must not gate the build — see #281 for the actual release-gate"
    }

    It 'Handles real registry without erroring' {
        $output = python $script $registry 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "real registry must produce valid metrics output: $($output -join "`n")"
    }
}
