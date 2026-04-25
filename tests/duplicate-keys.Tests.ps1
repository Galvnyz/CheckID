Describe 'No Duplicate JSON Keys' {

    BeforeAll {
        $script:repoRoot = (Resolve-Path "$PSScriptRoot/..").Path
        $script:validator = Join-Path $repoRoot 'scripts/Validate-NoDuplicateKeys.py'
        $script:fixturesDir = Join-Path $repoRoot 'tests/fixtures/duplicate-key'
        $script:brokenFixture = Join-Path $fixturesDir 'broken.json'
        $script:cleanFixture = Join-Path $fixturesDir 'clean.json'
    }

    It 'Validator script exists' {
        Test-Path $validator | Should -Be $true `
            -Because "scripts/Validate-NoDuplicateKeys.py must exist"
    }

    It 'Broken fixture exists' {
        Test-Path $brokenFixture | Should -Be $true `
            -Because "duplicate-key fixture is required to verify the gate catches the bug class"
    }

    It 'Clean fixture exists' {
        Test-Path $cleanFixture | Should -Be $true `
            -Because "clean fixture is required to verify the validator does not produce false positives"
    }

    It 'Validator catches a fixture with duplicate keys' {
        $output = python $validator $brokenFixture 2>&1
        $LASTEXITCODE | Should -Be 1 `
            -Because "validator must exit non-zero on duplicate keys: $($output -join "`n")"
        ($output -join "`n") | Should -Match 'duplicate key' `
            -Because "error message must mention 'duplicate key' for clarity"
        ($output -join "`n") | Should -Match 'ENTRA-PASSWORD-002' `
            -Because "error message must name the offending key"
    }

    It 'Validator passes against a clean fixture' {
        $output = python $validator $cleanFixture 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "clean fixture must pass: $($output -join "`n")"
    }

    It 'Validator passes against current data/ tree' {
        Push-Location $repoRoot
        try {
            $output = python $validator 2>&1
            $LASTEXITCODE | Should -Be 0 `
                -Because "data/ tree must currently be clean: $($output -join "`n")"
        } finally {
            Pop-Location
        }
    }
}
