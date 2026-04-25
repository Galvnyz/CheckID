Describe 'Schema-Strict Validation' {

    BeforeAll {
        $script:repoRoot      = (Resolve-Path "$PSScriptRoot/..").Path
        $script:schemaPath    = Join-Path $repoRoot 'data/registry.schema.json'
        $script:registryPath  = Join-Path $repoRoot 'data/registry.json'
        $script:fixturesDir   = Join-Path $repoRoot 'tests/fixtures/schema-strict'
        $script:missingImpact = Join-Path $fixturesDir 'missing-impactRating.json'
        $script:missingRemed  = Join-Path $fixturesDir 'missing-remediation.json'

        # Helper that runs jsonschema and captures exit code
        function script:Test-AgainstSchema {
            param([string]$Instance)
            python -c @"
import json, sys, jsonschema
try:
    schema = json.load(open(r'$schemaPath', encoding='utf-8'))
    instance = json.load(open(r'$Instance', encoding='utf-8'))
    jsonschema.validate(instance, schema)
    print('VALID')
except jsonschema.ValidationError as e:
    print(f'INVALID: {e.message} at {list(e.absolute_path)}')
    sys.exit(1)
"@ 2>&1
        }
    }

    It 'Schema requires impactRating at check level' {
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $schema.'$defs'.check.required | Should -Contain 'impactRating' `
            -Because "v2.23 #256 tightened schema must require impactRating"
    }

    It 'Schema requires remediation at check level' {
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $schema.'$defs'.check.required | Should -Contain 'remediation' `
            -Because "v2.23 #256 tightened schema must require remediation"
    }

    It 'Schema does NOT require rationale (must remain optional)' {
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $schema.'$defs'.check.required | Should -Not -Contain 'rationale' `
            -Because "rationale is sparse content (~27%) and must remain optional"
    }

    It 'Schema does NOT require impact (must remain optional)' {
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $schema.'$defs'.check.required | Should -Not -Contain 'impact' `
            -Because "impact is sparse content (~27%) and must remain optional"
    }

    It 'Schema does NOT require references (must remain optional)' {
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $schema.'$defs'.check.required | Should -Not -Contain 'references' `
            -Because "references is sparse content (~27%) and must remain optional"
    }

    It 'Current registry.json validates against the tightened schema' {
        $output = Test-AgainstSchema $registryPath
        $LASTEXITCODE | Should -Be 0 `
            -Because "all 1105 production checks must pass the tightened schema: $output"
        ($output -join "`n") | Should -Match 'VALID'
    }

    It 'Schema rejects a check missing impactRating' {
        $output = Test-AgainstSchema $missingImpact
        $LASTEXITCODE | Should -Be 1 `
            -Because "tightened schema must reject checks missing impactRating"
        ($output -join "`n") | Should -Match 'impactRating' `
            -Because "validation error must name the missing field"
    }

    It 'Schema rejects a check missing remediation' {
        $output = Test-AgainstSchema $missingRemed
        $LASTEXITCODE | Should -Be 1 `
            -Because "tightened schema must reject checks missing remediation"
        ($output -join "`n") | Should -Match 'remediation' `
            -Because "validation error must name the missing field"
    }
}
