Describe 'Per-Mapping Provenance (#260)' {

    BeforeAll {
        $script:repoRoot      = (Resolve-Path "$PSScriptRoot/..").Path
        $script:schemaPath    = Join-Path $repoRoot 'data/registry.schema.json'
        $script:registryPath  = Join-Path $repoRoot 'data/registry.json'
        $script:fixturesDir   = Join-Path $repoRoot 'tests/fixtures/mapping-provenance'
        $script:validFixture  = Join-Path $fixturesDir 'valid-source-values.json'
        $script:invalidFixture = Join-Path $fixturesDir 'invalid-source-value.json'

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

    It 'Schema declares source as an enum' {
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $sourceProp = $schema.'$defs'.frameworkMapping.properties.source
        $sourceProp | Should -Not -BeNullOrEmpty `
            -Because "frameworkMapping must define a source property"
        $sourceProp.enum | Should -Contain 'scf-derived'
        $sourceProp.enum | Should -Contain 'manual-override'
        $sourceProp.enum | Should -Contain 'cis-paraphrased'
        $sourceProp.enum | Should -Contain 'stig-manual'
        $sourceProp.enum | Should -Contain 'eidsca-crosswalk'
    }

    It 'Schema declares reason as an optional string' {
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $reasonProp = $schema.'$defs'.frameworkMapping.properties.reason
        $reasonProp | Should -Not -BeNullOrEmpty
        $reasonProp.type | Should -Be 'string'
    }

    It 'Schema does NOT require source or reason' {
        $schema = Get-Content $schemaPath -Raw | ConvertFrom-Json
        $required = $schema.'$defs'.frameworkMapping.required
        $required | Should -Not -Contain 'source' `
            -Because "source is optional; absence means scf-derived (the default)"
        $required | Should -Not -Contain 'reason' `
            -Because "reason is optional; only meaningful on overrides"
    }

    It 'Current registry.json validates against the schema (no data changes yet)' {
        $output = Test-AgainstSchema $registryPath
        $LASTEXITCODE | Should -Be 0 `
            -Because "v3.0.0 setup must not require data changes from v2.23.0: $output"
    }

    It 'Schema rejects an unknown source value' {
        $output = Test-AgainstSchema $invalidFixture
        $LASTEXITCODE | Should -Be 1 `
            -Because "unknown source value must fail validation"
        ($output -join "`n") | Should -Match 'made-up-source|enum' `
            -Because "validation error must point at the bad value or enum"
    }
}
