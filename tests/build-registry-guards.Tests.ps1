Describe 'Build-Registry.py defense-in-depth guards (#258)' {

    BeforeAll {
        $script:repoRoot   = (Resolve-Path "$PSScriptRoot/..").Path
        $script:script     = Join-Path $repoRoot 'scripts/Build-Registry.py'
        $script:source     = Get-Content $script -Raw
        $script:brokenFix  = Join-Path $repoRoot 'tests/fixtures/duplicate-key/broken.json'
    }

    It 'Defines _strict_load_json helper at module level' {
        $source | Should -Match 'def\s+_strict_load_json\s*\(' `
            -Because "module-level dup-key-rejecting JSON loader is the cornerstone of the guard"
    }

    It 'Has no unguarded json.load calls outside the helper' {
        # Allowed: the json.load inside _strict_load_json itself (line ~71).
        # Disallowed: any other bare json.load(...) or json.loads(file.read_text())
        # that bypasses the strict helper.
        $lines = $source -split "`r?`n"
        $offenders = @()
        $insideHelper = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -match '^def\s+_strict_load_json') { $insideHelper = $true; continue }
            if ($insideHelper -and $line -match '^def\s+\w' -and $line -notmatch '_reject_duplicates') {
                # Next top-level def — left the helper.
                $insideHelper = $false
            }
            if ($insideHelper) { continue }
            # Match actual call sites (json.load(...) / json.loads(...)) — not comments.
            if ($line -match '\bjson\.load\s*\(' -or $line -match '\bjson\.loads\s*\(') {
                $offenders += "line $($i+1): $($line.Trim())"
            }
        }
        $offenders | Should -BeNullOrEmpty `
            -Because "every input JSON load must go through _strict_load_json. Found: $($offenders -join '; ')"
    }

    It 'Calls _strict_load_json multiple times (input file count sanity)' {
        $matches_ = [regex]::Matches($source, '_strict_load_json\s*\(')
        # Helper definition + at least 7 call sites (8 input files; framework-titles
        # goes through load_framework_titles which uses the helper).
        $matches_.Count | Should -BeGreaterOrEqual 8 `
            -Because "expect helper used for every input JSON file (~7 call sites + 1 definition)"
    }

    It 'Includes pre-write schema validation block' {
        $source | Should -Match 'jsonschema\.validate\s*\(\s*registry\s*,' `
            -Because "build must validate registry against schema before write"
        $source | Should -Match 'Refusing to write' `
            -Because "validation failure must abort write with a clear message"
    }

    It 'Schema validation is wrapped in soft import (does not hard-require jsonschema)' {
        $source | Should -Match 'import jsonschema' `
            -Because "must import jsonschema"
        # Soft-import pattern: try/except ImportError around the import
        $source | Should -Match 'except ImportError' `
            -Because "soft import lets users without jsonschema still build (CI catches violations)"
    }

    It 'Emits one-line guards-passed summary at the end' {
        $source | Should -Match 'dup-key violations' `
            -Because "the final summary affirms the dup-key gate ran"
        $source | Should -Match 'schema validat' `
            -Because "the final summary mentions schema validation status"
    }

    It 'Helper raises ValueError on duplicate keys (functional check)' {
        $output = python -c @"
import sys, importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('br', r'$script')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
try:
    mod._strict_load_json(Path(r'$brokenFix'))
    print('FAIL: did not raise')
    sys.exit(1)
except ValueError as e:
    if 'duplicate key' in str(e):
        print('PASS')
    else:
        print(f'FAIL: wrong message: {e}')
        sys.exit(1)
"@ 2>&1
        $LASTEXITCODE | Should -Be 0 `
            -Because "helper must reject the duplicate-key fixture: $($output -join "`n")"
    }
}
