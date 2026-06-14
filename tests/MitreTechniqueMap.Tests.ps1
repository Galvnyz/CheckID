Describe 'MITRE ATT&CK Technique Map Integrity' {
    BeforeAll {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $mapPath = "$projectRoot/data/mitre-technique-map.json"
        $frameworkPath = "$projectRoot/data/frameworks/mitre-attack.json"

        $data = Get-Content -Path $mapPath -Raw | ConvertFrom-Json
        $framework = Get-Content -Path $frameworkPath -Raw | ConvertFrom-Json

        # The tactic codes the mitre-attack framework declares (source of truth for valid tactics).
        $declaredTactics = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($p in $framework.scoring.tactics.PSObject.Properties) { [void]$declaredTactics.Add($p.Name) }

        $techniquePattern = '^T\d{4}(\.\d{3})?$'
        $entries = @($data.map.PSObject.Properties)
    }

    Context 'Top-level structure' {
        It 'Has description and map' {
            $data.PSObject.Properties.Name | Should -Contain 'description'
            $data.PSObject.Properties.Name | Should -Contain 'map'
        }
        It 'Points at the local JSON schema' {
            $data.'$schema' | Should -Be './mitre-technique-map.schema.json'
        }
        It 'Map is non-empty' {
            $entries.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Technique keys' {
        It 'Every map key is a well-formed ATT&CK technique ID' {
            $bad = $entries | Where-Object { $_.Name -notmatch $techniquePattern } | ForEach-Object { $_.Name }
            ($bad -join ', ') | Should -BeNullOrEmpty -Because 'keys must match T#### or T####.###'
        }
    }

    Context 'Tactic values' {
        It 'Every mapped tactic code is declared by the mitre-attack framework' {
            $unknown = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($e in $entries) {
                foreach ($code in @($e.Value)) {
                    if (-not $declaredTactics.Contains($code)) { [void]$unknown.Add($code) }
                }
            }
            ($unknown | Sort-Object) -join ', ' | Should -BeNullOrEmpty `
                -Because 'every tactic code must exist in frameworks/mitre-attack.json scoring.tactics'
        }
    }
}
