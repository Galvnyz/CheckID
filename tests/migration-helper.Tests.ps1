Describe 'ConvertTo-LegacyRemediationString cmdlet (#265)' {

    BeforeAll {
        Import-Module "$PSScriptRoot/../CheckID.psd1" -Force
    }

    It 'Returns empty string for null/empty input' {
        ConvertTo-LegacyRemediationString $null | Should -Be ''
    }

    It 'Reconstructs powershell + portal remediation' {
        $rem = [PSCustomObject]@{
            powershell = [PSCustomObject]@{ command = 'Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly' }
            portal     = [PSCustomObject]@{
                path  = 'SharePoint admin center > Policies > Sharing'
                steps = @('SharePoint admin center', 'Policies', 'Sharing')
            }
        }
        $result = ConvertTo-LegacyRemediationString $rem 3>$null
        $result | Should -Be 'Run: Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly. SharePoint admin center > Policies > Sharing.'
    }

    It 'Reconstructs portal-only remediation' {
        $rem = [PSCustomObject]@{
            portal = [PSCustomObject]@{ path = 'Entra admin center > Properties > Manage security defaults' }
        }
        $result = ConvertTo-LegacyRemediationString $rem 3>$null
        $result | Should -Be 'Entra admin center > Properties > Manage security defaults.'
    }

    It 'Reconstructs portal + cli remediation' {
        $rem = [PSCustomObject]@{
            portal = [PSCustomObject]@{ path = 'Azure Portal > Kubernetes services > [cluster] > Settings' }
            cli    = [PSCustomObject]@{ command = 'az aks update --enable-aad' }
        }
        $result = ConvertTo-LegacyRemediationString $rem 3>$null
        $result | Should -Match 'Azure Portal > Kubernetes services'
        $result | Should -Match 'Or: az aks update --enable-aad'
    }

    It 'Reconstructs Microsoft Graph API remediation' {
        $rem = [PSCustomObject]@{
            graph = [PSCustomObject]@{
                endpoint = 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
                method   = 'PATCH'
            }
        }
        $result = ConvertTo-LegacyRemediationString $rem 3>$null
        $result | Should -Match 'Microsoft Graph API: PATCH'
        $result | Should -Match 'graph\.microsoft\.com/v1\.0/policies/authorizationPolicy'
    }

    It 'Returns notes-only remediation as-is' {
        $rem = [PSCustomObject]@{
            notes = 'Connect to Exchange Online and verify accepted domains'
        }
        $result = ConvertTo-LegacyRemediationString $rem 3>$null
        $result | Should -Be 'Connect to Exchange Online and verify accepted domains'
    }

    It 'Round-trips a real registry check (SPO-SHARING-001)' {
        $check = Get-CheckById 'SPO-SHARING-001'
        $reconstructed = ConvertTo-LegacyRemediationString $check.remediation 3>$null
        # Must contain the powershell command and the portal path
        $reconstructed | Should -Match 'Set-SPOTenant'
        $reconstructed | Should -Match 'SharePoint admin center'
    }

    It 'Emits a deprecation warning' {
        # Reset the once-per-session flag so the warning fires.
        & (Get-Module CheckID) { $script:_LegacyRemediationDeprecationWarned = $false }
        $rem = [PSCustomObject]@{ portal = [PSCustomObject]@{ path = 'Test path' } }
        $warnings = $null
        $null = ConvertTo-LegacyRemediationString $rem -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings | Should -Not -BeNullOrEmpty
        ($warnings -join ' ') | Should -Match 'deprecated'
    }
}

Describe 'tools/migrate-checkid-3.0.ps1 (#265)' {

    BeforeAll {
        $script:scriptPath = Resolve-Path "$PSScriptRoot/../tools/migrate-checkid-3.0.ps1"
        $script:testInput = Join-Path ([System.IO.Path]::GetTempPath()) "checkid-mig-in-$(New-Guid).json"
        $script:testOutput = Join-Path ([System.IO.Path]::GetTempPath()) "checkid-mig-out-$(New-Guid).json"

        # Build a minimal v2.x-shape registry fixture (string remediation).
        $fixture = @{
            schemaVersion = '2.23.0'
            dataVersion = '2026-04-25'
            generatedFrom = 'fixture'
            checks = @(
                @{
                    checkId    = 'TEST-MIGRATE-001'
                    name       = 'Test'
                    category   = 'TEST'
                    collector  = 'Entra'
                    hasAutomatedCheck = $true
                    licensing  = @{ minimum = 'E3' }
                    scf        = @{
                        primaryControlId   = 'IAC-01'
                        domain             = 'Test'
                        controlName        = 'Test'
                        controlDescription = 'Test'
                    }
                    frameworks = @{ 'nist-csf' = @{ controlId = 'PR.AA-01' } }
                    effort     = @{
                        complexity      = 1
                        isPhased        = $false
                        phaseCount      = 1
                        disruptionRisk  = $false
                    }
                    impactRating = @{ severity = 'Medium' }
                    remediation  = 'Run: Set-Test -Foo $true. Entra admin center > Properties > Test setting.'
                }
            )
        }
        $fixture | ConvertTo-Json -Depth 10 | Set-Content -Path $script:testInput -Encoding utf8
    }

    AfterAll {
        Remove-Item $script:testInput, $script:testOutput -Force -ErrorAction SilentlyContinue
    }

    It 'Migrates a v2.x fixture and writes valid JSON' {
        & pwsh -NoProfile -File $script:scriptPath -InputPath $script:testInput -OutputPath $script:testOutput 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 0
        Test-Path $script:testOutput | Should -Be $true

        $output = Get-Content $script:testOutput -Raw | ConvertFrom-Json
        $check = $output.checks[0]
        $check.remediation | Should -Not -BeOfType [string]
        $check.remediation.powershell.command | Should -Match 'Set-Test'
        $check.remediation.portal.path | Should -Match 'Entra admin center > Properties > Test setting'
    }
}
