Describe 'SKU Feature Map Integrity' {
    BeforeAll {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $mapPath = "$projectRoot/data/sku-feature-map.json"
        $registryPath = "$projectRoot/data/registry.json"

        $map = Get-Content -Path $mapPath -Raw | ConvertFrom-Json
        $registry = Get-Content -Path $registryPath -Raw | ConvertFrom-Json
        $registryCheckIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($c in $registry.checks) { [void]$registryCheckIds.Add($c.checkId) }

        $featureGroups = $map.featureGroups
        $groupKeys = @($featureGroups.PSObject.Properties.Name)
        $skuTiers = $map.skuTiers
    }

    # --- Structure ---

    Context 'Top-level structure' {
        It 'Has required top-level properties' {
            $props = $map.PSObject.Properties.Name
            $props | Should -Contain 'version' -Because 'version is required'
            $props | Should -Contain 'featureGroups' -Because 'featureGroups is required'
            $props | Should -Contain 'skuTiers' -Because 'skuTiers is required'
        }

        It 'Version follows semver format' {
            $map.version | Should -Match '^\d+\.\d+\.\d+$' `
                -Because 'version must follow MAJOR.MINOR.PATCH semver format'
        }

        It 'Has at least one feature group' {
            $groupKeys.Count | Should -BeGreaterOrEqual 1 `
                -Because 'there must be at least one feature group'
        }

        It 'Has E3 and E5 SKU tiers' {
            $tierNames = $skuTiers.PSObject.Properties.Name
            $tierNames | Should -Contain 'E3' -Because 'E3 tier is required'
            $tierNames | Should -Contain 'E5' -Because 'E5 tier is required'
        }
    }

    # --- Feature group fields ---

    Context 'Feature group field validation' {
        It 'Every feature group has all 8 required fields' {
            $requiredFields = @('displayName', 'description', 'category', 'servicePlans', 'detectionChecks', 'valueCategory', 'estimatedEffort', 'quickWin')
            foreach ($key in $groupKeys) {
                $group = $featureGroups.$key
                foreach ($field in $requiredFields) {
                    $group.PSObject.Properties.Name | Should -Contain $field `
                        -Because "feature group '$key' must have field '$field'"
                }
            }
        }

        It 'Every feature group category is a valid enum value' {
            $validCategories = @('Identity', 'Security', 'Compliance', 'Collaboration', 'Productivity')
            foreach ($key in $groupKeys) {
                $featureGroups.$key.category | Should -BeIn $validCategories `
                    -Because "'$key' category must be one of: $($validCategories -join ', ')"
            }
        }

        It 'Every feature group valueCategory is a valid enum value' {
            $validValueCategories = @('Security', 'Compliance', 'Productivity', 'Collaboration')
            foreach ($key in $groupKeys) {
                $featureGroups.$key.valueCategory | Should -BeIn $validValueCategories `
                    -Because "'$key' valueCategory must be one of: $($validValueCategories -join ', ')"
            }
        }

        It 'Every feature group estimatedEffort is a valid enum value' {
            $validEfforts = @('Low', 'Medium', 'High')
            foreach ($key in $groupKeys) {
                $featureGroups.$key.estimatedEffort | Should -BeIn $validEfforts `
                    -Because "'$key' estimatedEffort must be one of: $($validEfforts -join ', ')"
            }
        }

        It 'Every feature group quickWin is a boolean' {
            foreach ($key in $groupKeys) {
                $featureGroups.$key.quickWin | Should -BeOfType [bool] `
                    -Because "'$key' quickWin must be a boolean"
            }
        }

        It 'Every feature group has non-empty displayName and description strings' {
            foreach ($key in $groupKeys) {
                $featureGroups.$key.displayName | Should -Not -BeNullOrEmpty `
                    -Because "'$key' displayName must not be empty"
                $featureGroups.$key.description | Should -Not -BeNullOrEmpty `
                    -Because "'$key' description must not be empty"
            }
        }

        It 'Every feature group has non-empty servicePlans and detectionChecks arrays' {
            foreach ($key in $groupKeys) {
                $featureGroups.$key.servicePlans.Count | Should -BeGreaterOrEqual 1 `
                    -Because "'$key' must have at least one service plan"
                $featureGroups.$key.detectionChecks.Count | Should -BeGreaterOrEqual 1 `
                    -Because "'$key' must have at least one detection check"
            }
        }
    }

    # --- Detection check references ---

    Context 'Detection check references' {
        It 'Every detectionChecks entry exists in registry.json' {
            $missing = @()
            foreach ($key in $groupKeys) {
                foreach ($checkId in $featureGroups.$key.detectionChecks) {
                    if (-not $registryCheckIds.Contains($checkId)) {
                        $missing += "$checkId (in '$key')"
                    }
                }
            }
            $missing | Should -BeNullOrEmpty `
                -Because "all detection check references must exist in registry.json"
        }
    }

    # --- No duplicates ---

    Context 'Uniqueness constraints' {
        It 'Feature group keys are unique' {
            $dupes = $groupKeys | Group-Object | Where-Object { $_.Count -gt 1 }
            $dupes | Should -BeNullOrEmpty -Because 'feature group keys must be unique'
        }

        It 'No detection check appears in multiple feature groups' {
            $seen = @{}
            $duplicates = @()
            foreach ($key in $groupKeys) {
                foreach ($checkId in $featureGroups.$key.detectionChecks) {
                    if ($seen.ContainsKey($checkId)) {
                        $duplicates += "$checkId (in '$($seen[$checkId])' and '$key')"
                    }
                    $seen[$checkId] = $key
                }
            }
            $duplicates | Should -BeNullOrEmpty `
                -Because "each detection check should belong to exactly one feature group"
        }
    }

    # --- SKU tier plans ---

    Context 'SKU tier plan validation' -ForEach @('E3', 'E5') {
        It '<_> has at least one included plan' {
            $skuTiers.$_.includedPlans.Count | Should -BeGreaterOrEqual 1 `
                -Because "SKU tier '$_' must have at least one plan"
        }

        It '<_> has no duplicate plans' {
            $plans = $skuTiers.$_.includedPlans
            $dupes = $plans | Group-Object | Where-Object { $_.Count -gt 1 }
            $dupes | Should -BeNullOrEmpty `
                -Because "SKU tier '$_' must not have duplicate plans"
        }
    }
}
