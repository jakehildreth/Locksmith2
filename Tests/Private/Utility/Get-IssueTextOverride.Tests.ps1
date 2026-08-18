BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Get-IssueTextOverride' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeAll {
            $script:BaseConfig = @{
                Technique      = 'SchemaV1'
                IssueTemplate  = 'base issue'
                FixTemplate    = 'base fix'
                RevertTemplate = 'base revert'
                Overrides      = @(
                    @{
                        When           = @{ Property = 'IsCATemplate'; Value = $true }
                        IssueTemplate  = 'override issue'
                        FixTemplate    = 'override fix'
                        RevertTemplate = 'override revert'
                    }
                )
            }
        }

        Context 'No Overrides key on config' {
            It 'should return the base config when Overrides is absent' {
                $config = @{ IssueTemplate = 'base issue' }
                $template = New-MockLS2AdcsObject

                $result = Get-IssueTextOverride -Config $config -AdcsObject $template

                $result.IssueTemplate | Should -Be 'base issue'
            }
        }

        Context 'Empty Overrides array' {
            It 'should return the base config when Overrides is empty' {
                $config = @{ IssueTemplate = 'base issue'; Overrides = @() }
                $template = New-MockLS2AdcsObject

                $result = Get-IssueTextOverride -Config $config -AdcsObject $template

                $result.IssueTemplate | Should -Be 'base issue'
            }
        }

        Context 'When condition matches' {
            It 'should return the override text when the property equals the value' {
                $template = New-MockLS2AdcsObject -Properties @{ IsCATemplate = $true }

                $result = Get-IssueTextOverride -Config $script:BaseConfig -AdcsObject $template

                $result.IssueTemplate  | Should -Be 'override issue'
                $result.FixTemplate    | Should -Be 'override fix'
                $result.RevertTemplate | Should -Be 'override revert'
            }
        }

        Context 'When condition does not match' {
            It 'should return the base config when the property differs' {
                $template = New-MockLS2AdcsObject -Properties @{ IsCATemplate = $false }

                $result = Get-IssueTextOverride -Config $script:BaseConfig -AdcsObject $template

                $result.IssueTemplate | Should -Be 'base issue'
            }

            It 'should return the base config when the property is null' {
                $template = New-MockLS2AdcsObject
                $template.IsCATemplate = $false

                $result = Get-IssueTextOverride -Config $script:BaseConfig -AdcsObject $template

                $result.FixTemplate | Should -Be 'base fix'
            }
        }

        Context 'Multiple overrides' {
            It 'should return the first matching override' {
                $config = @{
                    IssueTemplate = 'base'
                    Overrides     = @(
                        @{ When = @{ Property = 'IsCATemplate'; Value = $true }; IssueTemplate = 'first' }
                        @{ When = @{ Property = 'IsCATemplate'; Value = $true }; IssueTemplate = 'second' }
                    )
                }
                $template = New-MockLS2AdcsObject -Properties @{ IsCATemplate = $true }

                $result = Get-IssueTextOverride -Config $config -AdcsObject $template

                $result.IssueTemplate | Should -Be 'first'
            }
        }
    }
}
