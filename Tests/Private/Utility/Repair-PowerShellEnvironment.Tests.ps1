#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot))
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot))
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {

    Describe 'Update-OutputEncoding' -Tag 'Unit' {

        AfterAll {
            # Restore UTF-8 after encoding tests so we don't break downstream tests
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        }

        It 'should set console output encoding to UTF-8 (CodePage 65001)' {
            [Console]::OutputEncoding = [System.Text.Encoding]::ASCII
            Update-OutputEncoding
            [Console]::OutputEncoding.CodePage | Should -Be 65001
        }

        It 'should be idempotent when encoding is already UTF-8' {
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
            { Update-OutputEncoding } | Should -Not -Throw
            [Console]::OutputEncoding.CodePage | Should -Be 65001
        }
    }

    Describe 'Update-DollarSignProfile' -Tag 'Unit' {

        It 'should not throw when invoked' {
            Mock Add-Content { }
            Mock Set-Content { }
            Mock Out-File { }
            { Update-DollarSignProfile } | Should -Not -Throw
        }
    }

    Describe 'Repair-PowerShellEnvironment' -Tag 'Unit' {

        BeforeEach {
            Mock Test-PowerShellEnvironment {
                return @{
                    IsWindows        = $true
                    IsSupportedOS    = $true
                    IsSupportedPS    = $true
                    IsUtf8           = $true
                }
            }
            Mock Update-OutputEncoding { }
            Mock Update-DollarSignProfile { }
            Mock Test-IsModuleAvailable { return $false }
        }

        Context 'Return value structure' {

            It 'should return a PSCustomObject' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result | Should -BeOfType [PSCustomObject]
            }

            It 'should have EncodingRepaired property' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result.PSObject.Properties.Name | Should -Contain 'EncodingRepaired'
            }

            It 'should have ProfileUpdated property' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result.PSObject.Properties.Name | Should -Contain 'ProfileUpdated'
            }

            It 'should NOT have ModulesInstalled property' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result.PSObject.Properties.Name | Should -Not -Contain 'ModulesInstalled'
            }

            It 'should NOT have ModulesImported property' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result.PSObject.Properties.Name | Should -Not -Contain 'ModulesImported'
            }

            It 'should have RemainingIssues property' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result.PSObject.Properties.Name | Should -Contain 'RemainingIssues'
            }

            It 'should have Success property' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result.PSObject.Properties.Name | Should -Contain 'Success'
            }
        }

        Context 'Encoding repair' {

            It 'should set EncodingRepaired to $true when IsUtf8 is $false and Force is used' {
                $result = Repair-PowerShellEnvironment -Force -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $false
                }
                $result.EncodingRepaired | Should -BeTrue
            }

            It 'should not set EncodingRepaired to $true when IsUtf8 is already $true' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result.EncodingRepaired | Should -BeFalse
            }
        }

        Context 'Non-fixable issues go to RemainingIssues' {

            It 'should record an OS issue in RemainingIssues when IsWindows is $false' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $false; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result.RemainingIssues | Should -Not -BeNullOrEmpty
            }

            It 'should record an OS version issue in RemainingIssues when IsSupportedOS is $false' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $false; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                $result.RemainingIssues | Should -Not -BeNullOrEmpty
            }

            It 'should record a PS version issue in RemainingIssues when IsSupportedPS is $false' {
                $result = Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $false
                    IsUtf8 = $true
                }
                $result.RemainingIssues | Should -Not -BeNullOrEmpty
            }
        }

        Context 'Profile update' {

            It 'should skip profile update when SkipProfileUpdate switch is specified' {
                $result = Repair-PowerShellEnvironment -SkipProfileUpdate -Force -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $false
                }
                $result.ProfileUpdated | Should -BeFalse
                Should -Invoke Update-DollarSignProfile -Times 0
            }
        }

        Context 'Auto environment test' {

            It 'should call Test-PowerShellEnvironment when no EnvironmentTest is provided' {
                Repair-PowerShellEnvironment
                Should -Invoke Test-PowerShellEnvironment -Times 1 -Exactly
            }

            It 'should not call Test-PowerShellEnvironment when EnvironmentTest is provided' {
                Repair-PowerShellEnvironment -EnvironmentTest @{
                    IsWindows = $true; IsSupportedOS = $true; IsSupportedPS = $true
                    IsUtf8 = $true
                }
                Should -Invoke Test-PowerShellEnvironment -Times 0
            }
        }
    }
}
