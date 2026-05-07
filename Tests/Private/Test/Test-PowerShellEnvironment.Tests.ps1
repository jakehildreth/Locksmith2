#requires -Version 5.1
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot))
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {

    Describe 'Test-PowerShellEnvironment' -Tag 'Unit' {

        BeforeEach {
            Mock Test-IsWindows { return $true }
            Mock Test-IsSupportedOS { return $true }
            Mock Test-IsSupportedPS { return $true }
            Mock Test-IsPowerShellCore { return $true }
            Mock Test-IsWindowsTerminal { return $true }
            Mock Test-IsUtf8 { return $true }
            Mock Test-IsModuleLoaded { return $true }
        }

        Context 'Return value structure' {

            It 'should return a dictionary (hashtable or ordered)' {
                $result = Test-PowerShellEnvironment
                $result | Should -BeOfType [System.Collections.IDictionary]
            }

            It 'should contain IsWindows key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'IsWindows' | Should -BeTrue
            }

            It 'should contain IsSupportedOS key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'IsSupportedOS' | Should -BeTrue
            }

            It 'should contain IsSupportedPS key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'IsSupportedPS' | Should -BeTrue
            }

            It 'should contain IsPowerShellCore key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'IsPowerShellCore' | Should -BeTrue
            }

            It 'should contain IsWindowsTerminal key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'IsWindowsTerminal' | Should -BeTrue
            }

            It 'should contain IsUtf8 key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'IsUtf8' | Should -BeTrue
            }

            It 'should contain AllModulesLoaded key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'AllModulesLoaded' | Should -BeTrue
            }

            It 'should contain MissingModules key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'MissingModules' | Should -BeTrue
            }
        }

        Context 'Happy path — all checks pass' {

            It 'should return IsWindows as $true when Test-IsWindows returns $true' {
                $result = Test-PowerShellEnvironment
                $result.IsWindows | Should -BeTrue
            }

            It 'should return IsSupportedOS as $true when Test-IsSupportedOS returns $true' {
                $result = Test-PowerShellEnvironment
                $result.IsSupportedOS | Should -BeTrue
            }

            It 'should return IsSupportedPS as $true when Test-IsSupportedPS returns $true' {
                $result = Test-PowerShellEnvironment
                $result.IsSupportedPS | Should -BeTrue
            }

            It 'should return IsPowerShellCore as $true when Test-IsPowerShellCore returns $true' {
                $result = Test-PowerShellEnvironment
                $result.IsPowerShellCore | Should -BeTrue
            }

            It 'should return IsWindowsTerminal as $true when Test-IsWindowsTerminal returns $true' {
                $result = Test-PowerShellEnvironment
                $result.IsWindowsTerminal | Should -BeTrue
            }

            It 'should return IsUtf8 as $true when Test-IsUtf8 returns $true' {
                $result = Test-PowerShellEnvironment
                $result.IsUtf8 | Should -BeTrue
            }

            It 'should return AllModulesLoaded as $true when all modules are loaded' {
                Mock Test-IsModuleLoaded { return $true }
                $result = Test-PowerShellEnvironment
                $result.AllModulesLoaded | Should -BeTrue
            }

            It 'should return MissingModules as an empty collection when all modules are loaded' {
                Mock Test-IsModuleLoaded { return $true }
                $result = Test-PowerShellEnvironment
                $result.MissingModules | Should -BeNullOrEmpty
            }
        }

        Context 'Non-fatal warnings — module checks' {

            It 'should set AllModulesLoaded to $false when at least one module is not loaded' {
                Mock Test-IsModuleLoaded { return $false }
                $result = Test-PowerShellEnvironment
                $result.AllModulesLoaded | Should -BeFalse
            }

            It 'should populate MissingModules when modules are not loaded' {
                Mock Test-IsModuleLoaded { return $false }
                $result = Test-PowerShellEnvironment
                $result.MissingModules | Should -Not -BeNullOrEmpty
            }

            It 'should check for PSCertutil module' {
                Test-PowerShellEnvironment
                Should -Invoke Test-IsModuleLoaded -ParameterFilter { $Name -eq 'PSCertutil' } -Times 1
            }

            It 'should check for PwshSpectreConsole module' {
                Test-PowerShellEnvironment
                Should -Invoke Test-IsModuleLoaded -ParameterFilter { $Name -eq 'PwshSpectreConsole' } -Times 1
            }

            It 'should check for PSWriteHTML module' {
                Test-PowerShellEnvironment
                Should -Invoke Test-IsModuleLoaded -ParameterFilter { $Name -eq 'PSWriteHTML' } -Times 1
            }
        }

        Context 'Terminating errors for unsupported environments' {

            It 'should throw a terminating error when Test-IsWindows returns $false' {
                Mock Test-IsWindows { return $false }
                { Test-PowerShellEnvironment } | Should -Throw
            }

            It 'should throw a terminating error when Test-IsSupportedOS returns $false' {
                Mock Test-IsSupportedOS { return $false }
                { Test-PowerShellEnvironment } | Should -Throw
            }

            It 'should throw a terminating error when Test-IsSupportedPS returns $false' {
                Mock Test-IsSupportedPS { return $false }
                { Test-PowerShellEnvironment } | Should -Throw
            }
        }
    }
}
