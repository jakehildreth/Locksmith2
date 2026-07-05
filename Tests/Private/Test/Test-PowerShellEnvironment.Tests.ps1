#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot))
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot))
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {

    Describe 'Test-PowerShellEnvironment' -Tag 'Unit' {

        BeforeEach {
            Mock Test-IsWindows { return $true }
            Mock Test-IsSupportedOS { return $true }
            Mock Test-IsSupportedPS { return $true }
            Mock Test-IsUtf8 { return $true }
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

            It 'should NOT contain IsPowerShellCore key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'IsPowerShellCore' | Should -BeFalse
            }

            It 'should NOT contain IsWindowsTerminal key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'IsWindowsTerminal' | Should -BeFalse
            }

            It 'should contain IsUtf8 key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'IsUtf8' | Should -BeTrue
            }

            It 'should NOT contain AllModulesLoaded key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'AllModulesLoaded' | Should -BeFalse
            }

            It 'should NOT contain MissingModules key' {
                $result = Test-PowerShellEnvironment
                $result.Keys -contains 'MissingModules' | Should -BeFalse
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

            It 'should return IsUtf8 as $true when Test-IsUtf8 returns $true' {
                $result = Test-PowerShellEnvironment
                $result.IsUtf8 | Should -BeTrue
            }


        }

        Context 'Module checks removed' {

            It 'should NOT check for PSCertutil module' {
                Mock Test-IsModuleLoaded { return $true }
                Test-PowerShellEnvironment
                Should -Invoke Test-IsModuleLoaded -ParameterFilter { $Name -eq 'PSCertutil' } -Times 0
            }

            It 'should NOT check for PwshSpectreConsole module' {
                Mock Test-IsModuleLoaded { return $true }
                Test-PowerShellEnvironment
                Should -Invoke Test-IsModuleLoaded -ParameterFilter { $Name -eq 'PwshSpectreConsole' } -Times 0
            }

            It 'should NOT check for PSWriteHTML module' {
                Mock Test-IsModuleLoaded { return $true }
                Test-PowerShellEnvironment
                Should -Invoke Test-IsModuleLoaded -ParameterFilter { $Name -eq 'PSWriteHTML' } -Times 0
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
