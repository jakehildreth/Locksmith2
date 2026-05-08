#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

Describe 'Install-NeededModule' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        Context 'Module already loaded' {
            It 'should return $true immediately without prompting' {
                Mock 'Test-IsModuleLoaded' { $true }
                Mock 'Read-Choice' { 'y' }
                $result = Install-NeededModule -Name 'SomeModule' -Force
                $result | Should -BeTrue
                Should -Invoke 'Read-Choice' -Times 0
            }

            It 'should not call Install-Module when module is already loaded' {
                Mock 'Test-IsModuleLoaded' { $true }
                Mock 'Install-Module' { }
                Install-NeededModule -Name 'SomeModule' -Force | Out-Null
                Should -Invoke 'Install-Module' -Times 0
            }
        }

        Context 'Module available but not loaded' {
            BeforeEach {
                Mock 'Test-IsModuleLoaded' { $false }
                Mock 'Test-IsModuleAvailable' { $true }
                Mock 'Import-Module' { }
            }

            It 'should return $true when user confirms and import succeeds' {
                Mock 'Read-Choice' { 'y' }
                $result = Install-NeededModule -Name 'SomeModule'
                $result | Should -BeTrue
            }

            It 'should call Import-Module with the module name when user confirms' {
                Mock 'Read-Choice' { 'y' }
                Install-NeededModule -Name 'SomeModule' | Out-Null
                Should -Invoke 'Import-Module' -Times 1 -ParameterFilter { $Name -eq 'SomeModule' }
            }

            It 'should return $false for optional module when user declines' {
                Mock 'Read-Choice' { 'n' }
                $result = Install-NeededModule -Name 'SomeModule' -WarningMessage 'Feature unavailable.'
                $result | Should -BeFalse
            }

            It 'should not call Import-Module when user declines' {
                Mock 'Read-Choice' { 'n' }
                Install-NeededModule -Name 'SomeModule' -WarningMessage 'Feature unavailable.' | Out-Null
                Should -Invoke 'Import-Module' -Times 0
            }
        }

        Context 'Module not available (needs install)' {
            BeforeEach {
                Mock 'Test-IsModuleLoaded' { $false }
                Mock 'Test-IsModuleAvailable' { $false }
                Mock 'Install-Module' { }
                Mock 'Import-Module' { }
            }

            It 'should call Install-Module then Import-Module when user confirms' {
                Mock 'Read-Choice' { 'y' }
                $result = Install-NeededModule -Name 'SomeModule' -WarningMessage 'Feature X unavailable.'
                $result | Should -BeTrue
                Should -Invoke 'Install-Module' -Times 1 -ParameterFilter { $Name -eq 'SomeModule' }
                Should -Invoke 'Import-Module' -Times 1 -ParameterFilter { $Name -eq 'SomeModule' }
            }

            It 'should bypass Read-Choice when -Force is specified' {
                Mock 'Read-Choice' { throw 'Should not be called' }
                $result = Install-NeededModule -Name 'SomeModule' -Force
                $result | Should -BeTrue
            }
        }

        Context 'Mandatory module — user declines' {
            It 'should throw a terminating error when mandatory module is declined' {
                Mock 'Test-IsModuleLoaded' { $false }
                Mock 'Test-IsModuleAvailable' { $false }
                Mock 'Read-Choice' { 'n' }
                { Install-NeededModule -Name 'RequiredModule' -Mandatory } |
                    Should -Throw
            }
        }

        Context 'Import failure for optional module' {
            It 'should return $false when Import-Module throws for an optional module' {
                Mock 'Test-IsModuleLoaded' { $false }
                Mock 'Test-IsModuleAvailable' { $true }
                Mock 'Read-Choice' { 'y' }
                Mock 'Import-Module' { throw 'Import failed' }
                $result = Install-NeededModule -Name 'SomeModule' -WarningMessage 'Feature X unavailable.'
                $result | Should -BeFalse
            }
        }

        Context 'Return type' {
            It 'should return [bool]' {
                Mock 'Test-IsModuleLoaded' { $true }
                $result = Install-NeededModule -Name 'SomeModule'
                $result | Should -BeOfType [bool]
            }
        }
    }
}
