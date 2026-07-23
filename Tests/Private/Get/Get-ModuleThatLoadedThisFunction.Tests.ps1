#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}

Describe 'Get-ModuleThatLoadedThisFunction' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        Context 'Call stack has a caller script within a loaded module' {
            It 'should return the module name when the calling script is within a module' {
                $fakeModule = [PSCustomObject]@{
                    Name       = 'FakeModule'
                    Path       = 'C:\Modules\FakeModule\FakeModule.psm1'
                    ModuleBase = 'C:\Modules\FakeModule'
                }

                $fakeCallerFrame = [PSCustomObject]@{
                    ScriptName = 'C:\Modules\FakeModule\Private\SomeFunction.ps1'
                }

                # The function itself is index 0, caller is index 1
                $fakeCallStack = @(
                    [PSCustomObject]@{ ScriptName = 'C:\Modules\FakeModule\Private\Get-ModuleThatLoadedThisFunction.ps1' },
                    $fakeCallerFrame
                )

                Mock 'Get-PSCallStack' { $fakeCallStack }
                Mock 'Get-Module' { @($fakeModule) }

                $result = Get-ModuleThatLoadedThisFunction
                $result | Should -Be 'FakeModule'
            }
        }

        Context 'Call stack has caller outside any loaded module' {
            It 'should return $null when no module matches the calling script path' {
                $fakeModule = [PSCustomObject]@{
                    Name       = 'OtherModule'
                    Path       = 'C:\Modules\OtherModule\OtherModule.psm1'
                    ModuleBase = 'C:\Modules\OtherModule'
                }

                $fakeCallStack = @(
                    [PSCustomObject]@{ ScriptName = 'C:\SomeScript\Get-ModuleThatLoadedThisFunction.ps1' },
                    [PSCustomObject]@{ ScriptName = 'C:\SomeScript\Caller.ps1' }
                )

                Mock 'Get-PSCallStack' { $fakeCallStack }
                Mock 'Get-Module' { @($fakeModule) }

                $result = Get-ModuleThatLoadedThisFunction
                $result | Should -BeNullOrEmpty
            }
        }

        Context 'Call stack has only one frame (no caller)' {
            It 'should return $null when call stack has no second frame' {
                $fakeCallStack = @(
                    [PSCustomObject]@{ ScriptName = 'C:\Modules\FakeModule\Get-ModuleThatLoadedThisFunction.ps1' }
                )

                Mock 'Get-PSCallStack' { $fakeCallStack }
                Mock 'Get-Module' { @() }

                $result = Get-ModuleThatLoadedThisFunction
                $result | Should -BeNullOrEmpty
            }
        }

        Context 'Caller script path is null or empty' {
            It 'should return $null when the calling script name is empty' {
                $fakeCallStack = @(
                    [PSCustomObject]@{ ScriptName = $null },
                    [PSCustomObject]@{ ScriptName = $null }
                )

                Mock 'Get-PSCallStack' { $fakeCallStack }
                Mock 'Get-Module' { @() }

                $result = Get-ModuleThatLoadedThisFunction
                $result | Should -BeNullOrEmpty
            }
        }

        Context 'Error handling' {
            It 'should return $null and write an error when Get-PSCallStack throws' {
                Mock 'Get-PSCallStack' { throw 'Unexpected error' }

                $result = Get-ModuleThatLoadedThisFunction -ErrorVariable errOut 2>&1 |
                    Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }
                $result | Should -BeNullOrEmpty
            }
        }
    }
}
