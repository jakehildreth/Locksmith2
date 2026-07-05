#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test'
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsLocalAdmin.ps1') -Raw)))
}

Describe 'Test-IsLocalAdmin' -Tag 'Unit' {

    Context 'Contract' {

        It 'should return a [bool]' {
            Test-IsLocalAdmin -WarningAction SilentlyContinue | Should -BeOfType [bool]
        }

        It 'should never throw, even when the identity check fails' {
            { Test-IsLocalAdmin -WarningAction SilentlyContinue } | Should -Not -Throw
        }

        It 'should expose no parameters of its own' {
            $explicit = (Get-Command Test-IsLocalAdmin).Parameters.Keys |
                Where-Object { $_ -notin [System.Management.Automation.Cmdlet]::CommonParameters }
            $explicit | Should -BeNullOrEmpty
        }
    }

    Context 'When the Windows identity API is unavailable' -Skip:($env:OS -eq 'Windows_NT') {

        It 'should fail safe to $false' {
            Test-IsLocalAdmin -WarningAction SilentlyContinue | Should -BeFalse
        }

        It 'should warn the caller that elevation could not be determined' {
            Test-IsLocalAdmin -WarningVariable warn -WarningAction SilentlyContinue | Out-Null
            $warn | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When running on Windows' -Tag 'Integration' -Skip:($env:OS -ne 'Windows_NT') {

        It 'should agree with the current principal Administrator role' {
            $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]$identity
            $expected  = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

            Test-IsLocalAdmin | Should -Be $expected
        }
    }
}
