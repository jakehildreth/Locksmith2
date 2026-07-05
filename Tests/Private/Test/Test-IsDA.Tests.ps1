#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test'
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsDA.ps1') -Raw)))
}

Describe 'Test-IsDA' -Tag 'Unit' {

    Context 'Contract' {

        It 'should return a [bool]' {
            Test-IsDA -ErrorAction SilentlyContinue | Should -BeOfType [bool]
        }

        It 'should expose no parameters of its own' {
            $explicit = (Get-Command Test-IsDA).Parameters.Keys |
                Where-Object { $_ -notin [System.Management.Automation.Cmdlet]::CommonParameters }
            $explicit | Should -BeNullOrEmpty
        }
    }

    Context 'When the Windows identity API is unavailable' -Skip:($env:OS -eq 'Windows_NT') {

        It 'should fail safe to $false' {
            Test-IsDA -ErrorAction SilentlyContinue | Should -BeFalse
        }

        It 'should write a non-terminating error rather than throw' {
            { Test-IsDA -ErrorAction SilentlyContinue } | Should -Not -Throw
            Test-IsDA -ErrorVariable err -ErrorAction SilentlyContinue | Out-Null
            $err | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When running on Windows' -Tag 'Integration' -Skip:($env:OS -ne 'Windows_NT') {

        It 'should agree with the token for well-known RID 512' {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $expected = [bool]($identity.Groups | Where-Object { $_.Value -match '-512$' })

            Test-IsDA | Should -Be $expected
        }
    }
}
