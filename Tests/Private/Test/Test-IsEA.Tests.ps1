#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test'
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsEA.ps1') -Raw)))
}

Describe 'Test-IsEA' -Tag 'Unit' {

    Context 'Contract' {

        It 'should return a [bool]' {
            Test-IsEA -ErrorAction SilentlyContinue | Should -BeOfType [bool]
        }

        It 'should expose no parameters of its own' {
            $explicit = (Get-Command Test-IsEA).Parameters.Keys |
                Where-Object { $_ -notin [System.Management.Automation.Cmdlet]::CommonParameters }
            $explicit | Should -BeNullOrEmpty
        }
    }

    Context 'When the Windows identity API is unavailable' -Skip:($IsWindows) {

        It 'should fail safe to $false' {
            Test-IsEA -ErrorAction SilentlyContinue | Should -BeFalse
        }

        It 'should write a non-terminating error rather than throw' {
            { Test-IsEA -ErrorAction SilentlyContinue } | Should -Not -Throw
            Test-IsEA -ErrorVariable err -ErrorAction SilentlyContinue | Out-Null
            $err | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When running on Windows' -Tag 'Integration' -Skip:(-not $IsWindows) {

        It 'should agree with the token for well-known RID 519' {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $expected = [bool]($identity.Groups | Where-Object { $_.Value -match '-519$' })

            Test-IsEA | Should -Be $expected
        }
    }
}
