#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test'
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsDA.ps1') -Raw)))

    # Stubs for the module functions Test-IsDA depends on.
    function Convert-IdentityReferenceToSid { param([Parameter(ValueFromPipeline)]$InputObject) }
    function New-AuthenticatedDirectoryEntry { param([string]$Path, [System.Management.Automation.PSCredential]$Credential) }

    # Returns the ParameterAttribute instances for a given parameter.
    function Get-ParamAttr {
        param($Command, $Name)
        (Get-Command $Command).Parameters[$Name].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
    }
}

Describe 'Test-IsDA' -Tag 'Unit' {

    Context 'Parameter contract' {

        It 'should return a [bool]' {
            Test-IsDA -ErrorAction SilentlyContinue | Should -BeOfType [bool]
        }

        It 'should not require -Credential' {
            (Get-ParamAttr -Command 'Test-IsDA' -Name 'Credential').Mandatory | Should -Not -Contain $true
        }

        It 'should not require -RootDSE' {
            (Get-ParamAttr -Command 'Test-IsDA' -Name 'RootDSE').Mandatory | Should -Not -Contain $true
        }

        It 'should type -RootDSE as a DirectoryEntry' {
            (Get-Command Test-IsDA).Parameters['RootDSE'].ParameterType.FullName |
                Should -Be 'System.DirectoryServices.DirectoryEntry'
        }

        It 'should declare a [bool] output type' {
            (Get-Command Test-IsDA).OutputType.Name | Should -Match 'Boolean'
        }
    }

    Context 'When the identity cannot be resolved to a SID' {

        It 'should fail safe to $false' {
            Mock Convert-IdentityReferenceToSid { $null }

            $cred    = [System.Management.Automation.PSCredential]::new(
                'CONTOSO\test', (ConvertTo-SecureString 'x' -AsPlainText -Force))
            $rootDSE = [System.DirectoryServices.DirectoryEntry]::new()

            Test-IsDA -Credential $cred -RootDSE $rootDSE -WarningAction SilentlyContinue |
                Should -BeFalse
        }
    }

    Context 'When the RootDSE path is unusable' {

        It 'should fail safe to $false when no server can be parsed from RootDSE' {
            Mock Convert-IdentityReferenceToSid {
                [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001')
            }

            $cred    = [System.Management.Automation.PSCredential]::new(
                'CONTOSO\test', (ConvertTo-SecureString 'x' -AsPlainText -Force))
            $rootDSE = [System.DirectoryServices.DirectoryEntry]::new()

            Test-IsDA -Credential $cred -RootDSE $rootDSE -WarningAction SilentlyContinue |
                Should -BeFalse
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
