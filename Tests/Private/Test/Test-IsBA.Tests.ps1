#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test'
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsBA.ps1') -Raw)))

    # Stubs for the module functions Test-IsBA depends on.
    function Convert-IdentityReferenceToSid { param([Parameter(ValueFromPipeline)]$InputObject) }
    function New-AuthenticatedDirectoryEntry { param([string]$Path, [System.Management.Automation.PSCredential]$Credential) }

    # Returns the ParameterAttribute instances for a given parameter.
    function Get-ParamAttr {
        param($Command, $Name)
        (Get-Command $Command).Parameters[$Name].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
    }
}

Describe 'Test-IsBA' -Tag 'Unit' {

    Context 'Parameter contract' {

        It 'should not require -Credential' {
            (Get-ParamAttr -Command 'Test-IsBA' -Name 'Credential').Mandatory | Should -Not -Contain $true
        }

        It 'should require -RootDSE' {
            (Get-ParamAttr -Command 'Test-IsBA' -Name 'RootDSE').Mandatory | Should -Contain $true
        }

        It 'should type -RootDSE as a DirectoryEntry' {
            (Get-Command Test-IsBA).Parameters['RootDSE'].ParameterType.FullName |
                Should -Be 'System.DirectoryServices.DirectoryEntry'
        }

        It 'should declare a [bool] output type' {
            (Get-Command Test-IsBA).OutputType.Name | Should -Match 'Boolean'
        }

        It 'should not expose an -IdentityReference parameter' {
            (Get-Command Test-IsBA).Parameters.ContainsKey('IdentityReference') | Should -BeFalse
        }
    }

    Context 'When the credential user cannot be resolved to a SID' {

        It 'should fail safe to $false' {
            Mock Convert-IdentityReferenceToSid { $null }

            $cred    = [System.Management.Automation.PSCredential]::new(
                'CONTOSO\test', (ConvertTo-SecureString 'x' -AsPlainText -Force))
            $rootDSE = [System.DirectoryServices.DirectoryEntry]::new()

            Test-IsBA -Credential $cred -RootDSE $rootDSE -WarningAction SilentlyContinue |
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

            Test-IsBA -Credential $cred -RootDSE $rootDSE -WarningAction SilentlyContinue |
                Should -BeFalse
        }
    }
}
