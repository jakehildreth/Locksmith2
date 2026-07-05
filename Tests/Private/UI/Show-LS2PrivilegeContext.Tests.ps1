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

InModuleScope 'Locksmith2' {
    Describe 'Show-LS2PrivilegeContext' -Tag 'Unit' {
        BeforeEach {
            Mock 'Write-Host' { }
            Mock 'Write-Verbose' { }
            Mock 'Write-Warning' { }

            Mock 'Test-IsDA' { $false }
            Mock 'Test-IsEA' { $false }
            Mock 'Test-IsLocalAdmin' { $false }
            Mock 'Test-IsBA' { $false }
        }

        Context 'Parameter contract' {
            It 'should require -Context' {
                $attr = (Get-Command 'Show-LS2PrivilegeContext').Parameters['Context'].Attributes |
                    Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
                $attr.Mandatory | Should -Contain $true
            }

            It 'should type -Context as a hashtable' {
                (Get-Command 'Show-LS2PrivilegeContext').Parameters['Context'].ParameterType.FullName |
                    Should -Be 'System.Collections.Hashtable'
            }
        }

        Context 'When displaying privilege status' {
            It 'should print DA status' {
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-LS2PrivilegeContext -Context $ctx
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Domain Admin*' }
            }

            It 'should print EA status' {
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-LS2PrivilegeContext -Context $ctx
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Enterprise Admin*' }
            }

            It 'should print BA status' {
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-LS2PrivilegeContext -Context $ctx
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Builtin Admin*' }
            }

            It 'should print local admin status' {
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-LS2PrivilegeContext -Context $ctx
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Local Admin*' }
            }

            It 'should call Test-IsBA with the credential when one is supplied' {
                $cred = [System.Management.Automation.PSCredential]::new(
                    'CONTOSO\admin', (ConvertTo-SecureString 'x' -AsPlainText -Force))
                $ctx = @{ Forest = 'contoso.com'; Credential = $cred; Method = 'ExplicitCredential' }
                $rootDSE = [System.DirectoryServices.DirectoryEntry]::new()
                Show-LS2PrivilegeContext -Context $ctx -RootDSE $rootDSE
                Should -Invoke 'Test-IsBA' -ParameterFilter { $Credential -eq $cred -and $RootDSE -eq $rootDSE }
            }

            It 'should call Test-IsBA with a null credential when none is supplied' {
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                $rootDSE = [System.DirectoryServices.DirectoryEntry]::new()
                Show-LS2PrivilegeContext -Context $ctx -RootDSE $rootDSE
                Should -Invoke 'Test-IsBA' -ParameterFilter { $Credential -eq $null -and $RootDSE -eq $rootDSE }
            }
        }

        Context 'When privilege checks return true' {
            It 'should indicate DA privileges' {
                Mock 'Test-IsDA' { $true }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-LS2PrivilegeContext -Context $ctx
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Yes*' -and $Object -like '*Domain Admin*' }
            }

            It 'should indicate EA privileges' {
                Mock 'Test-IsEA' { $true }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-LS2PrivilegeContext -Context $ctx
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Yes*' -and $Object -like '*Enterprise Admin*' }
            }

            It 'should indicate BA privileges' {
                $cred = [System.Management.Automation.PSCredential]::new(
                    'CONTOSO\admin', (ConvertTo-SecureString 'x' -AsPlainText -Force))
                Mock 'Test-IsBA' { $true }
                $rootDSE = [System.DirectoryServices.DirectoryEntry]::new()
                $ctx = @{ Forest = 'contoso.com'; Credential = $cred; Method = 'ExplicitCredential' }
                Show-LS2PrivilegeContext -Context $ctx -RootDSE $rootDSE
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Builtin Admin*' }
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Yes*' }
            }

            It 'should indicate local admin privileges' {
                Mock 'Test-IsLocalAdmin' { $true }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-LS2PrivilegeContext -Context $ctx
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Yes*' -and $Object -like '*Local Admin*' }
            }
        }

        Context 'When Test-IsBA fails' {
            It 'should display BA as unknown and write a warning when Test-IsBA errors' {
                $cred = [System.Management.Automation.PSCredential]::new(
                    'CONTOSO\admin', (ConvertTo-SecureString 'x' -AsPlainText -Force))
                Mock 'Test-IsBA' { $PSCmdlet.WriteError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new('boom'),
                        'BAFailed',
                        [System.Management.Automation.ErrorCategory]::NotSpecified,
                        $null
                    )
                ); $false }
                $ctx = @{ Forest = 'contoso.com'; Credential = $cred; Method = 'ExplicitCredential' }
                $rootDSE = [System.DirectoryServices.DirectoryEntry]::new()
                Show-LS2PrivilegeContext -Context $ctx -RootDSE $rootDSE -ErrorAction SilentlyContinue
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Builtin Admin*' -and $Object -like '*Unknown*' }
                Should -Invoke 'Write-Warning' -Times 1
            }

            It 'should display BA as unknown when Test-IsBA errors without a credential' {
                Mock 'Test-IsBA' { $PSCmdlet.WriteError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.Exception]::new('boom'),
                        'BAFailed',
                        [System.Management.Automation.ErrorCategory]::NotSpecified,
                        $null
                    )
                ); $false }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                $rootDSE = [System.DirectoryServices.DirectoryEntry]::new()
                Show-LS2PrivilegeContext -Context $ctx -RootDSE $rootDSE -ErrorAction SilentlyContinue
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Builtin Admin*' -and $Object -like '*Unknown*' }
                Should -Invoke 'Write-Warning' -Times 1
            }
        }

        Context 'When running non-interactively' {
            It 'should not print the privilege context block' {
                Mock 'Test-IsInteractiveSession' { $false }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-LS2PrivilegeContext -Context $ctx
                Should -Invoke 'Write-Host' -Times 0
            }

            It 'should still write verbose privilege lines' {
                Mock 'Test-IsInteractiveSession' { $false }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-LS2PrivilegeContext -Context $ctx
                Should -Invoke 'Write-Verbose' -Times 1 -Exactly:$false
            }
        }
    }
}
