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
    Describe 'Show-ConnectionContext' -Tag 'Unit' {
        BeforeEach {
            Mock 'Write-Host' { }
            Mock 'Write-Verbose' { }
            Mock 'Read-Choice' { 'y' }
        }

        Context 'Parameter contract' {
            It 'should require -Context' {
                $attr = (Get-Command 'Show-ConnectionContext').Parameters['Context'].Attributes |
                    Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
                $attr.Mandatory | Should -Contain $true
            }

            It 'should type -Context as a hashtable' {
                (Get-Command 'Show-ConnectionContext').Parameters['Context'].ParameterType.FullName |
                    Should -Be 'System.Collections.Hashtable'
            }

            It 'should accept -Force as a switch' {
                (Get-Command 'Show-ConnectionContext').Parameters['Force'].ParameterType.FullName |
                    Should -Be 'System.Management.Automation.SwitchParameter'
            }
        }

        Context 'When displaying the connection context' {
            It 'should print the forest' {
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-ConnectionContext -Context $ctx -Force
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -eq '  Forest   : contoso.com' }
            }

            It 'should print the user when no credential is supplied' {
                Mock 'Test-IsInteractiveSession' { $true }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-ConnectionContext -Context $ctx -Force
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*User     :*' }
            }

            It 'should print the credential user when a credential is supplied' {
                $cred = [System.Management.Automation.PSCredential]::new(
                    'CONTOSO\admin', (ConvertTo-SecureString 'x' -AsPlainText -Force))
                $ctx = @{ Forest = 'contoso.com'; Credential = $cred; Method = 'ExplicitCredential' }
                Show-ConnectionContext -Context $ctx -Force
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*CONTOSO\admin*' }
            }

            It 'should print the computer' {
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-ConnectionContext -Context $ctx -Force
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -like '*Computer :*' }
            }

            It 'should print the method' {
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-ConnectionContext -Context $ctx -Force
                Should -Invoke 'Write-Host' -ParameterFilter { $Object -eq '  Method   : DomainUser' }
            }
        }

        Context 'When prompting for confirmation' {
            It 'should prompt when -Force is not specified' {
                Mock 'Test-IsInteractiveSession' { $true }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-ConnectionContext -Context $ctx
                Should -Invoke 'Read-Choice' -Times 1
            }

            It 'should not prompt when -Force is specified' {
                Mock 'Test-IsInteractiveSession' { $true }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-ConnectionContext -Context $ctx -Force
                Should -Invoke 'Read-Choice' -Times 0
            }

            It 'should not prompt when not interactive' {
                Mock 'Test-IsInteractiveSession' { $false }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                Show-ConnectionContext -Context $ctx
                Should -Invoke 'Read-Choice' -Times 0
            }

            It 'should return $false when the user declines' {
                Mock 'Test-IsInteractiveSession' { $true }
                Mock 'Read-Choice' { 'n' }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                $result = Show-ConnectionContext -Context $ctx
                $result | Should -BeFalse
            }

            It 'should return $true when the user confirms' {
                Mock 'Test-IsInteractiveSession' { $true }
                Mock 'Read-Choice' { 'y' }
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                $result = Show-ConnectionContext -Context $ctx
                $result | Should -BeTrue
            }

            It 'should return $true when -Force is specified' {
                $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
                $result = Show-ConnectionContext -Context $ctx -Force
                $result | Should -BeTrue
            }
        }
    }
}
