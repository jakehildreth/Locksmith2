#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

# New-AuthenticatedDirectoryEntry calls New-Object System.DirectoryServices.DirectoryEntry with real
# credentials and an LDAP path. All tests require a working credential and ADSI connection.
$script:CanTestDirectoryEntry = $false
try {
    $testEntry = [System.DirectoryServices.DirectoryEntry]::new()
    $null = $testEntry.Path
    $script:CanTestDirectoryEntry = $true
} catch { }

Describe 'New-AuthenticatedDirectoryEntry' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        Context 'Credential parameter binding' {
            It 'should pass the credential username to the DirectoryEntry constructor' -Tag 'Integration' -Skip:(-not $script:CanTestDirectoryEntry) {
                $securePass = ConvertTo-SecureString 'password' -AsPlainText -Force
                $script:Credential = [System.Management.Automation.PSCredential]::new('CONTOSO\admin', $securePass)

                $capturedArgs = $null
                Mock 'New-Object' -ParameterFilter { $TypeName -eq 'System.DirectoryServices.DirectoryEntry' } {
                    $capturedArgs = $ArgumentList
                    $null
                }

                New-AuthenticatedDirectoryEntry -Path 'LDAP://dc.contoso.com/DC=contoso,DC=com'
                $capturedArgs | Should -Contain 'CONTOSO\admin'
            }

            It 'should pass the specified path as the first argument to the DirectoryEntry constructor' -Tag 'Integration' -Skip:(-not $script:CanTestDirectoryEntry) {
                $securePass = ConvertTo-SecureString 'password' -AsPlainText -Force
                $script:Credential = [System.Management.Automation.PSCredential]::new('CONTOSO\admin', $securePass)

                $capturedArgs = $null
                Mock 'New-Object' -ParameterFilter { $TypeName -eq 'System.DirectoryServices.DirectoryEntry' } {
                    $capturedArgs = $ArgumentList
                    $null
                }

                $testPath = 'LDAP://dc.contoso.com/DC=contoso,DC=com'
                New-AuthenticatedDirectoryEntry -Path $testPath
                $capturedArgs[0] | Should -Be $testPath
            }
        }

        Context 'Different LDAP paths' {
            It 'should pass a GC:// path unchanged to the DirectoryEntry constructor' -Tag 'Integration' -Skip:(-not $script:CanTestDirectoryEntry) {
                $securePass = ConvertTo-SecureString 'password' -AsPlainText -Force
                $script:Credential = [System.Management.Automation.PSCredential]::new('CONTOSO\admin', $securePass)

                $capturedPath = $null
                Mock 'New-Object' -ParameterFilter { $TypeName -eq 'System.DirectoryServices.DirectoryEntry' } {
                    $capturedPath = $ArgumentList[0]
                    $null
                }

                $gcPath = 'GC://dc.contoso.com/DC=contoso,DC=com'
                New-AuthenticatedDirectoryEntry -Path $gcPath
                $capturedPath | Should -Be $gcPath
            }
        }
    }
}
