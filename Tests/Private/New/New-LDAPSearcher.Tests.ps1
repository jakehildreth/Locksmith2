#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

Describe 'New-LDAPSearcher' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:Server = 'dc.contoso.com'
            $securePass = ConvertTo-SecureString 'password' -AsPlainText -Force
            $script:Credential = [System.Management.Automation.PSCredential]::new('CONTOSO\admin', $securePass)

            # Return a fake searcher object to avoid live .NET DirectorySearcher calls
            $script:FakeSearcher = [PSCustomObject]@{
                SearchRoot       = $null
                Filter           = ''
                SearchScope      = $null
                PageSize         = 0
                PropertiesToLoad = [System.Collections.ArrayList]::new()
            }
            Mock 'New-Object' -ParameterFilter { $TypeName -eq 'System.DirectoryServices.DirectorySearcher' } {
                $script:FakeSearcher
            }
            Mock 'New-AuthenticatedDirectoryEntry' { $null }
        }

        Context 'Constructs LDAP path correctly' {
            It 'should build path as LDAP://server/domainDN' {
                $script:capturedPath = $null
                Mock 'New-AuthenticatedDirectoryEntry' {
                    $script:capturedPath = $Path
                    $null
                }
                New-LDAPSearcher -DomainDN 'DC=contoso,DC=com' -Filter '(cn=*)' -PropertiesToLoad @('cn') | Out-Null
                $script:capturedPath | Should -Be 'LDAP://dc.contoso.com/DC=contoso,DC=com'
            }
        }

        Context 'Sets searcher properties' {
            It 'should set the Filter on the returned searcher' {
                $result = New-LDAPSearcher -DomainDN 'DC=contoso,DC=com' -Filter '(objectClass=user)' -PropertiesToLoad @('cn')
                $result.Filter | Should -Be '(objectClass=user)'
            }

            It 'should set PageSize to 1000' {
                $result = New-LDAPSearcher -DomainDN 'DC=contoso,DC=com' -Filter '(cn=*)' -PropertiesToLoad @('cn')
                $result.PageSize | Should -Be 1000
            }

            It 'should set SearchScope to Subtree' {
                $result = New-LDAPSearcher -DomainDN 'DC=contoso,DC=com' -Filter '(cn=*)' -PropertiesToLoad @('cn')
                $result.SearchScope | Should -Be ([System.DirectoryServices.SearchScope]::Subtree)
            }

            It 'should add the specified properties to PropertiesToLoad' {
                $result = New-LDAPSearcher -DomainDN 'DC=contoso,DC=com' -Filter '(cn=*)' -PropertiesToLoad @('cn', 'sAMAccountName')
                $result.PropertiesToLoad | Should -Contain 'cn'
                $result.PropertiesToLoad | Should -Contain 'sAMAccountName'
            }
        }

        Context 'Return value' {
            It 'should return the searcher object' {
                $result = New-LDAPSearcher -DomainDN 'DC=contoso,DC=com' -Filter '(cn=*)' -PropertiesToLoad @('cn')
                $result | Should -Not -BeNullOrEmpty
            }
        }
    }
}
