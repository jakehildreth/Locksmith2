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

Describe 'New-GCSearcher' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:Server = 'dc.contoso.com'
            $securePass = ConvertTo-SecureString 'password' -AsPlainText -Force
            $script:Credential = [System.Management.Automation.PSCredential]::new('CONTOSO\admin', $securePass)

            # Stub RootDSE with a rootDomainNamingContext property
            $fakeRootDSE = [PSCustomObject]@{}
            $fakeRootDSE | Add-Member -MemberType NoteProperty -Name 'rootDomainNamingContext' -Value (
                [PSCustomObject]@{ Value = 'DC=contoso,DC=com' }
            )
            $script:RootDSE = $fakeRootDSE

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

        Context 'No RootDSE available' {
            It 'should return $null when RootDSE is not set' {
                $script:RootDSE = $null
                $result = New-GCSearcher -Filter '(cn=*)' -PropertiesToLoad @('cn')
                $result | Should -BeNullOrEmpty
            }
        }

        Context 'Constructs GC path correctly' {
            It 'should build path as GC://server/rootDomainDN' {
                $script:capturedPath = $null
                Mock 'New-AuthenticatedDirectoryEntry' {
                    $script:capturedPath = $Path
                    $null
                }
                New-GCSearcher -Filter '(cn=*)' -PropertiesToLoad @('cn') | Out-Null
                $script:capturedPath | Should -Be 'GC://dc.contoso.com/DC=contoso,DC=com'
            }
        }

        Context 'Sets searcher properties' {
            It 'should set the Filter on the returned searcher' {
                $result = New-GCSearcher -Filter '(objectSid=S-1-5-21-1-2-3-1001)' -PropertiesToLoad @('objectSid')
                $result.Filter | Should -Be '(objectSid=S-1-5-21-1-2-3-1001)'
            }

            It 'should set PageSize to 1000' {
                $result = New-GCSearcher -Filter '(cn=*)' -PropertiesToLoad @('cn')
                $result.PageSize | Should -Be 1000
            }

            It 'should set SearchScope to Subtree' {
                $result = New-GCSearcher -Filter '(cn=*)' -PropertiesToLoad @('cn')
                $result.SearchScope | Should -Be ([System.DirectoryServices.SearchScope]::Subtree)
            }

            It 'should add the specified properties to PropertiesToLoad' {
                $result = New-GCSearcher -Filter '(cn=*)' -PropertiesToLoad @('distinguishedName', 'sAMAccountName')
                $result.PropertiesToLoad | Should -Contain 'distinguishedName'
                $result.PropertiesToLoad | Should -Contain 'sAMAccountName'
            }
        }
    }
}
