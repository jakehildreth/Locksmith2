BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Set-CAComputerPrincipal' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Non-CA objects' {
            It 'should not process non-CA objects' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    dNSHostName     = 'ca.contoso.com'
                }
                Mock New-GCSearcher { }
                Mock Resolve-Principal { }
                $result = $template | Set-CAComputerPrincipal
                Should -Invoke New-GCSearcher -Times 0
            }
        }

        Context 'CA without dNSHostName' {
            It 'should set ComputerPrincipal=$null when dNSHostName is null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    dNSHostName     = $null
                    cn              = 'MyCA'
                }
                Mock New-GCSearcher { }
                Mock Resolve-Principal { }
                $result = $ca | Set-CAComputerPrincipal
                $result.ComputerPrincipal | Should -BeNullOrEmpty
                Should -Invoke New-GCSearcher -Times 0
            }
        }

        Context 'Computer object found in GC' {
            It 'should set ComputerPrincipal to computer SID when GC search returns a result' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    dNSHostName     = 'ca.contoso.com'
                    cn              = 'MyCA'
                }
                $testSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1000')
                $sidBytes = New-Object byte[] 28
                $testSid.GetBinaryForm($sidBytes, 0)
                $mockResult = [PSCustomObject]@{
                    Properties = @{
                        distinguishedname = @('CN=CA$,OU=Computers,DC=contoso,DC=com')
                        objectsid         = @(, $sidBytes)
                        samaccountname    = @('CA$')
                    }
                }
                $mockSearcher = [PSCustomObject]@{}
                $mockSearcher | Add-Member -MemberType ScriptMethod -Name FindOne -Value { $mockResult }
                $mockSearcher | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
                Mock New-GCSearcher { $mockSearcher }
                Mock Resolve-Principal { }
                $result = $ca | Set-CAComputerPrincipal
                $result.ComputerPrincipal | Should -Be 'S-1-5-21-1-2-3-1000'
            }

            It 'should call Resolve-Principal with the computer SID' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    dNSHostName     = 'ca.contoso.com'
                    cn              = 'MyCA'
                }
                $testSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1000')
                $sidBytes = New-Object byte[] 28
                $testSid.GetBinaryForm($sidBytes, 0)
                $mockResult = [PSCustomObject]@{
                    Properties = @{
                        distinguishedname = @('CN=CA$,OU=Computers,DC=contoso,DC=com')
                        objectsid         = @(, $sidBytes)
                        samaccountname    = @('CA$')
                    }
                }
                $mockSearcher = [PSCustomObject]@{}
                $mockSearcher | Add-Member -MemberType ScriptMethod -Name FindOne -Value { $mockResult }
                $mockSearcher | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
                Mock New-GCSearcher { $mockSearcher }
                Mock Resolve-Principal { }
                $null = $ca | Set-CAComputerPrincipal
                Should -Invoke Resolve-Principal -Times 1 -Exactly
            }
        }

        Context 'Computer object NOT found in GC' {
            It 'should set ComputerPrincipal=$null when GC search returns no result' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    dNSHostName     = 'ca.contoso.com'
                    cn              = 'MyCA'
                }
                $mockSearcher = [PSCustomObject]@{}
                $mockSearcher | Add-Member -MemberType ScriptMethod -Name FindOne -Value { $null }
                $mockSearcher | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
                Mock New-GCSearcher { $mockSearcher }
                Mock Resolve-Principal { }
                $result = $ca | Set-CAComputerPrincipal
                $result.ComputerPrincipal | Should -BeNullOrEmpty
            }
        }

        Context 'New-GCSearcher returns null' {
            It 'should set ComputerPrincipal=$null when GC searcher cannot be created' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    dNSHostName     = 'ca.contoso.com'
                    cn              = 'MyCA'
                }
                Mock New-GCSearcher { $null }
                Mock Resolve-Principal { }
                $result = $ca | Set-CAComputerPrincipal
                $result.ComputerPrincipal | Should -BeNullOrEmpty
            }
        }
    }
}
