BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Set-CACertificateManager' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Object without CAFullName property' {
            It 'should skip and return object when CAFullName is null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = $null
                    cn              = 'MyCA'
                }
                Mock Get-PSCCertificateManager { }
                Mock Resolve-Principal { }
                $result = $ca | Set-CACertificateManager
                $result | Should -Not -BeNullOrEmpty
                Should -Invoke Get-PSCCertificateManager -Times 0
            }
        }

        Context 'Certificate Managers returned' {
            It 'should set CertificateManagers array from Get-PSCCertificateManager result' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockManagers = @(
                    [PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr1' },
                    [PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr2' }
                )
                Mock Get-PSCCertificateManager { $mockManagers }
                Mock Resolve-Principal { }
                $result = $ca | Set-CACertificateManager
                $result.CertificateManagers | Should -Not -BeNullOrEmpty
                $result.CertificateManagers.Count | Should -Be 2
            }

            It 'should call Resolve-Principal for each certificate manager' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockManagers = @(
                    [PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr1' },
                    [PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr2' }
                )
                Mock Get-PSCCertificateManager { $mockManagers }
                Mock Resolve-Principal { }
                $null = $ca | Set-CACertificateManager
                Should -Invoke Resolve-Principal -Times 2 -Exactly
            }
        }

        Context 'Get-PSCCertificateManager returns null or empty' {
            It 'should not set CertificateManagers when Get-PSCCertificateManager returns null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCCertificateManager { $null }
                Mock Resolve-Principal { }
                $result = $ca | Set-CACertificateManager
                $result | Should -Not -BeNullOrEmpty
                $result.CertificateManagers | Should -BeNullOrEmpty
            }
        }

        Context 'CAFullName is passed to Get-PSCCertificateManager' {
            It 'should call Get-PSCCertificateManager with the correct CAFullName' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCCertificateManager { @() } -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
                Mock Resolve-Principal { }
                $null = $ca | Set-CACertificateManager
                Should -Invoke Get-PSCCertificateManager -Times 1 -Exactly -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
            }
        }
    }
}