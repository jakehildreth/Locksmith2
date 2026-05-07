BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests' 'Shared' 'TestHelpers.psm1') -Force -ErrorAction Stop
}

# ─────────────────────────────────────────────────────────────────────────────
#  Set-DangerousCACertificateManager
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-DangerousCACertificateManager' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Non-CA objects are skipped' {
            It 'should not process non-CA objects' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    CertificateManagers = @([PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr1' })
                }
                Mock Convert-IdentityReferenceToSid { }
                Mock Test-IsDangerousPrincipal { }
                $result = $template | Set-DangerousCACertificateManager
                Should -Invoke Convert-IdentityReferenceToSid -Times 0
            }
        }

        Context 'CertificateManagers is null or empty' {
            It 'should return object when CertificateManagers is null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = $null
                }
                $result = $ca | Set-DangerousCACertificateManager
                $result | Should -Not -BeNullOrEmpty
                $result.DangerousCACertificateManager | Should -BeNullOrEmpty
            }

            It 'should not set DangerousCACertificateManager when CertificateManagers is empty array' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @()
                }
                $result = $ca | Set-DangerousCACertificateManager
                $result.DangerousCACertificateManager | Should -BeNullOrEmpty
            }
        }

        Context 'Dangerous certificate manager found' {
            It 'should populate DangerousCACertificateManager array with SID' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @([PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr1' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-600' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $result = $ca | Set-DangerousCACertificateManager
                $result.DangerousCACertificateManager | Should -Contain 'S-1-5-21-1-2-3-600'
            }

            It 'should build DangerousCACertificateManagerNames from PrincipalStore' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @([PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr1' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-600' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $script:PrincipalStore['S-1-5-21-1-2-3-600'] = [PSCustomObject]@{ ntAccountName = 'CONTOSO\CertMgr1' }
                $result = $ca | Set-DangerousCACertificateManager
                $result.DangerousCACertificateManagerNames | Should -Contain 'CONTOSO\CertMgr1 (S-1-5-21-1-2-3-600)'
            }

            It 'should use (could not resolve) in names when SID not in PrincipalStore' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @([PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr1' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-600' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $result = $ca | Set-DangerousCACertificateManager
                $result.DangerousCACertificateManagerNames | Should -Contain 'S-1-5-21-1-2-3-600 (could not resolve)'
            }

            It 'should call Resolve-Principal for each dangerous manager' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @(
                        [PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr1' },
                        [PSCustomObject]@{ CertificateManager = 'CONTOSO\CertMgr2' }
                    )
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-600' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $null = $ca | Set-DangerousCACertificateManager
                Should -Invoke Resolve-Principal -Times 2 -Exactly
            }
        }

        Context 'Certificate manager is NOT dangerous' {
            It 'should not include SID when manager is not dangerous' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @([PSCustomObject]@{ CertificateManager = 'CONTOSO\SafeMgr' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-512' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $false }
                $result = $ca | Set-DangerousCACertificateManager
                $result.DangerousCACertificateManager | Should -BeNullOrEmpty
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  Set-LowPrivilegeCACertificateManager
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-LowPrivilegeCACertificateManager' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Low-privilege certificate manager found' {
            It 'should populate LowPrivilegeCACertificateManager array with SID' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @([PSCustomObject]@{ CertificateManager = 'BUILTIN\Users' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-32-545' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $true }
                Mock Resolve-Principal { }
                $result = $ca | Set-LowPrivilegeCACertificateManager
                $result.LowPrivilegeCACertificateManager | Should -Contain 'S-1-5-32-545'
            }

            It 'should build LowPrivilegeCACertificateManagerNames from PrincipalStore' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @([PSCustomObject]@{ CertificateManager = 'BUILTIN\Users' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-32-545' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $true }
                Mock Resolve-Principal { }
                $script:PrincipalStore['S-1-5-32-545'] = [PSCustomObject]@{ ntAccountName = 'BUILTIN\Users' }
                $result = $ca | Set-LowPrivilegeCACertificateManager
                $result.LowPrivilegeCACertificateManagerNames | Should -Contain 'BUILTIN\Users (S-1-5-32-545)'
            }
        }

        Context 'Certificate manager is NOT low-privilege' {
            It 'should not include SID when manager is not low-privilege' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @([PSCustomObject]@{ CertificateManager = 'CONTOSO\DomainAdmin' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-512' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $false }
                $result = $ca | Set-LowPrivilegeCACertificateManager
                $result.LowPrivilegeCACertificateManager | Should -BeNullOrEmpty
            }
        }

        Context 'No CertificateManagers set' {
            It 'should return object without error when CertificateManagers is empty' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass         = @('top', 'pKIEnrollmentService')
                    SchemaClassName     = 'pKIEnrollmentService'
                    CertificateManagers = @()
                }
                $result = $ca | Set-LowPrivilegeCACertificateManager
                $result | Should -Not -BeNullOrEmpty
                $result.LowPrivilegeCACertificateManager | Should -BeNullOrEmpty
            }
        }
    }
}