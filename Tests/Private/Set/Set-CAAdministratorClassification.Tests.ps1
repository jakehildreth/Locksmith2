BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

# ─────────────────────────────────────────────────────────────────────────────
#  Set-DangerousCAAdministrator
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-DangerousCAAdministrator' -Tag 'Unit' {
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
                    SchemaClassName  = 'pKICertificateTemplate'
                    CAAdministrators = @([PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin1' })
                }
                Mock Convert-IdentityReferenceToSid { }
                Mock Test-IsDangerousPrincipal { }
                $result = $template | Set-DangerousCAAdministrator
                Should -Invoke Convert-IdentityReferenceToSid -Times 0
            }
        }

        Context 'CAAdministrators is null or empty' {
            It 'should return object when CAAdministrators is null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = $null
                }
                $result = $ca | Set-DangerousCAAdministrator
                $result | Should -Not -BeNullOrEmpty
                $result.DangerousCAAdministrator | Should -BeNullOrEmpty
            }

            It 'should not set DangerousCAAdministrator when CAAdministrators is empty array' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = @()
                }
                $result = $ca | Set-DangerousCAAdministrator
                $result.DangerousCAAdministrator | Should -BeNullOrEmpty
            }
        }

        Context 'Dangerous CA administrator found' {
            It 'should populate DangerousCAAdministrator array with SID' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = @([PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin1' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-500' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $result = $ca | Set-DangerousCAAdministrator
                $result.DangerousCAAdministrator | Should -Contain 'S-1-5-21-1-2-3-500'
            }

            It 'should build DangerousCAAdministratorNames from PrincipalStore' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = @([PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin1' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-500' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $script:PrincipalStore['S-1-5-21-1-2-3-500'] = [PSCustomObject]@{ ntAccountName = 'CONTOSO\Admin1' }
                $result = $ca | Set-DangerousCAAdministrator
                $result.DangerousCAAdministratorNames | Should -Contain 'CONTOSO\Admin1 (S-1-5-21-1-2-3-500)'
            }

            It 'should use (could not resolve) in names when SID not in PrincipalStore' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = @([PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin1' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-500' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $result = $ca | Set-DangerousCAAdministrator
                $result.DangerousCAAdministratorNames | Should -Contain 'S-1-5-21-1-2-3-500 (could not resolve)'
            }

            It 'should call Resolve-Principal for each dangerous administrator' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = @(
                        [PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin1' },
                        [PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin2' }
                    )
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-500' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $null = $ca | Set-DangerousCAAdministrator
                Should -Invoke Resolve-Principal -Times 2 -Exactly
            }
        }

        Context 'Administrator is NOT dangerous' {
            It 'should not include SID when administrator is not dangerous' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = @([PSCustomObject]@{ CAAdministrator = 'CONTOSO\SafeAdmin' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-512' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $false }
                $result = $ca | Set-DangerousCAAdministrator
                $result.DangerousCAAdministrator | Should -BeNullOrEmpty
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  Set-LowPrivilegeCAAdministrator
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-LowPrivilegeCAAdministrator' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Low-privilege CA administrator found' {
            It 'should populate LowPrivilegeCAAdministrator array with SID' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = @([PSCustomObject]@{ CAAdministrator = 'BUILTIN\Users' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-32-545' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $true }
                Mock Resolve-Principal { }
                $result = $ca | Set-LowPrivilegeCAAdministrator
                $result.LowPrivilegeCAAdministrator | Should -Contain 'S-1-5-32-545'
            }
        }

        Context 'Administrator is NOT low-privilege' {
            It 'should not include SID when administrator is not low-privilege' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = @([PSCustomObject]@{ CAAdministrator = 'CONTOSO\DomainAdmin' })
                }
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-512' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $false }
                $result = $ca | Set-LowPrivilegeCAAdministrator
                $result.LowPrivilegeCAAdministrator | Should -BeNullOrEmpty
            }
        }

        Context 'No CAAdministrators set' {
            It 'should return object without error when CAAdministrators is empty' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass      = @('top', 'pKIEnrollmentService')
                    SchemaClassName  = 'pKIEnrollmentService'
                    CAAdministrators = @()
                }
                $result = $ca | Set-LowPrivilegeCAAdministrator
                $result | Should -Not -BeNullOrEmpty
                $result.LowPrivilegeCAAdministrator | Should -BeNullOrEmpty
            }
        }
    }
}