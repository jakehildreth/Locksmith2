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
#  Set-AnyPurposeEKUExist
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-AnyPurposeEKUExist' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Non-template objects' {
            It 'should not process non-template objects' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName      = 'pKIEnrollmentService'
                    pKIExtendedKeyUsage  = @('2.5.29.37.0')
                }

                $result = $ca | Set-AnyPurposeEKUExist

                $result.AnyPurposeEKUExist | Should -BeNullOrEmpty
            }
        }

        Context 'Empty EKU list' {
            It 'should set AnyPurposeEKUExist=$true when pKIExtendedKeyUsage is null' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = $null
                }

                $result = $template | Set-AnyPurposeEKUExist

                $result.AnyPurposeEKUExist | Should -BeTrue
            }

            It 'should set AnyPurposeEKUExist=$true when pKIExtendedKeyUsage is empty array' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @()
                }

                $result = $template | Set-AnyPurposeEKUExist

                $result.AnyPurposeEKUExist | Should -BeTrue
            }
        }

        Context 'Any Purpose OID present' {
            It 'should set AnyPurposeEKUExist=$true when pKIExtendedKeyUsage contains 2.5.29.37.0' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('2.5.29.37.0')
                }

                $result = $template | Set-AnyPurposeEKUExist

                $result.AnyPurposeEKUExist | Should -BeTrue
            }

            It 'should set AnyPurposeEKUExist=$true when 2.5.29.37.0 is mixed with other OIDs' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2', '2.5.29.37.0')
                }

                $result = $template | Set-AnyPurposeEKUExist

                $result.AnyPurposeEKUExist | Should -BeTrue
            }
        }

        Context 'Any Purpose OID not present' {
            It 'should set AnyPurposeEKUExist=$false when pKIExtendedKeyUsage has only non-any-purpose OIDs' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2')
                }

                $result = $template | Set-AnyPurposeEKUExist

                $result.AnyPurposeEKUExist | Should -BeFalse
            }
        }

        Context 'Custom AnyPurposeEKU parameter' {
            It 'should detect custom OID when $AnyPurposeEKU parameter is provided' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.2.3.4.5')
                }

                $result = Set-AnyPurposeEKUExist -AdcsObject $template -AnyPurposeEKU @('1.2.3.4.5')

                $result.AnyPurposeEKUExist | Should -BeTrue
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  Set-AuthenticationEKUExist
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-AuthenticationEKUExist' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Non-template objects' {
            It 'should not process non-template objects' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKIEnrollmentService'
                    pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
                }

                $result = $ca | Set-AuthenticationEKUExist

                $result.AuthenticationEKUExist | Should -BeNullOrEmpty
            }
        }

        Context 'Empty EKU list' {
            It 'should set AuthenticationEKUExist=$false when pKIExtendedKeyUsage is null' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = $null
                }

                $result = $template | Set-AuthenticationEKUExist

                $result.AuthenticationEKUExist | Should -BeFalse
            }

            It 'should set AuthenticationEKUExist=$false when pKIExtendedKeyUsage is empty array' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @()
                }

                $result = $template | Set-AuthenticationEKUExist

                $result.AuthenticationEKUExist | Should -BeFalse
            }
        }

        Context 'Authentication OIDs' {
            It 'should set AuthenticationEKUExist=$true when pKIExtendedKeyUsage contains Client Authentication OID' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')
                }

                $result = $template | Set-AuthenticationEKUExist

                $result.AuthenticationEKUExist | Should -BeTrue
            }

            It 'should set AuthenticationEKUExist=$true when pKIExtendedKeyUsage contains PKINIT OID' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.5.2.3.4')
                }

                $result = $template | Set-AuthenticationEKUExist

                $result.AuthenticationEKUExist | Should -BeTrue
            }

            It 'should set AuthenticationEKUExist=$true when pKIExtendedKeyUsage contains Smart Card Logon OID' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.4.1.311.20.2.2')
                }

                $result = $template | Set-AuthenticationEKUExist

                $result.AuthenticationEKUExist | Should -BeTrue
            }

            It 'should set AuthenticationEKUExist=$false when pKIExtendedKeyUsage has only non-auth OIDs' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.4.1.311.20.2.1', '1.3.6.1.5.5.7.3.4')
                }

                $result = $template | Set-AuthenticationEKUExist

                $result.AuthenticationEKUExist | Should -BeFalse
            }
        }

        Context 'Custom AuthenticationEKU parameter' {
            It 'should detect custom auth OID when $AuthenticationEKU parameter is provided' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('9.9.9.9.9')
                }

                $result = Set-AuthenticationEKUExist -AdcsObject $template -AuthenticationEKU @('9.9.9.9.9')

                $result.AuthenticationEKUExist | Should -BeTrue
            }

            It 'should use only custom OIDs when $AuthenticationEKU parameter is provided' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2')  # default Client Auth OID
                }

                # Override with a different OID — default should NOT match
                $result = Set-AuthenticationEKUExist -AdcsObject $template -AuthenticationEKU @('9.9.9.9.9')

                $result.AuthenticationEKUExist | Should -BeFalse
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  Set-EnrollmentAgentEKUExist
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-EnrollmentAgentEKUExist' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Non-template objects' {
            It 'should not process non-template objects' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKIEnrollmentService'
                    pKIExtendedKeyUsage = @('1.3.6.1.4.1.311.20.2.1')
                }

                $result = $ca | Set-EnrollmentAgentEKUExist

                $result.EnrollmentAgentEKUExist | Should -BeNullOrEmpty
            }
        }

        Context 'Enrollment Agent OID present' {
            It 'should set EnrollmentAgentEKUExist=$true when Certificate Request Agent OID is present' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.4.1.311.20.2.1')
                }

                $result = $template | Set-EnrollmentAgentEKUExist

                $result.EnrollmentAgentEKUExist | Should -BeTrue
            }

            It 'should set EnrollmentAgentEKUExist=$true when EA OID is mixed with other OIDs' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.1')
                }

                $result = $template | Set-EnrollmentAgentEKUExist

                $result.EnrollmentAgentEKUExist | Should -BeTrue
            }
        }

        Context 'Enrollment Agent OID not present' {
            It 'should set EnrollmentAgentEKUExist=$false when EKU list does not contain EA OID' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2')
                }

                $result = $template | Set-EnrollmentAgentEKUExist

                $result.EnrollmentAgentEKUExist | Should -BeFalse
            }

            It 'should set EnrollmentAgentEKUExist=$false when pKIExtendedKeyUsage is empty' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @()
                }

                $result = $template | Set-EnrollmentAgentEKUExist

                $result.EnrollmentAgentEKUExist | Should -BeFalse
            }
        }

        Context 'Custom EnrollmentAgentEKU parameter' {
            It 'should detect custom OID when $EnrollmentAgentEKU parameter is provided' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    pKIExtendedKeyUsage = @('8.8.8.8.8')
                }

                $result = Set-EnrollmentAgentEKUExist -AdcsObject $template -EnrollmentAgentEKU @('8.8.8.8.8')

                $result.EnrollmentAgentEKUExist | Should -BeTrue
            }
        }
    }
}
