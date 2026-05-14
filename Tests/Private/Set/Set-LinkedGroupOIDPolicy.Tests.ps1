#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {
    Describe 'Set-LinkedGroupOIDPolicy' -Tag 'Unit' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'No OID objects in store' {
            It 'should set HasLinkedGroupOIDPolicy to $false when store has no OID objects' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName  = 'pKICertificateTemplate'
                    CertificatePolicy = @('1.3.6.1.4.1.311.21.8.1234567.7654321.1111111.2222222.3333333.1.4444444.5555555')
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.HasLinkedGroupOIDPolicy | Should -BeFalse
            }

            It 'should set LinkedGroupOIDPolicies to empty when store has no OID objects' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @('1.3.6.1.4.1.311.21.8.1234567.7654321.1111111.2222222.3333333.1.4444444.5555555')
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.LinkedGroupOIDPolicies | Should -BeNullOrEmpty
            }
        }

        Context 'OID object in store without group link' {
            BeforeEach {
                $oidObject = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'msPKI-Enterprise-Oid'
                    CertTemplateOID = '1.3.6.1.4.1.311.21.8.1234567.7654321.1111111.2222222.3333333.1.4444444.5555555'
                    OIDToGroupLink  = $null
                }
                $script:AdcsObjectStore['OID-1'] = $oidObject
            }

            It 'should set HasLinkedGroupOIDPolicy to $false when matching OID has no group link' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @('1.3.6.1.4.1.311.21.8.1234567.7654321.1111111.2222222.3333333.1.4444444.5555555')
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.HasLinkedGroupOIDPolicy | Should -BeFalse
            }

            It 'should set LinkedGroupOIDPolicies to empty when matching OID has no group link' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @('1.3.6.1.4.1.311.21.8.1234567.7654321.1111111.2222222.3333333.1.4444444.5555555')
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.LinkedGroupOIDPolicies | Should -BeNullOrEmpty
            }
        }

        Context 'OID object in store with group link and matching template policy' {
            BeforeEach {
                $oidObject = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'msPKI-Enterprise-Oid'
                    CertTemplateOID = '1.3.6.1.4.1.311.21.8.1234567.7654321.1111111.2222222.3333333.1.4444444.5555555'
                    OIDToGroupLink  = 'CN=PrivilegedGroup,CN=Users,DC=contoso,DC=com'
                }
                $script:AdcsObjectStore['OID-1'] = $oidObject
            }

            It 'should set HasLinkedGroupOIDPolicy to $true when template policy OID matches a group-linked OID' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @('1.3.6.1.4.1.311.21.8.1234567.7654321.1111111.2222222.3333333.1.4444444.5555555')
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.HasLinkedGroupOIDPolicy | Should -BeTrue
            }

            It 'should populate LinkedGroupOIDPolicies with the linked group DN' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @('1.3.6.1.4.1.311.21.8.1234567.7654321.1111111.2222222.3333333.1.4444444.5555555')
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.LinkedGroupOIDPolicies | Should -Contain 'CN=PrivilegedGroup,CN=Users,DC=contoso,DC=com'
            }

            It 'should pass the template object through the pipeline' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @('1.3.6.1.4.1.311.21.8.1234567.7654321.1111111.2222222.3333333.1.4444444.5555555')
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result | Should -Not -BeNullOrEmpty
                $result.GetType().Name | Should -Be 'LS2AdcsObject'
            }
        }

        Context 'Multiple policy OIDs — only one linked' {
            BeforeEach {
                $oidObject = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'msPKI-Enterprise-Oid'
                    CertTemplateOID = '1.3.6.1.4.1.311.21.8.LINKED.OID'
                    OIDToGroupLink  = 'CN=LinkedGroup,CN=Users,DC=contoso,DC=com'
                }
                $script:AdcsObjectStore['OID-linked'] = $oidObject
            }

            It 'should only include the group DN for the OID that has a group link' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @(
                        '1.3.6.1.4.1.311.21.8.UNLINKED.OID'
                        '1.3.6.1.4.1.311.21.8.LINKED.OID'
                    )
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.LinkedGroupOIDPolicies.Count | Should -Be 1
                $result.LinkedGroupOIDPolicies | Should -Contain 'CN=LinkedGroup,CN=Users,DC=contoso,DC=com'
            }

            It 'should set HasLinkedGroupOIDPolicy to $true when at least one policy OID is linked' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @(
                        '1.3.6.1.4.1.311.21.8.UNLINKED.OID'
                        '1.3.6.1.4.1.311.21.8.LINKED.OID'
                    )
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.HasLinkedGroupOIDPolicy | Should -BeTrue
            }
        }

        Context 'Multiple policy OIDs — multiple linked to different groups' {
            BeforeEach {
                $oidObject1 = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'msPKI-Enterprise-Oid'
                    CertTemplateOID = '1.3.6.1.4.1.311.21.8.LINKED.OID.1'
                    OIDToGroupLink  = 'CN=GroupA,CN=Users,DC=contoso,DC=com'
                }
                $oidObject2 = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'msPKI-Enterprise-Oid'
                    CertTemplateOID = '1.3.6.1.4.1.311.21.8.LINKED.OID.2'
                    OIDToGroupLink  = 'CN=GroupB,CN=Users,DC=contoso,DC=com'
                }
                $script:AdcsObjectStore['OID-1'] = $oidObject1
                $script:AdcsObjectStore['OID-2'] = $oidObject2
            }

            It 'should include all linked group DNs when multiple policy OIDs link to groups' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @(
                        '1.3.6.1.4.1.311.21.8.LINKED.OID.1'
                        '1.3.6.1.4.1.311.21.8.LINKED.OID.2'
                    )
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.LinkedGroupOIDPolicies.Count | Should -Be 2
                $result.LinkedGroupOIDPolicies | Should -Contain 'CN=GroupA,CN=Users,DC=contoso,DC=com'
                $result.LinkedGroupOIDPolicies | Should -Contain 'CN=GroupB,CN=Users,DC=contoso,DC=com'
            }
        }

        Context 'Non-template objects piped in' {
            It 'should not set HasLinkedGroupOIDPolicy on a CA object' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    name            = 'MyCA'
                }

                $result = $ca | Set-LinkedGroupOIDPolicy

                $result.HasLinkedGroupOIDPolicy | Should -BeNullOrEmpty
            }

            It 'should pass non-template objects through the pipeline' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    name            = 'MyCA'
                }

                $result = $ca | Set-LinkedGroupOIDPolicy

                $result | Should -Not -BeNullOrEmpty
            }
        }

        Context 'Template with no CertificatePolicy' {
            It 'should set HasLinkedGroupOIDPolicy to $false when template has no policy OIDs' {
                $oidObject = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'msPKI-Enterprise-Oid'
                    CertTemplateOID = '1.3.6.1.4.1.311.21.8.SOME.OID'
                    OIDToGroupLink  = 'CN=SomeGroup,CN=Users,DC=contoso,DC=com'
                }
                $script:AdcsObjectStore['OID-1'] = $oidObject

                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKICertificateTemplate'
                    CertificatePolicy = @()
                }

                $result = $template | Set-LinkedGroupOIDPolicy

                $result.HasLinkedGroupOIDPolicy | Should -BeFalse
            }
        }
    }
}
