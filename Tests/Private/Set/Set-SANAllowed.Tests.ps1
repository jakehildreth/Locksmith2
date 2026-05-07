BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests' 'Shared' 'TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Set-SANAllowed' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Template filtering' {
            It 'should not process non-template objects (SchemaClassName is not pKICertificateTemplate)' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName   = 'pKIEnrollmentService'
                    CertificateNameFlag = 1
                }

                $result = $ca | Set-SANAllowed

                $result.SANAllowed | Should -BeNullOrEmpty
            }
        }

        Context 'CertificateNameFlag is null' {
            It 'should set SANAllowed=$false when CertificateNameFlag is null' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    CertificateNameFlag = $null
                }

                $result = $template | Set-SANAllowed

                $result.SANAllowed | Should -BeFalse
            }
        }

        Context 'Bit 1 not set' {
            It 'should set SANAllowed=$false when CertificateNameFlag is 0' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    CertificateNameFlag = 0
                }

                $result = $template | Set-SANAllowed

                $result.SANAllowed | Should -BeFalse
            }

            It 'should set SANAllowed=$false when CertificateNameFlag is 2 (bit 1 not set)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    CertificateNameFlag = 2
                }

                $result = $template | Set-SANAllowed

                $result.SANAllowed | Should -BeFalse
            }

            It 'should set SANAllowed=$false when CertificateNameFlag is 4 (bit 1 not set)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    CertificateNameFlag = 4
                }

                $result = $template | Set-SANAllowed

                $result.SANAllowed | Should -BeFalse
            }
        }

        Context 'Bit 1 set' {
            It 'should set SANAllowed=$true when CertificateNameFlag is 1 (only bit 1 set)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    CertificateNameFlag = 1
                }

                $result = $template | Set-SANAllowed

                $result.SANAllowed | Should -BeTrue
            }

            It 'should set SANAllowed=$true when CertificateNameFlag is 3 (bit 1 and bit 2 set)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    CertificateNameFlag = 3
                }

                $result = $template | Set-SANAllowed

                $result.SANAllowed | Should -BeTrue
            }

            It 'should set SANAllowed=$true when CertificateNameFlag is 0x00000001' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    CertificateNameFlag = 0x00000001
                }

                $result = $template | Set-SANAllowed

                $result.SANAllowed | Should -BeTrue
            }
        }

        Context 'Pipeline processing' {
            It 'should process multiple template objects in pipeline' {
                $templates = @(
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; CertificateNameFlag = 1 }),
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; CertificateNameFlag = 0 }),
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; CertificateNameFlag = 1 })
                )

                $results = $templates | Set-SANAllowed

                $results.Count | Should -Be 3
                $results[0].SANAllowed | Should -BeTrue
                $results[1].SANAllowed | Should -BeFalse
                $results[2].SANAllowed | Should -BeTrue
            }

            It 'should return the modified object in the pipeline' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName     = 'pKICertificateTemplate'
                    CertificateNameFlag = 1
                    name                = 'TestTemplate'
                }

                $result = $template | Set-SANAllowed

                $result | Should -Not -BeNullOrEmpty
                $result.name | Should -Be 'TestTemplate'
            }
        }
    }
}
