BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests' 'Shared' 'TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Set-RequiresEnrollmentAgentSignature' -Tag 'Unit' {
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
                    SchemaClassName       = 'pKIEnrollmentService'
                    RASignature           = 1
                    RAApplicationPolicies = @('1.3.6.1.4.1.311.20.2.1')
                }

                $result = $ca | Set-RequiresEnrollmentAgentSignature

                $result.RequiresEnrollmentAgentSignature | Should -BeNullOrEmpty
            }
        }

        Context 'RASignature is null or missing' {
            It 'should set RequiresEnrollmentAgentSignature=$false when RASignature is null' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    RASignature     = $null
                }

                $result = $template | Set-RequiresEnrollmentAgentSignature

                $result.RequiresEnrollmentAgentSignature | Should -BeFalse
            }
        }

        Context 'RASignature is 0' {
            It 'should set RequiresEnrollmentAgentSignature=$false when RASignature is 0' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    RASignature     = 0
                }

                $result = $template | Set-RequiresEnrollmentAgentSignature

                $result.RequiresEnrollmentAgentSignature | Should -BeFalse
            }
        }

        Context 'RASignature is 1 but RAApplicationPolicies does not contain EA OID' {
            It 'should set RequiresEnrollmentAgentSignature=$false when RASignature=1 but RAApplicationPolicies is null' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName       = 'pKICertificateTemplate'
                    RASignature           = 1
                    RAApplicationPolicies = $null
                }

                $result = $template | Set-RequiresEnrollmentAgentSignature

                $result.RequiresEnrollmentAgentSignature | Should -BeFalse
            }

            It 'should set RequiresEnrollmentAgentSignature=$false when RASignature=1 but RAApplicationPolicies is empty' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName       = 'pKICertificateTemplate'
                    RASignature           = 1
                    RAApplicationPolicies = @()
                }

                $result = $template | Set-RequiresEnrollmentAgentSignature

                $result.RequiresEnrollmentAgentSignature | Should -BeFalse
            }

            It 'should set RequiresEnrollmentAgentSignature=$false when RASignature=1 but EA OID not in RAApplicationPolicies' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName       = 'pKICertificateTemplate'
                    RASignature           = 1
                    RAApplicationPolicies = @('1.3.6.1.5.5.7.3.2')  # Client Auth, not EA
                }

                $result = $template | Set-RequiresEnrollmentAgentSignature

                $result.RequiresEnrollmentAgentSignature | Should -BeFalse
            }
        }

        Context 'RASignature is 1 and RAApplicationPolicies contains EA OID' {
            It 'should set RequiresEnrollmentAgentSignature=$true when both conditions met' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName       = 'pKICertificateTemplate'
                    RASignature           = 1
                    RAApplicationPolicies = @('1.3.6.1.4.1.311.20.2.1')
                }

                $result = $template | Set-RequiresEnrollmentAgentSignature

                $result.RequiresEnrollmentAgentSignature | Should -BeTrue
            }

            It 'should set RequiresEnrollmentAgentSignature=$true when EA OID is mixed with other policies' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName       = 'pKICertificateTemplate'
                    RASignature           = 1
                    RAApplicationPolicies = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.1')
                }

                $result = $template | Set-RequiresEnrollmentAgentSignature

                $result.RequiresEnrollmentAgentSignature | Should -BeTrue
            }
        }

        Context 'Pipeline processing' {
            It 'should process multiple template objects correctly' {
                $templates = @(
                    (New-MockLS2AdcsObject -Properties @{
                        SchemaClassName       = 'pKICertificateTemplate'
                        RASignature           = 1
                        RAApplicationPolicies = @('1.3.6.1.4.1.311.20.2.1')
                    }),
                    (New-MockLS2AdcsObject -Properties @{
                        SchemaClassName = 'pKICertificateTemplate'
                        RASignature     = 0
                    })
                )

                $results = $templates | Set-RequiresEnrollmentAgentSignature

                $results.Count | Should -Be 2
                $results[0].RequiresEnrollmentAgentSignature | Should -BeTrue
                $results[1].RequiresEnrollmentAgentSignature | Should -BeFalse
            }
        }
    }
}
