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

# NOTE: Only Set-ManagerApprovalNotRequired exists in the source and is called by the
# Initialize-AdcsObjectStore pipeline. This file tests that function.
Describe 'Set-ManagerApprovalNotRequired' -Tag 'Unit' {
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
                    SchemaClassName = 'pKIEnrollmentService'
                    EnrollmentFlag  = 0
                }

                $result = $ca | Set-ManagerApprovalNotRequired

                $result.ManagerApprovalNotRequired | Should -BeNullOrEmpty
            }
        }

        Context 'EnrollmentFlag is null (vulnerable — no approval required)' {
            It 'should set ManagerApprovalNotRequired=$true when EnrollmentFlag is null' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = $null
                }

                $result = $template | Set-ManagerApprovalNotRequired

                $result.ManagerApprovalNotRequired | Should -BeTrue
            }
        }

        Context 'CT_FLAG_PEND_ALL_REQUESTS bit (0x00000002) not set (vulnerable)' {
            It 'should set ManagerApprovalNotRequired=$true when EnrollmentFlag is 0' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 0
                }

                $result = $template | Set-ManagerApprovalNotRequired

                $result.ManagerApprovalNotRequired | Should -BeTrue
            }

            It 'should set ManagerApprovalNotRequired=$true when EnrollmentFlag has bit 2 NOT set (value=1)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 1  # bit 1 set, bit 2 not set
                }

                $result = $template | Set-ManagerApprovalNotRequired

                $result.ManagerApprovalNotRequired | Should -BeTrue
            }

            It 'should set ManagerApprovalNotRequired=$true when EnrollmentFlag has 0x80000 but not bit 2' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 0x80000
                }

                $result = $template | Set-ManagerApprovalNotRequired

                $result.ManagerApprovalNotRequired | Should -BeTrue
            }
        }

        Context 'CT_FLAG_PEND_ALL_REQUESTS bit set (not vulnerable — approval required)' {
            It 'should set ManagerApprovalNotRequired=$false when EnrollmentFlag has bit 2 set (value=2)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 2
                }

                $result = $template | Set-ManagerApprovalNotRequired

                $result.ManagerApprovalNotRequired | Should -BeFalse
            }

            It 'should set ManagerApprovalNotRequired=$false when EnrollmentFlag is 3 (bit 2 set along with bit 1)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 3
                }

                $result = $template | Set-ManagerApprovalNotRequired

                $result.ManagerApprovalNotRequired | Should -BeFalse
            }
        }

        Context 'Pipeline processing' {
            It 'should process multiple templates and return all' {
                $templates = @(
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; EnrollmentFlag = $null }),
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; EnrollmentFlag = 0 }),
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; EnrollmentFlag = 2 })
                )

                $results = $templates | Set-ManagerApprovalNotRequired

                $results.Count | Should -Be 3
                $results[0].ManagerApprovalNotRequired | Should -BeTrue
                $results[1].ManagerApprovalNotRequired | Should -BeTrue
                $results[2].ManagerApprovalNotRequired | Should -BeFalse
            }
        }
    }
}
