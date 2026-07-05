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

Describe 'Set-NoSecurityExtension' -Tag 'Unit' {
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
                    EnrollmentFlag  = 0x80000
                }

                $result = $ca | Set-NoSecurityExtension

                $result.NoSecurityExtension | Should -BeNullOrEmpty
            }
        }

        Context 'EnrollmentFlag is null' {
            It 'should set NoSecurityExtension=$false when EnrollmentFlag is null' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = $null
                }

                $result = $template | Set-NoSecurityExtension

                $result.NoSecurityExtension | Should -BeFalse
            }
        }

        Context 'CT_FLAG_NO_SECURITY_EXTENSION bit not set' {
            It 'should set NoSecurityExtension=$false when EnrollmentFlag is 0' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 0
                }

                $result = $template | Set-NoSecurityExtension

                $result.NoSecurityExtension | Should -BeFalse
            }

            It 'should set NoSecurityExtension=$false when EnrollmentFlag is 2 (bit 0x80000 not set)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 2
                }

                $result = $template | Set-NoSecurityExtension

                $result.NoSecurityExtension | Should -BeFalse
            }
        }

        Context 'CT_FLAG_NO_SECURITY_EXTENSION bit set (0x80000)' {
            It 'should set NoSecurityExtension=$true when EnrollmentFlag is exactly 0x80000' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 0x80000
                }

                $result = $template | Set-NoSecurityExtension

                $result.NoSecurityExtension | Should -BeTrue
            }

            It 'should set NoSecurityExtension=$true when EnrollmentFlag has 0x80000 plus other bits' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 0x80002  # 0x80000 | 2
                }

                $result = $template | Set-NoSecurityExtension

                $result.NoSecurityExtension | Should -BeTrue
            }

            It 'should set NoSecurityExtension=$true when EnrollmentFlag is 524288 (decimal of 0x80000)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    EnrollmentFlag  = 524288
                }

                $result = $template | Set-NoSecurityExtension

                $result.NoSecurityExtension | Should -BeTrue
            }
        }

        Context 'Pipeline processing' {
            It 'should process multiple template objects and return all' {
                $templates = @(
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; EnrollmentFlag = 0x80000 }),
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; EnrollmentFlag = 0 })
                )

                $results = $templates | Set-NoSecurityExtension

                $results.Count | Should -Be 2
                $results[0].NoSecurityExtension | Should -BeTrue
                $results[1].NoSecurityExtension | Should -BeFalse
            }
        }
    }
}
