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

# NOTE: Only Set-AuthorizedSignatureNotRequired exists in the source and is called by the
# Initialize-AdcsObjectStore pipeline. This file tests that function.
Describe 'Set-AuthorizedSignatureNotRequired' -Tag 'Unit' {
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
                    RASignature     = 0
                }

                $result = $ca | Set-AuthorizedSignatureNotRequired

                $result.AuthorizedSignatureNotRequired | Should -BeNullOrEmpty
            }
        }

        Context 'RASignature is null (vulnerable — no signature required)' {
            It 'should set AuthorizedSignatureNotRequired=$true when RASignature is null' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    RASignature     = $null
                }

                $result = $template | Set-AuthorizedSignatureNotRequired

                $result.AuthorizedSignatureNotRequired | Should -BeTrue
            }
        }

        Context 'RASignature is 0 (vulnerable — no signature required)' {
            It 'should set AuthorizedSignatureNotRequired=$true when RASignature is 0' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    RASignature     = 0
                }

                $result = $template | Set-AuthorizedSignatureNotRequired

                $result.AuthorizedSignatureNotRequired | Should -BeTrue
            }
        }

        Context 'RASignature >= 1 (not vulnerable — signature required)' {
            It 'should set AuthorizedSignatureNotRequired=$false when RASignature is 1' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    RASignature     = 1
                }

                $result = $template | Set-AuthorizedSignatureNotRequired

                $result.AuthorizedSignatureNotRequired | Should -BeFalse
            }

            It 'should set AuthorizedSignatureNotRequired=$false when RASignature is 2' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    RASignature     = 2
                }

                $result = $template | Set-AuthorizedSignatureNotRequired

                $result.AuthorizedSignatureNotRequired | Should -BeFalse
            }
        }

        Context 'Pipeline processing' {
            It 'should process multiple templates and return all' {
                $templates = @(
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; RASignature = $null }),
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; RASignature = 0 }),
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; RASignature = 1 })
                )

                $results = $templates | Set-AuthorizedSignatureNotRequired

                $results.Count | Should -Be 3
                $results[0].AuthorizedSignatureNotRequired | Should -BeTrue
                $results[1].AuthorizedSignatureNotRequired | Should -BeTrue
                $results[2].AuthorizedSignatureNotRequired | Should -BeFalse
            }
        }
    }
}
