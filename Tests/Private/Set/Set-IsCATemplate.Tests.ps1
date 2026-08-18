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

Describe 'Set-IsCATemplate' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Non-template objects' {
            It 'should not set IsCATemplate on non-template objects' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                }

                $result = $ca | Set-IsCATemplate

                $result.IsCATemplate | Should -BeFalse
            }
        }

        Context 'CA-shaped templates' {
            It 'should set IsCATemplate=$true when pKIDefaultKeySpec is 2 (AT_SIGNATURE)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName    = 'pKICertificateTemplate'
                    cn                 = 'SubCA'
                    pKIDefaultKeySpec  = 2
                }

                $result = $template | Set-IsCATemplate

                $result.IsCATemplate | Should -BeTrue
            }
        }

        Context 'End-entity templates' {
            It 'should set IsCATemplate=$false when pKIDefaultKeySpec is 1 (AT_KEYEXCHANGE)' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName    = 'pKICertificateTemplate'
                    cn                 = 'WebServer'
                    pKIDefaultKeySpec  = 1
                }

                $result = $template | Set-IsCATemplate

                $result.IsCATemplate | Should -BeFalse
            }

            It 'should set IsCATemplate=$false when pKIDefaultKeySpec is null' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    cn              = 'WebServer'
                }

                $result = $template | Set-IsCATemplate

                $result.IsCATemplate | Should -BeFalse
            }
        }
    }
}
