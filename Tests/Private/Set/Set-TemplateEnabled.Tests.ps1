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

Describe 'Set-TemplateEnabled' -Tag 'Unit' {
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
                    cn                   = 'MyCA'
                    certificateTemplates = @('WebServer')
                }
                $script:AdcsObjectStore['CA-Key'] = $ca

                $result = $ca | Set-TemplateEnabled

                $result.Enabled | Should -BeNullOrEmpty
            }
        }

        Context 'No CA objects in store' {
            It 'should set Enabled=$false when AdcsObjectStore has no CA objects' {
                # Store is empty (no CAs)
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    cn              = 'WebServer'
                }

                $result = $template | Set-TemplateEnabled

                $result.Enabled | Should -BeFalse
                $result.EnabledOn | Should -BeNullOrEmpty
            }
        }

        Context 'Template published on CA' {
            It 'should set Enabled=$true when CA certificateTemplates contains template CN' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass          = @('top', 'pKIEnrollmentService')
                    SchemaClassName      = 'pKIEnrollmentService'
                    cn                   = 'MyCA'
                    name                 = 'MyCA'
                    certificateTemplates = @('WebServer')
                }
                $script:AdcsObjectStore['CA-1'] = $ca

                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    cn              = 'WebServer'
                }

                $result = $template | Set-TemplateEnabled

                $result.Enabled | Should -BeTrue
            }

            It 'should populate EnabledOn with the CA name where template is published' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass          = @('top', 'pKIEnrollmentService')
                    SchemaClassName      = 'pKIEnrollmentService'
                    cn                   = 'MyCA'
                    name                 = 'MyCA'
                    certificateTemplates = @('WebServer')
                }
                $script:AdcsObjectStore['CA-1'] = $ca

                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    cn              = 'WebServer'
                }

                $result = $template | Set-TemplateEnabled

                $result.EnabledOn | Should -Contain 'MyCA'
            }
        }

        Context 'Template not published on any CA' {
            It 'should set Enabled=$false when CA exists but template CN not in its certificateTemplates' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName      = 'pKIEnrollmentService'
                    cn                   = 'MyCA'
                    name                 = 'MyCA'
                    certificateTemplates = @('User', 'Computer')
                }
                $script:AdcsObjectStore['CA-1'] = $ca

                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    cn              = 'WebServer'
                }

                $result = $template | Set-TemplateEnabled

                $result.Enabled | Should -BeFalse
                $result.EnabledOn | Should -BeNullOrEmpty
            }
        }

        Context 'Multiple CAs' {
            It 'should populate EnabledOn with all CA names that publish the template' {
                $ca1 = New-MockLS2AdcsObject -Properties @{
                    objectClass          = @('top', 'pKIEnrollmentService')
                    SchemaClassName      = 'pKIEnrollmentService'
                    cn                   = 'CA1'
                    name                 = 'CA1'
                    certificateTemplates = @('WebServer', 'User')
                }
                $ca2 = New-MockLS2AdcsObject -Properties @{
                    objectClass          = @('top', 'pKIEnrollmentService')
                    SchemaClassName      = 'pKIEnrollmentService'
                    cn                   = 'CA2'
                    name                 = 'CA2'
                    certificateTemplates = @('WebServer', 'Computer')
                }
                $script:AdcsObjectStore['CA-1'] = $ca1
                $script:AdcsObjectStore['CA-2'] = $ca2

                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    cn              = 'WebServer'
                }

                $result = $template | Set-TemplateEnabled

                $result.Enabled | Should -BeTrue
                $result.EnabledOn.Count | Should -Be 2
                $result.EnabledOn | Should -Contain 'CA1'
                $result.EnabledOn | Should -Contain 'CA2'
            }

            It 'should only include CAs that publish the template in EnabledOn' {
                $ca1 = New-MockLS2AdcsObject -Properties @{
                    objectClass          = @('top', 'pKIEnrollmentService')
                    SchemaClassName      = 'pKIEnrollmentService'
                    cn                   = 'CA1'
                    name                 = 'CA1'
                    certificateTemplates = @('WebServer')
                }
                $ca2 = New-MockLS2AdcsObject -Properties @{
                    objectClass          = @('top', 'pKIEnrollmentService')
                    SchemaClassName      = 'pKIEnrollmentService'
                    cn                   = 'CA2'
                    name                 = 'CA2'
                    certificateTemplates = @('User')  # does not publish WebServer
                }
                $script:AdcsObjectStore['CA-1'] = $ca1
                $script:AdcsObjectStore['CA-2'] = $ca2

                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    cn              = 'WebServer'
                }

                $result = $template | Set-TemplateEnabled

                $result.Enabled | Should -BeTrue
                $result.EnabledOn | Should -Contain 'CA1'
                $result.EnabledOn | Should -Not -Contain 'CA2'
            }
        }
    }
}
