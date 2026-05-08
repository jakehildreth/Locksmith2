BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Set-CADisableExtensionList' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Object without CAFullName property' {
            It 'should skip and return object when CAFullName is null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = $null
                    cn              = 'MyCA'
                }
                Mock Get-PSCDisableExtensionList { }
                $result = $ca | Set-CADisableExtensionList
                $result | Should -Not -BeNullOrEmpty
                Should -Invoke Get-PSCDisableExtensionList -Times 0
            }
        }

        Context 'No extensions disabled' {
            It 'should set DisableExtensionList to empty when no extensions returned' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCDisableExtensionList { @() }
                $result = $ca | Set-CADisableExtensionList
                $result.DisableExtensionList | Should -BeNullOrEmpty
                $result.SecurityExtensionDisabled | Should -BeFalse
            }
        }

        Context 'Extensions disabled but security extension is NOT in list' {
            It 'should set SecurityExtensionDisabled=$false when security OID not in list' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockList = @([PSCustomObject]@{ DisabledExtension = '1.3.6.1.5.5.7.48.1' })
                Mock Get-PSCDisableExtensionList { $mockList }
                $result = $ca | Set-CADisableExtensionList
                $result.SecurityExtensionDisabled | Should -BeFalse
                $result.DisableExtensionList | Should -Contain '1.3.6.1.5.5.7.48.1'
            }
        }

        Context 'Security extension (1.3.6.1.4.1.311.25.2) is disabled' {
            It 'should set SecurityExtensionDisabled=$true when security OID is in disable list' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockList = @([PSCustomObject]@{ DisabledExtension = '1.3.6.1.4.1.311.25.2' })
                Mock Get-PSCDisableExtensionList { $mockList }
                $result = $ca | Set-CADisableExtensionList
                $result.SecurityExtensionDisabled | Should -BeTrue
            }

            It 'should populate DisableExtensionList with multiple OIDs' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockList = @(
                    [PSCustomObject]@{ DisabledExtension = '1.3.6.1.4.1.311.25.2' },
                    [PSCustomObject]@{ DisabledExtension = '1.3.6.1.5.5.7.48.1' }
                )
                Mock Get-PSCDisableExtensionList { $mockList }
                $result = $ca | Set-CADisableExtensionList
                $result.SecurityExtensionDisabled | Should -BeTrue
                $result.DisableExtensionList | Should -Contain '1.3.6.1.4.1.311.25.2'
                $result.DisableExtensionList | Should -Contain '1.3.6.1.5.5.7.48.1'
            }
        }

        Context 'CAFullName is passed to Get-PSCDisableExtensionList' {
            It 'should call Get-PSCDisableExtensionList with the correct CAFullName' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCDisableExtensionList { @() } -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
                $null = $ca | Set-CADisableExtensionList
                Should -Invoke Get-PSCDisableExtensionList -Times 1 -Exactly -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
            }
        }
    }
}