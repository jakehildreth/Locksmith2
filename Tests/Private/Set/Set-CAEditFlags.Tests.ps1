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

Describe 'Set-CAEditFlags' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'EDITF_ATTRIBUTESUBJECTALTNAME2 flag is ENABLED (SAN flag enabled)' {
            It 'should set SANFlagEnabled=$true when EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockFlags = @([PSCustomObject]@{ EditFlag = 'EDITF_ATTRIBUTESUBJECTALTNAME2'; Enabled = $true })
                Mock Get-PSCEditFlag { $mockFlags }
                $result = $ca | Set-CAEditFlags
                $result.SANFlagEnabled | Should -BeTrue
            }

            It 'should set EditFlags array from Get-PSCEditFlag result' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockFlags = @([PSCustomObject]@{ EditFlag = 'EDITF_ATTRIBUTESUBJECTALTNAME2'; Enabled = $true })
                Mock Get-PSCEditFlag { $mockFlags }
                $result = $ca | Set-CAEditFlags
                $result.EditFlags | Should -Not -BeNullOrEmpty
            }
        }

        Context 'EDITF_ATTRIBUTESUBJECTALTNAME2 flag is DISABLED (SAN flag not enabled)' {
            It 'should set SANFlagEnabled=$false when EDITF_ATTRIBUTESUBJECTALTNAME2 is disabled' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockFlags = @([PSCustomObject]@{ EditFlag = 'EDITF_ATTRIBUTESUBJECTALTNAME2'; Enabled = $false })
                Mock Get-PSCEditFlag { $mockFlags }
                $result = $ca | Set-CAEditFlags
                $result.SANFlagEnabled | Should -BeFalse
            }
        }

        Context 'EDITF_ATTRIBUTESUBJECTALTNAME2 flag not in result list' {
            It 'should set SANFlagEnabled=$false when EDITF_ATTRIBUTESUBJECTALTNAME2 is absent from results' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockFlags = @([PSCustomObject]@{ EditFlag = 'EDITF_SOME_OTHER_FLAG'; Enabled = $true })
                Mock Get-PSCEditFlag { $mockFlags }
                $result = $ca | Set-CAEditFlags
                $result.SANFlagEnabled | Should -BeFalse
            }
        }

        Context 'Get-PSCEditFlag returns no results' {
            It 'should not set EditFlags when Get-PSCEditFlag returns null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCEditFlag { $null }
                $result = $ca | Set-CAEditFlags
                $result | Should -Not -BeNullOrEmpty
                $result.EditFlags | Should -BeNullOrEmpty
            }
        }

        Context 'CAFullName is passed to Get-PSCEditFlag' {
            It 'should call Get-PSCEditFlag with the correct CAFullName' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCEditFlag { @() } -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
                $null = $ca | Set-CAEditFlags
                Should -Invoke Get-PSCEditFlag -Times 1 -Exactly -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
            }
        }
    }
}
