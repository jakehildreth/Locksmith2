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

Describe 'Set-CAInterfaceFlags' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'IF_ENFORCEENCRYPTICERTREQUEST flag is PRESENT (RPC encryption required)' {
            It 'should set RPCEncryptionNotRequired=$false when IF_ENFORCEENCRYPTICERTREQUEST is enabled' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockFlags = @([PSCustomObject]@{ InterfaceFlag = 'IF_ENFORCEENCRYPTICERTREQUEST'; Enabled = $true })
                Mock Get-PSCInterfaceFlag { $mockFlags }
                $result = $ca | Set-CAInterfaceFlags
                $result.RPCEncryptionNotRequired | Should -BeFalse
            }

            It 'should set InterfaceFlags array from Get-PSCInterfaceFlag result' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockFlags = @([PSCustomObject]@{ InterfaceFlag = 'IF_ENFORCEENCRYPTICERTREQUEST'; Enabled = $true })
                Mock Get-PSCInterfaceFlag { $mockFlags }
                $result = $ca | Set-CAInterfaceFlags
                $result.InterfaceFlags | Should -Not -BeNullOrEmpty
            }
        }

        Context 'IF_ENFORCEENCRYPTICERTREQUEST flag is ABSENT (RPC encryption not required)' {
            It 'should set RPCEncryptionNotRequired=$true when IF_ENFORCEENCRYPTICERTREQUEST flag is absent' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockFlags = @([PSCustomObject]@{ InterfaceFlag = 'IF_SOME_OTHER_FLAG'; Enabled = $true })
                Mock Get-PSCInterfaceFlag { $mockFlags }
                $result = $ca | Set-CAInterfaceFlags
                $result.RPCEncryptionNotRequired | Should -BeTrue
            }

            It 'should set RPCEncryptionNotRequired=$true when IF_ENFORCEENCRYPTICERTREQUEST is disabled' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockFlags = @([PSCustomObject]@{ InterfaceFlag = 'IF_ENFORCEENCRYPTICERTREQUEST'; Enabled = $false })
                Mock Get-PSCInterfaceFlag { $mockFlags }
                $result = $ca | Set-CAInterfaceFlags
                $result.RPCEncryptionNotRequired | Should -BeTrue
            }
        }

        Context 'Get-PSCInterfaceFlag returns no results' {
            It 'should not set InterfaceFlags when Get-PSCInterfaceFlag returns null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCInterfaceFlag { $null }
                $result = $ca | Set-CAInterfaceFlags
                $result | Should -Not -BeNullOrEmpty
                $result.InterfaceFlags | Should -BeNullOrEmpty
            }
        }

        Context 'CAFullName is passed to Get-PSCInterfaceFlag' {
            It 'should call Get-PSCInterfaceFlag with the correct CAFullName' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCInterfaceFlag { @() } -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
                $null = $ca | Set-CAInterfaceFlags
                Should -Invoke Get-PSCInterfaceFlag -Times 1 -Exactly -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
            }
        }
    }
}
