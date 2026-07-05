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

Describe 'Set-CAAdministrator' -Tag 'Unit' {
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
                Mock Get-PSCCAAdministrator { }
                Mock Resolve-Principal { }
                $result = $ca | Set-CAAdministrator
                $result | Should -Not -BeNullOrEmpty
                Should -Invoke Get-PSCCAAdministrator -Times 0
            }
        }

        Context 'CA Administrators returned' {
            It 'should set CAAdministrators array from Get-PSCCAAdministrator result' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockAdmins = @(
                    [PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin1' },
                    [PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin2' }
                )
                Mock Get-PSCCAAdministrator { $mockAdmins }
                Mock Resolve-Principal { }
                $result = $ca | Set-CAAdministrator
                $result.CAAdministrators | Should -Not -BeNullOrEmpty
                $result.CAAdministrators.Count | Should -Be 2
            }

            It 'should call Resolve-Principal for each administrator' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockAdmins = @(
                    [PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin1' },
                    [PSCustomObject]@{ CAAdministrator = 'CONTOSO\Admin2' }
                )
                Mock Get-PSCCAAdministrator { $mockAdmins }
                Mock Resolve-Principal { }
                $null = $ca | Set-CAAdministrator
                Should -Invoke Resolve-Principal -Times 2 -Exactly
            }
        }

        Context 'Get-PSCCAAdministrator returns null or empty' {
            It 'should not set CAAdministrators when Get-PSCCAAdministrator returns null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCCAAdministrator { $null }
                Mock Resolve-Principal { }
                $result = $ca | Set-CAAdministrator
                $result | Should -Not -BeNullOrEmpty
                $result.CAAdministrators | Should -BeNullOrEmpty
            }
        }

        Context 'CAFullName is passed to Get-PSCCAAdministrator' {
            It 'should call Get-PSCCAAdministrator with the correct CAFullName' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCCAAdministrator { @() } -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
                Mock Resolve-Principal { }
                $null = $ca | Set-CAAdministrator
                Should -Invoke Get-PSCCAAdministrator -Times 1 -Exactly -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
            }
        }
    }
}
