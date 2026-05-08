BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Set-CAAuditFilter' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'AuditFilter returned' {
            It 'should set AuditFilter property from Get-PSCAuditFilter result' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockAuditFilter = [PSCustomObject]@{ AuditFilter = 127 }
                Mock Get-PSCAuditFilter { $mockAuditFilter }
                $result = $ca | Set-CAAuditFilter
                $result.AuditFilter | Should -Be 127
            }

            It 'should set AuditFilter to 0 when result has AuditFilter=0' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                $mockAuditFilter = [PSCustomObject]@{ AuditFilter = 0 }
                Mock Get-PSCAuditFilter { $mockAuditFilter }
                $result = $ca | Set-CAAuditFilter
                $result.AuditFilter | Should -Be 0
            }
        }

        Context 'Get-PSCAuditFilter returns null' {
            It 'should return object without setting AuditFilter when result is null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCAuditFilter { $null }
                $result = $ca | Set-CAAuditFilter
                $result | Should -Not -BeNullOrEmpty
                $result.AuditFilter | Should -BeNullOrEmpty
            }
        }

        Context 'CAFullName is passed to Get-PSCAuditFilter' {
            It 'should call Get-PSCAuditFilter with the correct CAFullName' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    CAFullName      = 'contoso.com\MyCA'
                    cn              = 'MyCA'
                }
                Mock Get-PSCAuditFilter { $null } -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
                $null = $ca | Set-CAAuditFilter
                Should -Invoke Get-PSCAuditFilter -Times 1 -Exactly -ParameterFilter { $CAFullName -eq 'contoso.com\MyCA' }
            }
        }
    }
}