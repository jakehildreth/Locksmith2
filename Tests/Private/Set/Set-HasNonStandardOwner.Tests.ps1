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

Describe 'Set-HasNonStandardOwner' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'StandardOwners not initialized' {
            It 'should warn and not process objects when StandardOwners is empty' {
                # StandardOwners is empty (set in BeforeEach)
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = 'S-1-5-18'
                }

                # Function writes a warning and returns early from begin block when StandardOwners is empty
                $result = $obj | Set-HasNonStandardOwner 3>&1

                $result | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } |
                    Select-Object -ExpandProperty Message |
                    Should -Match 'StandardOwners not initialized'
            }
        }

        Context 'Owner is a standard owner' {
            BeforeEach {
                # Use Test-IsStandardOwner mock — the function under test calls this internal helper
                Mock Test-IsStandardOwner { $true }
                $script:StandardOwners = @('S-1-5-18')  # Non-empty so begin block passes
            }

            It 'should set HasNonStandardOwner=$false when owner matches a standard owner pattern' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = 'S-1-5-18'
                }

                $result = $obj | Set-HasNonStandardOwner

                $result.HasNonStandardOwner | Should -BeFalse
            }
        }

        Context 'Owner is not a standard owner' {
            BeforeEach {
                Mock Test-IsStandardOwner { $false }
                $script:StandardOwners = @('S-1-5-18')
            }

            It 'should set HasNonStandardOwner=$true when owner does not match any standard owner' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = 'S-1-5-21-100-200-300-1001'
                }

                $result = $obj | Set-HasNonStandardOwner

                $result.HasNonStandardOwner | Should -BeTrue
            }
        }

        Context 'Owner cannot be determined' {
            BeforeEach {
                $script:StandardOwners = @('S-1-5-18')
            }

            It 'should set HasNonStandardOwner=$null when Owner property is null' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = $null
                }

                $result = $obj | Set-HasNonStandardOwner

                $result.HasNonStandardOwner | Should -BeNullOrEmpty
            }
        }

        Context 'Pipeline processing' {
            BeforeEach {
                $script:StandardOwners = @('S-1-5-18')
                # Alternate: standard / non-standard based on input
                Mock Test-IsStandardOwner {
                    param($OwnerIdentity)
                    $OwnerIdentity -eq 'S-1-5-18'
                }
            }

            It 'should process multiple objects in pipeline' {
                $objects = @(
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; Owner = 'S-1-5-18' }),
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; Owner = 'S-1-5-21-1-2-3-999' })
                )

                $results = $objects | Set-HasNonStandardOwner

                $results.Count | Should -Be 2
                $results[0].HasNonStandardOwner | Should -BeFalse
                $results[1].HasNonStandardOwner | Should -BeTrue
            }
        }
    }
}
