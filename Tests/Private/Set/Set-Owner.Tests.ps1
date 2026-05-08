BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Set-Owner' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null

            Mock Resolve-Principal { } -Verifiable
        }

        Context 'No owner present' {
            It 'should return object unchanged when Owner is null' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = $null
                }

                $result = $obj | Set-Owner

                $result | Should -Not -BeNullOrEmpty
                $result.Owner | Should -BeNullOrEmpty
            }

            It 'should return object unchanged when Owner is empty string' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = ''
                }

                $result = $obj | Set-Owner

                $result | Should -Not -BeNullOrEmpty
            }
        }

        Context 'Owner in raw SID format (S-1-...)' {
            It 'should normalize Owner to SID string when Owner is a raw SID' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = 'S-1-5-18'
                }

                $result = $obj | Set-Owner

                $result.Owner | Should -Be 'S-1-5-18'
            }

            It 'should call Resolve-Principal with the extracted SID' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = 'S-1-5-18'
                }

                $null = $obj | Set-Owner

                Should -Invoke Resolve-Principal -Times 1 -Exactly
            }
        }

        Context 'Owner in SDDL format (O:S-1-...)' {
            It 'should extract SID from SDDL O: prefix and normalize Owner' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = 'O:S-1-5-18'
                }

                $result = $obj | Set-Owner

                $result.Owner | Should -Be 'S-1-5-18'
            }
        }

        Context 'Owner in NTAccount format (DOMAIN\User)' {
            It 'should translate NTAccount to SID and normalize Owner' -Skip:(-not $IsWindows) {
                # Use a well-known local SID that resolves on all Windows machines
                $obj = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName = 'pKICertificateTemplate'
                    Owner           = 'NT AUTHORITY\SYSTEM'
                }

                $result = $obj | Set-Owner

                # NT AUTHORITY\SYSTEM = S-1-5-18
                $result.Owner | Should -Be 'S-1-5-18'
            }
        }

        Context 'Pipeline processing' {
            It 'should process multiple objects and return all' {
                $objects = @(
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; Owner = 'S-1-5-18' }),
                    (New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate'; Owner = 'S-1-5-19' })
                )

                $results = $objects | Set-Owner

                $results.Count | Should -Be 2
            }
        }
    }
}
