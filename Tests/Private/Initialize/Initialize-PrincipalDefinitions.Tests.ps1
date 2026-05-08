#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

Describe 'Initialize-PrincipalDefinitions' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:SafePrincipals      = @()
            $script:DangerousPrincipals = @()
            $script:StandardOwners      = @()
            $script:RootDSE             = $null
            $script:DomainStore         = @{}
        }

        Context 'Successful file load — without RootDSE/DomainStore' {
            It 'should populate $script:SafePrincipals from the data file' {
                Initialize-PrincipalDefinitions
                $script:SafePrincipals.Count | Should -BeGreaterThan 0
            }

            It 'should populate $script:DangerousPrincipals from the data file' {
                Initialize-PrincipalDefinitions
                $script:DangerousPrincipals.Count | Should -BeGreaterThan 0
            }

            It 'should have empty $script:StandardOwners without RootDSE (EA SID added at runtime)' {
                Initialize-PrincipalDefinitions
                # StandardOwners in the .psd1 is intentionally empty;
                # the forest Enterprise Admins SID is injected only when RootDSE + DomainStore are set.
                $script:StandardOwners.Count | Should -Be 0
            }
        }

        Context 'Forest-specific EA SID injection' {
            It 'should append the forest Enterprise Admins SID to StandardOwners when RootDSE and DomainStore are set' {
                $rootDomainDN = 'DC=contoso,DC=com'
                $domainSid = 'S-1-5-21-1234567890-1234567890-1234567890'

                $fakeRootDSE = [PSCustomObject]@{}
                $fakeRootDSE | Add-Member -MemberType NoteProperty -Name 'rootDomainNamingContext' -Value (
                    [PSCustomObject]@{ Value = $rootDomainDN }
                )
                $script:RootDSE = $fakeRootDSE

                $domainEntry = [PSCustomObject]@{
                    distinguishedName = $rootDomainDN
                    objectSid         = $domainSid
                    nETBIOSName       = 'CONTOSO'
                    dnsRoot           = 'contoso.com'
                }
                $script:DomainStore[$rootDomainDN] = $domainEntry

                Initialize-PrincipalDefinitions

                $expectedEASid = "$domainSid-519"
                $script:StandardOwners | Should -Contain $expectedEASid
            }

            It 'should not add a duplicate EA SID if already present in StandardOwners' {
                $rootDomainDN = 'DC=contoso,DC=com'
                $domainSid = 'S-1-5-21-1234567890-1234567890-1234567890'
                $expectedEASid = "$domainSid-519"

                $fakeRootDSE = [PSCustomObject]@{}
                $fakeRootDSE | Add-Member -MemberType NoteProperty -Name 'rootDomainNamingContext' -Value (
                    [PSCustomObject]@{ Value = $rootDomainDN }
                )
                $script:RootDSE = $fakeRootDSE

                $domainEntry = [PSCustomObject]@{
                    distinguishedName = $rootDomainDN
                    objectSid         = $domainSid
                    nETBIOSName       = 'CONTOSO'
                    dnsRoot           = 'contoso.com'
                }
                $script:DomainStore[$rootDomainDN] = $domainEntry

                # Pre-populate the array so the EA SID is already present
                Initialize-PrincipalDefinitions  # loads data file + injects EA SID once
                $countAfterFirst = ($script:StandardOwners | Where-Object { $_ -eq $expectedEASid }).Count

                Initialize-PrincipalDefinitions  # should not add a second copy
                $countAfterSecond = ($script:StandardOwners | Where-Object { $_ -eq $expectedEASid }).Count

                $countAfterSecond | Should -Be $countAfterFirst
            }
        }

        Context 'Graceful degradation — missing RootDSE or DomainStore' {
            It 'should still populate standard principals when RootDSE is null' {
                $script:RootDSE = $null
                Initialize-PrincipalDefinitions
                $script:DangerousPrincipals.Count | Should -BeGreaterThan 0
            }

            It 'should still populate standard principals when DomainStore is empty' {
                $fakeRootDSE = [PSCustomObject]@{}
                $fakeRootDSE | Add-Member -MemberType NoteProperty -Name 'rootDomainNamingContext' -Value (
                    [PSCustomObject]@{ Value = 'DC=contoso,DC=com' }
                )
                $script:RootDSE = $fakeRootDSE
                $script:DomainStore = @{}  # empty — rootDomainDN not found
                Initialize-PrincipalDefinitions
                $script:DangerousPrincipals.Count | Should -BeGreaterThan 0
            }
        }

        Context 'Error resilience' {
            It 'should initialise arrays to empty rather than leaving them null when data file is missing' {
                Mock 'Test-Path' { $false }
                Initialize-PrincipalDefinitions
                # Piping @() into Should loses the value (empty pipeline = $null to Pester).
                # Use -is [array] piped via a scalar $true/$false comparison instead.
                ($script:SafePrincipals      -is [array]) | Should -Be $true -Because 'fallback initialises to @()'
                ($script:DangerousPrincipals -is [array]) | Should -Be $true -Because 'fallback initialises to @()'
                ($script:StandardOwners      -is [array]) | Should -Be $true -Because 'fallback initialises to @()'
            }
        }
    }
}
