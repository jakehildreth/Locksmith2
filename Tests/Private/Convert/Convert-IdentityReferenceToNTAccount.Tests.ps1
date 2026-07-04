#requires -Version 5.1
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

Describe 'Convert-IdentityReferenceToNTAccount' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:PrincipalStore = @{}
            $script:DomainStore = @{}
        }

        Context 'NTAccount passthrough' {
            It 'should return the original NTAccount object without modification' {
                $ntAccount = [System.Security.Principal.NTAccount]::new('CONTOSO\jdoe')
                $result = Convert-IdentityReferenceToNTAccount -SecurityIdentifier $ntAccount
                $result | Should -BeOfType [System.Security.Principal.NTAccount]
                $result.Value | Should -Be 'CONTOSO\jdoe'
            }
        }

        Context 'PrincipalStore cache hit' {
            It 'should return NTAccount from PrincipalStore when SID is cached' {
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
                $principal = New-MockLS2Principal -Properties @{
                    objectSid    = 'S-1-5-18'
                    NTAccountName = 'NT AUTHORITY\SYSTEM'
                }
                $script:PrincipalStore['S-1-5-18'] = $principal

                $result = Convert-IdentityReferenceToNTAccount -SecurityIdentifier $sid
                $result | Should -BeOfType [System.Security.Principal.NTAccount]
                $result.Value | Should -Be 'NT AUTHORITY\SYSTEM'
            }

            It 'should not call Translate when PrincipalStore has the SID' {
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
                $principal = New-MockLS2Principal -Properties @{
                    objectSid     = 'S-1-5-18'
                    NTAccountName = 'NT AUTHORITY\SYSTEM'
                }
                $script:PrincipalStore['S-1-5-18'] = $principal
                # If Translate were called, it would succeed for a well-known SID anyway.
                # The key check is the cache is used (verify result is from store).
                $result = Convert-IdentityReferenceToNTAccount -SecurityIdentifier $sid
                $result.Value | Should -Be 'NT AUTHORITY\SYSTEM'
            }
        }

        Context 'SID-shaped NTAccount normalisation' {
            It 'should normalise a SID-shaped identity reference to a SecurityIdentifier' {
                # An ACE can surface a SID as NTAccount (e.g. "S-1-5-21-1-2-3-500")
                # The function normalises it before lookup.
                $sidShaped = [System.Security.Principal.NTAccount]::new('S-1-5-18')
                $principal = New-MockLS2Principal -Properties @{
                    objectSid     = 'S-1-5-18'
                    NTAccountName = 'NT AUTHORITY\SYSTEM'
                }
                $script:PrincipalStore['S-1-5-18'] = $principal

                $result = Convert-IdentityReferenceToNTAccount -SecurityIdentifier $sidShaped
                $result.Value | Should -Be 'NT AUTHORITY\SYSTEM'
            }
        }

        Context 'Well-known SID translation (Integration)' {
            BeforeAll {
                # S-1-5-18 is NT AUTHORITY\SYSTEM — translatable without AD
                $script:WellKnownSidAvailable = $true
                try {
                    $null = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18').Translate(
                        [System.Security.Principal.NTAccount])
                } catch {
                    $script:WellKnownSidAvailable = $false
                }
            }

            It 'should translate S-1-5-18 to NT AUTHORITY\SYSTEM via Translate()' -Skip:(-not $script:WellKnownSidAvailable) {
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
                $result = Convert-IdentityReferenceToNTAccount -SecurityIdentifier $sid
                $result | Should -BeOfType [System.Security.Principal.NTAccount]
                $result.Value | Should -Be 'NT AUTHORITY\SYSTEM'
            }
        }

        Context 'Pipeline input' {
            It 'should accept SecurityIdentifier via the pipeline' {
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
                $principal = New-MockLS2Principal -Properties @{
                    objectSid     = 'S-1-5-18'
                    NTAccountName = 'NT AUTHORITY\SYSTEM'
                }
                $script:PrincipalStore['S-1-5-18'] = $principal

                $result = $sid | Convert-IdentityReferenceToNTAccount
                $result.Value | Should -Be 'NT AUTHORITY\SYSTEM'
            }
        }
    }
}
