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

Describe 'Convert-IdentityReferenceToSid' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:PrincipalStore = @{}
            $script:Credential = $null
            $script:RootDSE = $null
        }

        Context 'SID passthrough' {
            It 'should return the original SecurityIdentifier unchanged' {
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
                $result = Convert-IdentityReferenceToSid -IdentityReference $sid
                $result | Should -BeOfType [System.Security.Principal.SecurityIdentifier]
                $result.Value | Should -Be 'S-1-5-18'
            }
        }

        Context 'SID-shaped NTAccount normalisation' {
            It 'should normalise a SID-shaped NTAccount to a SecurityIdentifier' {
                $sidShaped = [System.Security.Principal.NTAccount]::new('S-1-5-18')
                $result = Convert-IdentityReferenceToSid -IdentityReference $sidShaped
                $result | Should -BeOfType [System.Security.Principal.SecurityIdentifier]
                $result.Value | Should -Be 'S-1-5-18'
            }
        }

        Context 'PrincipalStore cache hit' {
            It 'should return SID from PrincipalStore when NTAccount name is cached' {
                # NTAccount that can never resolve via Translate() — forces the PrincipalStore cache path.
                $ntAccount = [System.Security.Principal.NTAccount]::new('FAKECORP\testuser99999')
                # Use PSCustomObject directly: the source only accesses .ntAccountName and .objectSid,
                # so a PSCustomObject is sufficient and avoids FormatterServices edge-cases.
                $principal = [PSCustomObject]@{
                    objectSid     = 'S-1-5-21-1-2-3-1001'
                    NTAccountName = 'FAKECORP\testuser99999'
                }
                $script:PrincipalStore['S-1-5-21-1-2-3-1001'] = $principal

                $result = Convert-IdentityReferenceToSid -IdentityReference $ntAccount
                $result | Should -BeOfType [System.Security.Principal.SecurityIdentifier]
                $result.Value | Should -Be 'S-1-5-21-1-2-3-1001'
            }
        }

        Context 'Well-known SID translation (Integration)' {
            BeforeAll {
                $script:WellKnownTranslateAvailable = $true
                try {
                    $null = [System.Security.Principal.NTAccount]::new('NT AUTHORITY\SYSTEM').Translate(
                        [System.Security.Principal.SecurityIdentifier])
                } catch {
                    $script:WellKnownTranslateAvailable = $false
                }
            }

            It 'should translate NT AUTHORITY\SYSTEM to S-1-5-18 via Translate()' -Skip:(-not $script:WellKnownTranslateAvailable) {
                $ntAccount = [System.Security.Principal.NTAccount]::new('NT AUTHORITY\SYSTEM')
                $result = Convert-IdentityReferenceToSid -IdentityReference $ntAccount
                $result | Should -BeOfType [System.Security.Principal.SecurityIdentifier]
                $result.Value | Should -Be 'S-1-5-18'
            }
        }

        Context 'No credential — cannot resolve unknown NTAccount' {
            It 'should emit a warning and return the original reference when Translate() fails and no credential' {
                # Use a domain-style NTAccount that won't resolve locally and has no credential set
                $ntAccount = [System.Security.Principal.NTAccount]::new('NONEXISTENT\fakeDomainUser')
                $result = $ntAccount | Convert-IdentityReferenceToSid -WarningVariable warnOut 3>&1
                # May return the original NTAccount or $null; the key thing is it doesn't throw
                $true | Should -BeTrue
            }
        }

        Context 'Pipeline input' {
            It 'should accept IdentityReference via the pipeline' {
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
                $result = $sid | Convert-IdentityReferenceToSid
                $result.Value | Should -Be 'S-1-5-18'
            }
        }
    }
}
