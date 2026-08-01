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
}

Describe 'Test-IsStandardOwner' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:StandardOwners = @()
        }

        Context 'When StandardOwners provided explicitly' {

            It 'should return $true for an exact SID match' {
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-18' -StandardOwners @('S-1-5-18') | Should -BeTrue
            }

            It 'should return $true when SID matches a -512$ regex pattern (Domain Admins)' {
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-21-1234567890-1234567890-1234567890-512' -StandardOwners @('-512$') |
                    Should -BeTrue
            }

            It 'should return $true when SID matches a -519$ regex pattern (Enterprise Admins)' {
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-21-1234567890-1234567890-1234567890-519' -StandardOwners @('-519$') |
                    Should -BeTrue
            }

            It 'should return $true when SID matches one of multiple patterns' {
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-18' -StandardOwners @('-512$', 'S-1-5-18', '-519$') |
                    Should -BeTrue
            }

            It 'should return $false when SID does not match any pattern' {
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-21-1234567890-1234567890-1234567890-1001' `
                    -StandardOwners @('-512$', '-519$', 'S-1-5-18') |
                    Should -BeFalse
            }

            It 'should return $false when SID ends in -512 but pattern requires -513$' {
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-21-1234567890-1234567890-1234567890-512' -StandardOwners @('-513$') |
                    Should -BeFalse
            }

            It 'should accept pipeline input' {
                'S-1-5-18' | Test-IsStandardOwner -StandardOwners @('S-1-5-18') | Should -BeTrue
            }

            It 'should return $false when NTAccount cannot be translated (unresolvable account)' {
                Test-IsStandardOwner -OwnerIdentity 'FAKE\NonExistentAccount99' -StandardOwners @('-512$') |
                    Should -BeFalse
            }
        }

        Context 'When using $script:StandardOwners (no param provided)' {

            It 'should write a warning when $script:StandardOwners is empty' {
                $script:StandardOwners = @()
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-18' -WarningVariable warnOut -WarningAction SilentlyContinue | Out-Null
                $warnOut | Should -Not -BeNullOrEmpty
            }

            It 'should return $true when $script:StandardOwners contains a matching SID' {
                $script:StandardOwners = @('S-1-5-18')
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-18' | Should -BeTrue
            }

            It 'should return $true when $script:StandardOwners contains a matching regex pattern' {
                $script:StandardOwners = @('-512$', '-519$')
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-21-1234567890-1234567890-1234567890-519' | Should -BeTrue
            }

            It 'should return $false for a non-standard SID using populated $script:StandardOwners' {
                $script:StandardOwners = @('-512$', '-519$')
                Test-IsStandardOwner -OwnerIdentity 'S-1-5-21-1234567890-1234567890-1234567890-1001' | Should -BeFalse
            }
        }
    }
}
