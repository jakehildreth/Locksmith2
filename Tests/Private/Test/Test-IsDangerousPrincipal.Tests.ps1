#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

Describe 'Test-IsDangerousPrincipal' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        Context 'When DangerousEnrollee is provided explicitly' {

            It 'should return $true when identity matches an exact pattern' {
                Test-IsDangerousPrincipal -IdentityReference 'Everyone' -DangerousEnrollee @('Everyone', 'S-1-1-0') |
                    Should -BeTrue
            }

            It 'should return $true when identity matches a regex suffix pattern (-513$)' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-513' -DangerousEnrollee @('-513$') |
                    Should -BeTrue
            }

            It 'should return $true when identity matches -515$ (Domain Computers)' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-5-21-999-888-777-515' -DangerousEnrollee @('-515$') |
                    Should -BeTrue
            }

            It 'should return $true when identity matches NULL SID exactly' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-0-0' -DangerousEnrollee @('S-1-0-0') |
                    Should -BeTrue
            }

            It 'should return $false when identity does not match any pattern' {
                Test-IsDangerousPrincipal -IdentityReference 'CONTOSO\Domain Admins' -DangerousEnrollee @('Everyone', 'S-1-1-0', '-513$') |
                    Should -BeFalse
            }

            It 'should return $false for Domain Admins SID (-512)' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-512' -DangerousEnrollee @('-513$', '-515$') |
                    Should -BeFalse
            }

            It 'should accept pipeline input and return one bool per item' {
                $results = @('Everyone', 'CONTOSO\Domain Admins', 'S-1-5-21-1-2-3-513') |
                    Test-IsDangerousPrincipal -DangerousEnrollee @('Everyone', '-513$')
                $results.Count | Should -Be 3
                $results[0] | Should -BeTrue
                $results[1] | Should -BeFalse
                $results[2] | Should -BeTrue
            }

            It 'should return [bool] output type' {
                $result = Test-IsDangerousPrincipal -IdentityReference 'Everyone' -DangerousEnrollee @('Everyone')
                $result | Should -BeOfType [bool]
            }
        }

        Context 'When DangerousEnrollee is loaded from module state' {
            BeforeAll {
                Initialize-PrincipalDefinitions
            }

            It 'should return $true for Everyone' {
                Test-IsDangerousPrincipal -IdentityReference 'Everyone' | Should -BeTrue
            }

            It 'should return $true for S-1-1-0 (Everyone SID)' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-1-0' | Should -BeTrue
            }

            It 'should return $true for S-1-5-11 (Authenticated Users)' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-5-11' | Should -BeTrue
            }

            It 'should return $true for Domain Users SID ending in -513' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-513' | Should -BeTrue
            }

            It 'should return $true for Domain Computers SID ending in -515' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-515' | Should -BeTrue
            }

            It 'should return $false for Domain Admins SID ending in -512' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-512' | Should -BeFalse
            }

            It 'should return $false for SYSTEM SID (S-1-5-18)' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-5-18' | Should -BeFalse
            }

            It 'should return $false for Enterprise Admins SID ending in -519' {
                Test-IsDangerousPrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-519' | Should -BeFalse
            }
        }
    }
}
