#requires -Version 5.1
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

Describe 'Test-IsLowPrivilegePrincipal' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        Context 'When SafeEnrollee and DangerousEnrollee are provided explicitly' {
            BeforeAll {
                $script:SafeList      = @('-512$', '-519$', 'S-1-5-18')
                $script:DangerousList = @('S-1-1-0', 'Everyone', '-513$', '-515$')
            }

            It 'should return $true for a custom principal (neither safe nor dangerous)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'CONTOSO\WebServerAdmins' `
                    -SafeEnrollee $script:SafeList -DangerousEnrollee $script:DangerousList |
                    Should -BeTrue
            }

            It 'should return $true for an arbitrary custom SID with no matching pattern' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'S-1-5-21-1-2-3-9999' `
                    -SafeEnrollee $script:SafeList -DangerousEnrollee $script:DangerousList |
                    Should -BeTrue
            }

            It 'should return $false for a safe (admin) principal matching -512$' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-512' `
                    -SafeEnrollee $script:SafeList -DangerousEnrollee $script:DangerousList |
                    Should -BeFalse
            }

            It 'should return $false for SYSTEM (exact SID in safe list)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'S-1-5-18' `
                    -SafeEnrollee $script:SafeList -DangerousEnrollee $script:DangerousList |
                    Should -BeFalse
            }

            It 'should return $false for Everyone (dangerous principal)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'Everyone' `
                    -SafeEnrollee $script:SafeList -DangerousEnrollee $script:DangerousList |
                    Should -BeFalse
            }

            It 'should return $false for Domain Users SID (dangerous -513$)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'S-1-5-21-999-888-777-513' `
                    -SafeEnrollee $script:SafeList -DangerousEnrollee $script:DangerousList |
                    Should -BeFalse
            }

            It 'should return $false for Domain Computers SID (dangerous -515$)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'S-1-5-21-999-888-777-515' `
                    -SafeEnrollee $script:SafeList -DangerousEnrollee $script:DangerousList |
                    Should -BeFalse
            }

            It 'should return [bool] output type' {
                $result = Test-IsLowPrivilegePrincipal -IdentityReference 'CONTOSO\Custom' `
                    -SafeEnrollee $script:SafeList -DangerousEnrollee $script:DangerousList
                $result | Should -BeOfType [bool]
            }

            It 'should accept pipeline input and return one bool per item' {
                $results = @('CONTOSO\SvcAccount', 'S-1-5-21-1-2-3-512', 'Everyone') |
                    Test-IsLowPrivilegePrincipal -SafeEnrollee $script:SafeList -DangerousEnrollee $script:DangerousList
                $results.Count | Should -Be 3
                $results[0] | Should -BeTrue   # custom — low privilege
                $results[1] | Should -BeFalse  # Domain Admins — safe
                $results[2] | Should -BeFalse  # Everyone — dangerous
            }
        }

        Context 'When loading from PrincipalDefinitions.psd1' {

            It 'should return $true for a custom principal not in either list' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'CONTOSO\CustomServiceAccount' | Should -BeTrue
            }

            It 'should return $false for Enterprise Admins SID (-519)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-519' | Should -BeFalse
            }

            It 'should return $false for Domain Admins SID (-512)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-512' | Should -BeFalse
            }

            It 'should return $false for SYSTEM SID (S-1-5-18, safe)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'S-1-5-18' | Should -BeFalse
            }

            It 'should return $false for Everyone (dangerous)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'Everyone' | Should -BeFalse
            }

            It 'should return $false for Domain Computers SID (-515, dangerous)' {
                Test-IsLowPrivilegePrincipal -IdentityReference 'S-1-5-21-1234567890-1234567890-1234567890-515' | Should -BeFalse
            }
        }
    }
}
