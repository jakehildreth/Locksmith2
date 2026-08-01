#requires -Version 5.1
BeforeAll {
    $PesterPreference = [PesterConfiguration]::Default
    $PesterPreference.Should.ErrorAction = 'Continue'

    $DataFilePath = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Data\PrincipalDefinitions.ps1'
    . $DataFilePath
}

Describe 'PrincipalDefinitions data file' -Tag 'Unit', 'Data' {

    Context 'Required top-level structure' {

        It '$script:PrincipalDefinitionsBase should be populated after dot-sourcing' {
            $script:PrincipalDefinitionsBase | Should -Not -BeNullOrEmpty
        }

        It 'should have a SafePrincipals key' {
            $script:PrincipalDefinitionsBase.ContainsKey('SafePrincipals') | Should -BeTrue
        }

        It 'should have a DangerousPrincipals key' {
            $script:PrincipalDefinitionsBase.ContainsKey('DangerousPrincipals') | Should -BeTrue
        }

        It 'should have a StandardOwners key' {
            $script:PrincipalDefinitionsBase.ContainsKey('StandardOwners') | Should -BeTrue
        }
    }

    Context 'SafePrincipals' {

        It 'should be an array' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -BeOfType [object]
            @($script:PrincipalDefinitionsBase.SafePrincipals).Count | Should -BeGreaterThan 0
        }

        It 'should contain exactly 19 entries' {
            @($script:PrincipalDefinitionsBase.SafePrincipals).Count | Should -Be 19
        }

        It 'should contain the Domain Admins RID pattern (-512$)' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -Contain '-512$'
        }

        It 'should contain the Enterprise Admins RID pattern (-519$)' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -Contain '-519$'
        }

        It 'should contain the Schema Admins RID pattern (-518$)' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -Contain '-518$'
        }

        It 'should contain the local Administrators SID (S-1-5-32-544)' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -Contain 'S-1-5-32-544'
        }

        It 'should contain the Local System SID (S-1-5-18)' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -Contain 'S-1-5-18'
        }

        It 'should contain the NT AUTHORITY\SELF SID (S-1-5-10)' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -Contain 'S-1-5-10'
        }

        It 'should contain NT AUTHORITY\\SYSTEM NTAccount name' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -Contain 'NT AUTHORITY\\SYSTEM'
        }

        It 'should contain NT AUTHORITY\\SELF NTAccount name' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -Contain 'NT AUTHORITY\\SELF'
        }

        It 'should contain NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS NTAccount name' {
            $script:PrincipalDefinitionsBase.SafePrincipals | Should -Contain 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS'
        }
    }

    Context 'DangerousPrincipals' {

        It 'should be an array' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -BeOfType [object]
        }

        It 'should contain exactly 11 entries' {
            @($script:PrincipalDefinitionsBase.DangerousPrincipals).Count | Should -Be 11
        }

        It 'should contain the NULL SID (S-1-0-0)' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain 'S-1-0-0'
        }

        It 'should contain the Everyone SID (S-1-1-0)' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain 'S-1-1-0'
        }

        It 'should contain Everyone NTAccount name' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain 'Everyone'
        }

        It 'should contain the Anonymous Logon SID (S-1-5-7)' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain 'S-1-5-7'
        }

        It 'should contain NT AUTHORITY\\ANONYMOUS LOGON NTAccount name' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain 'NT AUTHORITY\\ANONYMOUS LOGON'
        }

        It 'should contain the Authenticated Users SID (S-1-5-11)' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain 'S-1-5-11'
        }

        It 'should contain NT AUTHORITY\\Authenticated Users NTAccount name' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain 'NT AUTHORITY\\Authenticated Users'
        }

        It 'should contain the BUILTIN\\Users SID (S-1-5-32-545)' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain 'S-1-5-32-545'
        }

        It 'should contain BUILTIN\\Users NTAccount name' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain 'BUILTIN\\Users'
        }

        It 'should contain the Domain Users RID pattern (-513$)' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain '-513$'
        }

        It 'should contain the Domain Computers RID pattern (-515$)' {
            $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Contain '-515$'
        }
    }

    Context 'StandardOwners' {

        It 'should be initially empty (runtime-populated by forest Enterprise Admins SID)' {
            @($script:PrincipalDefinitionsBase.StandardOwners).Count | Should -Be 0
        }
    }

    Context 'Cross-contamination guards' {

        It 'should not have any DangerousPrincipals entries in SafePrincipals' {
            foreach ($dangerous in $script:PrincipalDefinitionsBase.DangerousPrincipals) {
                $script:PrincipalDefinitionsBase.SafePrincipals | Should -Not -Contain $dangerous
            }
        }

        It 'should not have any SafePrincipals entries in DangerousPrincipals' {
            foreach ($safe in $script:PrincipalDefinitionsBase.SafePrincipals) {
                $script:PrincipalDefinitionsBase.DangerousPrincipals | Should -Not -Contain $safe
            }
        }
    }
}
