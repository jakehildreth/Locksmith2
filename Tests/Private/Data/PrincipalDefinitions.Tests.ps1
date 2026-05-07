#requires -Version 5.1
BeforeAll {
    $PesterPreference = [PesterConfiguration]::Default
    $PesterPreference.Should.ErrorAction = 'Continue'

    $DataFilePath = Join-Path $PSScriptRoot '..' '..' '..' 'Private' 'Data' 'PrincipalDefinitions.psd1'
    $script:Data = Import-PowerShellDataFile -Path $DataFilePath
}

Describe 'PrincipalDefinitions data file' -Tag 'Unit', 'Data' {

    Context 'Required top-level keys' {

        It 'should have a DataVersion key' {
            $script:Data.ContainsKey('DataVersion') | Should -BeTrue
        }

        It 'should have a SafePrincipals key' {
            $script:Data.ContainsKey('SafePrincipals') | Should -BeTrue
        }

        It 'should have a DangerousPrincipals key' {
            $script:Data.ContainsKey('DangerousPrincipals') | Should -BeTrue
        }

        It 'should have a StandardOwners key' {
            $script:Data.ContainsKey('StandardOwners') | Should -BeTrue
        }
    }

    Context 'DataVersion' {

        It 'should have DataVersion equal to 1.0' {
            $script:Data.DataVersion | Should -Be '1.0'
        }
    }

    Context 'SafePrincipals' {

        It 'should be an array' {
            $script:Data.SafePrincipals | Should -BeOfType [object]
            @($script:Data.SafePrincipals).Count | Should -BeGreaterThan 0
        }

        It 'should contain exactly 19 entries' {
            @($script:Data.SafePrincipals).Count | Should -Be 19
        }

        It 'should contain the Domain Admins RID pattern (-512$)' {
            $script:Data.SafePrincipals | Should -Contain '-512$'
        }

        It 'should contain the Enterprise Admins RID pattern (-519$)' {
            $script:Data.SafePrincipals | Should -Contain '-519$'
        }

        It 'should contain the Schema Admins RID pattern (-518$)' {
            $script:Data.SafePrincipals | Should -Contain '-518$'
        }

        It 'should contain the local Administrators SID (S-1-5-32-544)' {
            $script:Data.SafePrincipals | Should -Contain 'S-1-5-32-544'
        }

        It 'should contain the Local System SID (S-1-5-18)' {
            $script:Data.SafePrincipals | Should -Contain 'S-1-5-18'
        }

        It 'should contain the NT AUTHORITY\SELF SID (S-1-5-10)' {
            $script:Data.SafePrincipals | Should -Contain 'S-1-5-10'
        }

        It 'should contain NT AUTHORITY\\SYSTEM NTAccount name' {
            $script:Data.SafePrincipals | Should -Contain 'NT AUTHORITY\\SYSTEM'
        }

        It 'should contain NT AUTHORITY\\SELF NTAccount name' {
            $script:Data.SafePrincipals | Should -Contain 'NT AUTHORITY\\SELF'
        }

        It 'should contain NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS NTAccount name' {
            $script:Data.SafePrincipals | Should -Contain 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS'
        }
    }

    Context 'DangerousPrincipals' {

        It 'should be an array' {
            $script:Data.DangerousPrincipals | Should -BeOfType [object]
        }

        It 'should contain exactly 11 entries' {
            @($script:Data.DangerousPrincipals).Count | Should -Be 11
        }

        It 'should contain the NULL SID (S-1-0-0)' {
            $script:Data.DangerousPrincipals | Should -Contain 'S-1-0-0'
        }

        It 'should contain the Everyone SID (S-1-1-0)' {
            $script:Data.DangerousPrincipals | Should -Contain 'S-1-1-0'
        }

        It 'should contain Everyone NTAccount name' {
            $script:Data.DangerousPrincipals | Should -Contain 'Everyone'
        }

        It 'should contain the Anonymous Logon SID (S-1-5-7)' {
            $script:Data.DangerousPrincipals | Should -Contain 'S-1-5-7'
        }

        It 'should contain NT AUTHORITY\\ANONYMOUS LOGON NTAccount name' {
            $script:Data.DangerousPrincipals | Should -Contain 'NT AUTHORITY\\ANONYMOUS LOGON'
        }

        It 'should contain the Authenticated Users SID (S-1-5-11)' {
            $script:Data.DangerousPrincipals | Should -Contain 'S-1-5-11'
        }

        It 'should contain NT AUTHORITY\\Authenticated Users NTAccount name' {
            $script:Data.DangerousPrincipals | Should -Contain 'NT AUTHORITY\\Authenticated Users'
        }

        It 'should contain the BUILTIN\\Users SID (S-1-5-32-545)' {
            $script:Data.DangerousPrincipals | Should -Contain 'S-1-5-32-545'
        }

        It 'should contain BUILTIN\\Users NTAccount name' {
            $script:Data.DangerousPrincipals | Should -Contain 'BUILTIN\\Users'
        }

        It 'should contain the Domain Users RID pattern (-513$)' {
            $script:Data.DangerousPrincipals | Should -Contain '-513$'
        }

        It 'should contain the Domain Computers RID pattern (-515$)' {
            $script:Data.DangerousPrincipals | Should -Contain '-515$'
        }
    }

    Context 'StandardOwners' {

        It 'should be initially empty (runtime-populated by forest Enterprise Admins SID)' {
            @($script:Data.StandardOwners).Count | Should -Be 0
        }
    }

    Context 'Cross-contamination guards' {

        It 'should not have any DangerousPrincipals entries in SafePrincipals' {
            foreach ($dangerous in $script:Data.DangerousPrincipals) {
                $script:Data.SafePrincipals | Should -Not -Contain $dangerous
            }
        }

        It 'should not have any SafePrincipals entries in DangerousPrincipals' {
            foreach ($safe in $script:Data.SafePrincipals) {
                $script:Data.DangerousPrincipals | Should -Not -Contain $safe
            }
        }
    }
}
