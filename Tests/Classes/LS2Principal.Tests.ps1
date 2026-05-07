#requires -Version 5.1
BeforeAll {
    $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

Describe 'LS2Principal class' -Tag 'Unit' {

    Describe 'Well-known principal constructor ([string] ObjectSid, [string] NTAccountName)' {

        It 'should construct without throwing' {
            { [LS2Principal]::new('S-1-0-0', 'NULL SID') } | Should -Not -Throw
        }

        It 'should set objectSid to the provided SID string' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.objectSid | Should -Be 'S-1-0-0'
        }

        It 'should set NTAccountName to the provided name string' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.NTAccountName | Should -Be 'NULL SID'
        }

        It 'should set objectClass to wellKnownPrincipal' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.objectClass | Should -Be 'wellKnownPrincipal'
        }

        It 'should set distinguishedName to null' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.distinguishedName | Should -BeNullOrEmpty
        }

        It 'should set sAMAccountName to null' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.sAMAccountName | Should -BeNullOrEmpty
        }

        It 'should set displayName to null' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.displayName | Should -BeNullOrEmpty
        }

        It 'should set userPrincipalName to null' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.userPrincipalName | Should -BeNullOrEmpty
        }

        It 'should set memberOf to an empty array' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.memberOf | Should -BeNullOrEmpty
        }

        It 'should set ObjectSecurity to null' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.ObjectSecurity | Should -BeNullOrEmpty
        }
    }

    Describe 'Well-known principal constructor with common SIDs' {

        It 'should create Everyone (S-1-1-0) principal correctly' {
            $p = [LS2Principal]::new('S-1-1-0', 'Everyone')
            $p.objectSid | Should -Be 'S-1-1-0'
            $p.NTAccountName | Should -Be 'Everyone'
            $p.objectClass | Should -Be 'wellKnownPrincipal'
        }

        It 'should create Local System (S-1-5-18) principal correctly' {
            $p = [LS2Principal]::new('S-1-5-18', 'NT AUTHORITY\SYSTEM')
            $p.objectSid | Should -Be 'S-1-5-18'
            $p.NTAccountName | Should -Be 'NT AUTHORITY\SYSTEM'
            $p.objectClass | Should -Be 'wellKnownPrincipal'
        }

        It 'should create Authenticated Users (S-1-5-11) principal correctly' {
            $p = [LS2Principal]::new('S-1-5-11', 'NT AUTHORITY\Authenticated Users')
            $p.objectSid | Should -Be 'S-1-5-11'
            $p.NTAccountName | Should -Be 'NT AUTHORITY\Authenticated Users'
        }

        It 'should create BUILTIN\Administrators (S-1-5-32-544) principal correctly' {
            $p = [LS2Principal]::new('S-1-5-32-544', 'BUILTIN\Administrators')
            $p.objectSid | Should -Be 'S-1-5-32-544'
            $p.NTAccountName | Should -Be 'BUILTIN\Administrators'
        }
    }

    Describe 'LS2Principal AD constructor — integration (requires Active Directory)' -Tag 'Integration', 'ActiveDirectory' {

        It 'AD constructor requires SearchResult, Server, SidKey, NTAccountName parameters' -Skip {
            # Skipped: requires a live Active Directory environment
            # Signature: [LS2Principal]::new([SearchResult], [string], [SecurityIdentifier], [string])
        }
    }

    Describe 'LS2Principal properties' {

        It 'should expose objectSid as a readable string property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'objectSid' | Should -Not -BeNullOrEmpty
        }

        It 'should expose NTAccountName as a readable string property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'NTAccountName' | Should -Not -BeNullOrEmpty
        }

        It 'should expose objectClass as a readable string property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'objectClass' | Should -Not -BeNullOrEmpty
        }

        It 'should expose memberOf as a property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'memberOf' | Should -Not -BeNullOrEmpty
        }

        It 'should expose MemberCount as an integer property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'MemberCount' | Should -Not -BeNullOrEmpty
        }

        It 'should expose distinguishedName as a property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'distinguishedName' | Should -Not -BeNullOrEmpty
        }

        It 'should expose sAMAccountName as a property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'sAMAccountName' | Should -Not -BeNullOrEmpty
        }

        It 'should expose displayName as a property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'displayName' | Should -Not -BeNullOrEmpty
        }

        It 'should expose userPrincipalName as a property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'userPrincipalName' | Should -Not -BeNullOrEmpty
        }

        It 'should expose ObjectSecurity as a property' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p | Get-Member -Name 'ObjectSecurity' | Should -Not -BeNullOrEmpty
        }

        It 'should have exactly 10 public properties' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            @($p | Get-Member -MemberType Property).Count | Should -Be 10
        }
    }

    Describe 'LS2Principal type' {

        It 'should be of type LS2Principal' {
            $p = [LS2Principal]::new('S-1-0-0', 'NULL SID')
            $p.GetType().Name | Should -Be 'LS2Principal'
        }

        It 'should have two constructors' {
            [LS2Principal].GetConstructors().Count | Should -Be 2
        }

        It 'well-known constructor should take exactly 2 parameters' {
            $wellKnownCtor = [LS2Principal].GetConstructors() |
                Where-Object { $_.GetParameters().Count -eq 2 }
            $wellKnownCtor | Should -Not -BeNullOrEmpty
        }
    }
}
