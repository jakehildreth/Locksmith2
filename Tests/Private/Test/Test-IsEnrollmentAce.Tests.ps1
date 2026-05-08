#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test'
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsEnrollmentAce.ps1') -Raw)))
}

Describe 'Test-IsEnrollmentAce' -Tag 'Unit' {

    BeforeAll {
        $EnrollmentGuid = [System.Guid]::new('0e10c968-78fb-11d2-90d4-00c04f79dc55')
        $AllGuid        = [System.Guid]::new('00000000-0000-0000-0000-000000000000')

        function New-EnrollmentMockAce {
            param(
                [System.DirectoryServices.ActiveDirectoryRights]
                $Rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [string]$AccessControlType = 'Allow',
                [System.Guid]$ObjectTypeGuid = [System.Guid]::new('0e10c968-78fb-11d2-90d4-00c04f79dc55'),
                [string]$Identity = 'S-1-5-21-1-2-3-999'
            )
            $sid = [System.Security.Principal.SecurityIdentifier]::new($Identity)
            [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                $sid,
                $Rights,
                [System.Security.AccessControl.AccessControlType]::$AccessControlType,
                $ObjectTypeGuid,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,
                [System.Guid]::Empty
            )
        }
    }

    It 'should return a [bool]' {
        $ace = New-EnrollmentMockAce
        Test-IsEnrollmentAce -Ace $ace | Should -BeOfType [bool]
    }

    It 'should return $true for Allow + ExtendedRight + Certificate-Enrollment GUID' {
        $ace = New-EnrollmentMockAce -Rights ExtendedRight -ObjectTypeGuid $EnrollmentGuid
        Test-IsEnrollmentAce -Ace $ace | Should -BeTrue
    }

    It 'should return $true for Allow + ExtendedRight + all-zeros GUID (applies to all types)' {
        $ace = New-EnrollmentMockAce -Rights ExtendedRight -ObjectTypeGuid $AllGuid
        Test-IsEnrollmentAce -Ace $ace | Should -BeTrue
    }

    It 'should return $true for Allow + GenericAll + Certificate-Enrollment GUID' {
        $ace = New-EnrollmentMockAce -Rights GenericAll -ObjectTypeGuid $EnrollmentGuid
        Test-IsEnrollmentAce -Ace $ace | Should -BeTrue
    }

    It 'should return $true for Allow + GenericAll + all-zeros GUID' {
        $ace = New-EnrollmentMockAce -Rights GenericAll -ObjectTypeGuid $AllGuid
        Test-IsEnrollmentAce -Ace $ace | Should -BeTrue
    }

    It 'should return $false for Deny ACE with ExtendedRight and enrollment GUID' {
        $ace = New-EnrollmentMockAce -Rights ExtendedRight -AccessControlType Deny -ObjectTypeGuid $EnrollmentGuid
        Test-IsEnrollmentAce -Ace $ace | Should -BeFalse
    }

    It 'should return $false for Allow + GenericRead (no enrollment right)' {
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-999')
        $ace = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $sid,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        Test-IsEnrollmentAce -Ace $ace | Should -BeFalse
    }

    It 'should return $false for Allow + ExtendedRight with a non-enrollment GUID' {
        $otherGuid = [System.Guid]::new('a05b8cc2-17bc-4802-a710-e7c15ab866a2')
        $ace = New-EnrollmentMockAce -Rights ExtendedRight -ObjectTypeGuid $otherGuid
        Test-IsEnrollmentAce -Ace $ace | Should -BeFalse
    }

    It 'should accept pipeline input and return one bool per ACE' {
        $ace1 = New-EnrollmentMockAce -Rights ExtendedRight -ObjectTypeGuid $EnrollmentGuid
        $ace2 = New-EnrollmentMockAce -Rights ExtendedRight -ObjectTypeGuid ([System.Guid]::new('a05b8cc2-17bc-4802-a710-e7c15ab866a2'))
        $results = @($ace1, $ace2) | Test-IsEnrollmentAce
        $results.Count | Should -Be 2
        $results[0] | Should -BeTrue
        $results[1] | Should -BeFalse
    }
}
