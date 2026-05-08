#requires -Version 5.1
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests' 'Shared' 'TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Test-IssueExists' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:IssueStore = @{}
        }

        It 'should return $false when IssueStore is empty' {
            $issue = New-MockLS2Issue
            Test-IssueExists -Issue $issue -DistinguishedName $issue.DistinguishedName -Technique 'ESC1' |
                Should -BeFalse
        }

        It 'should return $false when the DN is not in IssueStore' {
            $issue = New-MockLS2Issue
            $script:IssueStore['CN=OtherObject,DC=contoso,DC=com'] = @{ 'ESC1' = @($issue) }
            Test-IssueExists -Issue $issue -DistinguishedName $issue.DistinguishedName -Technique 'ESC1' |
                Should -BeFalse
        }

        It 'should return $false when DN exists but technique key is absent' {
            $issue = New-MockLS2Issue
            $script:IssueStore[$issue.DistinguishedName] = @{ 'ESC2' = @($issue) }
            Test-IssueExists -Issue $issue -DistinguishedName $issue.DistinguishedName -Technique 'ESC1' |
                Should -BeFalse
        }

        It 'should return $true when an identical issue already exists for the DN and technique' {
            $issue = New-MockLS2Issue
            $script:IssueStore[$issue.DistinguishedName] = @{ 'ESC1' = @($issue) }
            Test-IssueExists -Issue $issue -DistinguishedName $issue.DistinguishedName -Technique 'ESC1' |
                Should -BeTrue
        }

        It 'should return $false when stored issue has a different IdentityReferenceSID' {
            $issue1 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-500' }
            $issue2 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-501' }
            $script:IssueStore[$issue1.DistinguishedName] = @{ 'ESC1' = @($issue1) }
            Test-IssueExists -Issue $issue2 -DistinguishedName $issue2.DistinguishedName -Technique 'ESC1' |
                Should -BeFalse
        }

        It 'should return $false when stored issue has a different Owner' {
            $issue1 = New-MockLS2Issue -Overrides @{ Owner = 'CONTOSO\EnterpriseAdmins' }
            $issue2 = New-MockLS2Issue -Overrides @{ Owner = 'CONTOSO\SomeoneElse' }
            $script:IssueStore[$issue1.DistinguishedName] = @{ 'ESC1' = @($issue1) }
            Test-IssueExists -Issue $issue2 -DistinguishedName $issue2.DistinguishedName -Technique 'ESC1' |
                Should -BeFalse
        }

        It 'should return $true when one of multiple stored issues matches' {
            $issue1 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-500' }
            $issue2 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-501' }
            $issueToFind = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-501' }
            $script:IssueStore[$issue1.DistinguishedName] = @{ 'ESC1' = @($issue1, $issue2) }
            Test-IssueExists -Issue $issueToFind -DistinguishedName $issueToFind.DistinguishedName -Technique 'ESC1' |
                Should -BeTrue
        }

        It 'should return a [bool]' {
            $issue = New-MockLS2Issue
            $result = Test-IssueExists -Issue $issue -DistinguishedName $issue.DistinguishedName -Technique 'ESC1'
            $result | Should -BeOfType [bool]
        }
    }
}
