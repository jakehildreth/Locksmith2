#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Add-ToIssueStore' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:IssueStore = @{}
        }

        Context 'First issue for a new DN and Technique' {
            It 'should initialise the DN key in IssueStore' {
                $issue = New-MockLS2Issue
                Add-ToIssueStore -DistinguishedName $issue.DistinguishedName -Technique 'ESC1' -Issue $issue
                $script:IssueStore.ContainsKey($issue.DistinguishedName) | Should -BeTrue
            }

            It 'should initialise the Technique key inside the DN' {
                $issue = New-MockLS2Issue
                Add-ToIssueStore -DistinguishedName $issue.DistinguishedName -Technique 'ESC1' -Issue $issue
                $script:IssueStore[$issue.DistinguishedName].ContainsKey('ESC1') | Should -BeTrue
            }

            It 'should store exactly one issue in the array' {
                $issue = New-MockLS2Issue
                Add-ToIssueStore -DistinguishedName $issue.DistinguishedName -Technique 'ESC1' -Issue $issue
                $script:IssueStore[$issue.DistinguishedName]['ESC1'].Count | Should -Be 1
            }

            It 'should store the exact issue object' {
                $issue = New-MockLS2Issue
                Add-ToIssueStore -DistinguishedName $issue.DistinguishedName -Technique 'ESC1' -Issue $issue
                $script:IssueStore[$issue.DistinguishedName]['ESC1'][0].Technique | Should -Be 'ESC1'
            }
        }

        Context 'Subsequent issues for same DN and Technique' {
            It 'should append a second issue to the array' {
                $issue1 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-500' }
                $issue2 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-501' }
                Add-ToIssueStore -DistinguishedName $issue1.DistinguishedName -Technique 'ESC1' -Issue $issue1
                Add-ToIssueStore -DistinguishedName $issue2.DistinguishedName -Technique 'ESC1' -Issue $issue2
                $script:IssueStore[$issue1.DistinguishedName]['ESC1'].Count | Should -Be 2
            }

            It 'should preserve the first issue when appending a second' {
                $issue1 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-500' }
                $issue2 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-501' }
                Add-ToIssueStore -DistinguishedName $issue1.DistinguishedName -Technique 'ESC1' -Issue $issue1
                Add-ToIssueStore -DistinguishedName $issue2.DistinguishedName -Technique 'ESC1' -Issue $issue2
                $script:IssueStore[$issue1.DistinguishedName]['ESC1'][0].IdentityReferenceSID | Should -Be 'S-1-5-21-1-2-3-500'
            }
        }

        Context 'Multiple Techniques for the same DN' {
            It 'should create separate technique keys under the same DN' {
                $issue1 = New-MockLS2Issue -Overrides @{ Technique = 'ESC1' }
                $issue2 = New-MockLS2Issue -Overrides @{ Technique = 'ESC2' }
                Add-ToIssueStore -DistinguishedName $issue1.DistinguishedName -Technique 'ESC1' -Issue $issue1
                Add-ToIssueStore -DistinguishedName $issue2.DistinguishedName -Technique 'ESC2' -Issue $issue2
                $script:IssueStore[$issue1.DistinguishedName].Count | Should -Be 2
            }

            It 'should not mix issues between different techniques' {
                $issue1 = New-MockLS2Issue -Overrides @{ Technique = 'ESC1' }
                $issue2 = New-MockLS2Issue -Overrides @{ Technique = 'ESC2' }
                Add-ToIssueStore -DistinguishedName $issue1.DistinguishedName -Technique 'ESC1' -Issue $issue1
                Add-ToIssueStore -DistinguishedName $issue2.DistinguishedName -Technique 'ESC2' -Issue $issue2
                $script:IssueStore[$issue1.DistinguishedName]['ESC2'].Count | Should -Be 1
            }
        }

        Context 'Multiple DNs' {
            It 'should create separate DN keys for different distinguished names' {
                $dn1 = 'CN=Template1,CN=Certificate Templates,DC=contoso,DC=com'
                $dn2 = 'CN=Template2,CN=Certificate Templates,DC=contoso,DC=com'
                $issue1 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn1 }
                $issue2 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn2 }
                Add-ToIssueStore -DistinguishedName $dn1 -Technique 'ESC1' -Issue $issue1
                Add-ToIssueStore -DistinguishedName $dn2 -Technique 'ESC1' -Issue $issue2
                $script:IssueStore.Count | Should -Be 2
            }
        }

        Context 'Return value' {
            It 'should not return anything' {
                $issue = New-MockLS2Issue
                $result = Add-ToIssueStore -DistinguishedName $issue.DistinguishedName -Technique 'ESC1' -Issue $issue
                $result | Should -BeNullOrEmpty
            }
        }
    }
}
