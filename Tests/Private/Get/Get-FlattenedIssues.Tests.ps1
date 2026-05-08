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

Describe 'Get-FlattenedIssues' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:IssueStore = @{}
        }

        Context 'Empty IssueStore' {
            It 'should emit a warning and return nothing when IssueStore is empty' {
                $result = @(Get-FlattenedIssues -WarningVariable wv 3>&1 | Where-Object { $_ -is [LS2Issue] })
                $result.Count | Should -Be 0
            }
        }

        Context 'Single DN with single technique and single issue' {
            It 'should return exactly one LS2Issue object' {
                $issue = New-MockLS2Issue
                $script:IssueStore[$issue.DistinguishedName] = @{ 'ESC1' = @($issue) }
                $result = @(Get-FlattenedIssues)
                $result.Count | Should -Be 1
            }

            It 'should return the original LS2Issue object' {
                $issue = New-MockLS2Issue
                $script:IssueStore[$issue.DistinguishedName] = @{ 'ESC1' = @($issue) }
                $result = @(Get-FlattenedIssues)
                $result[0].Technique | Should -Be 'ESC1'
            }
        }

        Context 'Multiple techniques for one DN' {
            It 'should return issues from all techniques' {
                $dn = 'CN=Template1,CN=Certificate Templates,DC=contoso,DC=com'
                $issue1 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn; Technique = 'ESC1' }
                $issue2 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn; Technique = 'ESC2' }
                $script:IssueStore[$dn] = @{
                    'ESC1' = @($issue1)
                    'ESC2' = @($issue2)
                }
                $result = @(Get-FlattenedIssues)
                $result.Count | Should -Be 2
            }
        }

        Context 'Multiple DNs' {
            It 'should return issues from all DNs' {
                $dn1 = 'CN=Template1,CN=Certificate Templates,DC=contoso,DC=com'
                $dn2 = 'CN=Template2,CN=Certificate Templates,DC=contoso,DC=com'
                $issue1 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn1 }
                $issue2 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn2 }
                $script:IssueStore[$dn1] = @{ 'ESC1' = @($issue1) }
                $script:IssueStore[$dn2] = @{ 'ESC1' = @($issue2) }
                $result = @(Get-FlattenedIssues)
                $result.Count | Should -Be 2
            }
        }

        Context 'Multiple issues per DN/Technique' {
            It 'should return all individual issues in the array' {
                $dn = 'CN=Template1,CN=Certificate Templates,DC=contoso,DC=com'
                $issue1 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn; IdentityReferenceSID = 'S-1-5-21-1-2-3-500' }
                $issue2 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn; IdentityReferenceSID = 'S-1-5-21-1-2-3-501' }
                $script:IssueStore[$dn] = @{ 'ESC1' = @($issue1, $issue2) }
                $result = @(Get-FlattenedIssues)
                $result.Count | Should -Be 2
            }
        }

        Context 'Output type' {
            It 'should output LS2Issue objects' {
                $issue = New-MockLS2Issue
                $script:IssueStore[$issue.DistinguishedName] = @{ 'ESC1' = @($issue) }
                $result = @(Get-FlattenedIssues)
                $result[0].GetType().Name | Should -Be 'LS2Issue'
            }
        }
    }
}
