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

Describe 'Get-IssueCount' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:IssueStore = @{}
        }

        Context 'Empty store' {
            It 'should return 0 when IssueStore is empty' {
                Get-IssueCount -Technique 'ESC1' | Should -Be 0
            }

            It 'should return 0 for any technique when IssueStore is empty' {
                Get-IssueCount -Technique 'ESC99' | Should -Be 0
            }
        }

        Context 'Technique not present' {
            It 'should return 0 when the DN exists but has a different technique' {
                $issue = New-MockLS2Issue -Overrides @{ Technique = 'ESC2' }
                $script:IssueStore[$issue.DistinguishedName] = @{ 'ESC2' = @($issue) }
                Get-IssueCount -Technique 'ESC1' | Should -Be 0
            }
        }

        Context 'Single DN with matching technique' {
            It 'should return 1 for a single issue' {
                $issue = New-MockLS2Issue
                $script:IssueStore[$issue.DistinguishedName] = @{ 'ESC1' = @($issue) }
                Get-IssueCount -Technique 'ESC1' | Should -Be 1
            }

            It 'should return 2 for two issues under the same DN and technique' {
                $issue1 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-500' }
                $issue2 = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-501' }
                $script:IssueStore[$issue1.DistinguishedName] = @{ 'ESC1' = @($issue1, $issue2) }
                Get-IssueCount -Technique 'ESC1' | Should -Be 2
            }
        }

        Context 'Multiple DNs' {
            It 'should sum issues across multiple DNs for the same technique' {
                $dn1 = 'CN=Template1,CN=Certificate Templates,DC=contoso,DC=com'
                $dn2 = 'CN=Template2,CN=Certificate Templates,DC=contoso,DC=com'
                $issue1 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn1 }
                $issue2 = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn2 }
                $script:IssueStore[$dn1] = @{ 'ESC1' = @($issue1) }
                $script:IssueStore[$dn2] = @{ 'ESC1' = @($issue2) }
                Get-IssueCount -Technique 'ESC1' | Should -Be 2
            }

            It 'should count only the requested technique even when other techniques exist' {
                $dn1 = 'CN=Template1,CN=Certificate Templates,DC=contoso,DC=com'
                $esc1Issue = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn1; Technique = 'ESC1' }
                $esc2Issue = New-MockLS2Issue -Overrides @{ DistinguishedName = $dn1; Technique = 'ESC2' }
                $script:IssueStore[$dn1] = @{
                    'ESC1' = @($esc1Issue)
                    'ESC2' = @($esc2Issue, $esc2Issue)
                }
                Get-IssueCount -Technique 'ESC1' | Should -Be 1
            }
        }

        Context 'Return type' {
            It 'should return an [int]' {
                $result = Get-IssueCount -Technique 'ESC1'
                $result | Should -BeOfType [int]
            }
        }
    }
}
