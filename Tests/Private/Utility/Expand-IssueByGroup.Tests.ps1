#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Expand-IssueByGroup' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:PrincipalStore = @{}
        }

        Context 'Issue with no IdentityReferenceSID' {
            It 'should return the original issue unchanged when IdentityReferenceSID is empty' {
                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = '' }
                $result = Expand-IssueByGroup -Issue $issue
                $result.Count | Should -Be 1
                $result[0].Technique | Should -Be $issue.Technique
            }

            It 'should return the original issue unchanged when IdentityReferenceSID is null' {
                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = $null }
                $result = Expand-IssueByGroup -Issue $issue
                $result.Count | Should -Be 1
            }
        }

        Context 'Principal not in PrincipalStore' {
            It 'should return the original issue when principal SID is not in PrincipalStore' {
                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = 'S-1-5-21-1-2-3-500' }
                # PrincipalStore is empty
                $result = Expand-IssueByGroup -Issue $issue
                $result.Count | Should -Be 1
                $result[0].IdentityReferenceSID | Should -Be 'S-1-5-21-1-2-3-500'
            }
        }

        Context 'Principal is a user (not a group)' {
            It 'should return the original issue when principal objectClass is user' {
                $sid = 'S-1-5-21-1-2-3-1001'
                $principal = New-MockLS2Principal -Properties @{ objectClass = 'user'; objectSid = $sid }
                $script:PrincipalStore[$sid] = $principal

                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = $sid }
                $result = Expand-IssueByGroup -Issue $issue
                $result.Count | Should -Be 1
                $result[0].IdentityReferenceSID | Should -Be $sid
            }

            It 'should not call Expand-GroupMembership for non-group principals' {
                $sid = 'S-1-5-21-1-2-3-1001'
                $principal = New-MockLS2Principal -Properties @{ objectClass = 'user'; objectSid = $sid }
                $script:PrincipalStore[$sid] = $principal
                Mock 'Expand-GroupMembership' { @() }

                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = $sid }
                $null = Expand-IssueByGroup -Issue $issue
                Should -Invoke 'Expand-GroupMembership' -Times 0
            }
        }

        Context 'Principal is a group with members' {
            It 'should call Expand-GroupMembership for group principals' {
                $groupSid = 'S-1-5-21-1-2-3-513'
                $memberSid = 'S-1-5-21-1-2-3-1001'
                $group = New-MockLS2Principal -Properties @{ objectClass = 'group'; objectSid = $groupSid; NTAccountName = 'CONTOSO\Domain Users' }
                $member = New-MockLS2Principal -Properties @{ objectClass = 'user'; objectSid = $memberSid; NTAccountName = 'CONTOSO\jdoe' }
                $script:PrincipalStore[$groupSid] = $group
                $script:PrincipalStore[$memberSid] = $member

                Mock 'Expand-GroupMembership' { @($groupSid, $memberSid) }

                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = $groupSid; IdentityReference = 'CONTOSO\Domain Users' }
                $null = Expand-IssueByGroup -Issue $issue
                Should -Invoke 'Expand-GroupMembership' -Times 1
            }

            It 'should return member issues (not the group) by default' {
                $groupSid = 'S-1-5-21-1-2-3-513'
                $memberSid = 'S-1-5-21-1-2-3-1001'
                $group = New-MockLS2Principal -Properties @{ objectClass = 'group'; objectSid = $groupSid; NTAccountName = 'CONTOSO\Domain Users' }
                $member = New-MockLS2Principal -Properties @{ objectClass = 'user'; objectSid = $memberSid; NTAccountName = 'CONTOSO\jdoe' }
                $script:PrincipalStore[$groupSid] = $group
                $script:PrincipalStore[$memberSid] = $member

                Mock 'Expand-GroupMembership' { @($groupSid, $memberSid) }

                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = $groupSid; IdentityReference = 'CONTOSO\Domain Users' }
                $result = Expand-IssueByGroup -Issue $issue
                # Default: group SID filtered out from memberSids, so only 1 member
                $result.Count | Should -BeGreaterOrEqual 1
                $result | ForEach-Object { $_.IdentityReferenceSID | Should -Not -Be $groupSid }
            }

            It 'should include the group issue when -IncludeGroup is specified' {
                $groupSid = 'S-1-5-21-1-2-3-513'
                $memberSid = 'S-1-5-21-1-2-3-1001'
                $group = New-MockLS2Principal -Properties @{ objectClass = 'group'; objectSid = $groupSid; NTAccountName = 'CONTOSO\Domain Users' }
                $member = New-MockLS2Principal -Properties @{ objectClass = 'user'; objectSid = $memberSid; NTAccountName = 'CONTOSO\jdoe' }
                $script:PrincipalStore[$groupSid] = $group
                $script:PrincipalStore[$memberSid] = $member

                Mock 'Expand-GroupMembership' { @($groupSid, $memberSid) }

                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = $groupSid; IdentityReference = 'CONTOSO\Domain Users' }
                $result = Expand-IssueByGroup -Issue $issue -IncludeGroup
                # Should include group + member = 2 items minimum
                $result.Count | Should -BeGreaterOrEqual 2
            }
        }

        Context 'Group with no members' {
            It 'should set MemberCount to 0 and return original issue when group is empty' {
                $groupSid = 'S-1-5-21-1-2-3-513'
                $group = New-MockLS2Principal -Properties @{ objectClass = 'group'; objectSid = $groupSid; NTAccountName = 'CONTOSO\EmptyGroup' }
                $script:PrincipalStore[$groupSid] = $group

                # Expand-GroupMembership returns only the group SID itself — no members
                Mock 'Expand-GroupMembership' { @($groupSid) }

                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = $groupSid; IdentityReference = 'CONTOSO\EmptyGroup' }
                $result = Expand-IssueByGroup -Issue $issue
                $result[0].MemberCount | Should -Be 0
            }
        }

        Context 'Pipeline input' {
            It 'should accept LS2Issue objects via the pipeline' {
                $issue = New-MockLS2Issue -Overrides @{ IdentityReferenceSID = '' }
                $result = $issue | Expand-IssueByGroup
                $result.Count | Should -Be 1
            }
        }
    }
}
