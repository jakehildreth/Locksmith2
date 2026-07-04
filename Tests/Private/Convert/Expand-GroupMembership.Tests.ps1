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

Describe 'Expand-GroupMembership' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:PrincipalStore = @{}
            $script:ExpandedGroupCache = @{}
            $script:Server = 'dc.contoso.com'
            $script:Credential = $null
        }

        Context 'SID not in PrincipalStore' {
            It 'should return the input SID unchanged when not in PrincipalStore' {
                $result = Expand-GroupMembership -SidList @('S-1-5-21-1-2-3-500')
                $result | Should -Contain 'S-1-5-21-1-2-3-500'
            }

            It 'should not expand unknown SIDs' {
                $result = Expand-GroupMembership -SidList @('S-1-5-21-1-2-3-500')
                $result.Count | Should -Be 1
            }
        }

        Context 'Non-group principal' {
            It 'should return the user SID unchanged' {
                $sid = 'S-1-5-21-1-2-3-1001'
                $user = New-MockLS2Principal -Properties @{
                    objectSid  = $sid
                    objectClass = 'user'
                }
                $script:PrincipalStore[$sid] = $user

                $result = Expand-GroupMembership -SidList @($sid)
                $result | Should -Contain $sid
            }

            It 'should return exactly 1 item for a single user SID' {
                $sid = 'S-1-5-21-1-2-3-1001'
                $user = New-MockLS2Principal -Properties @{
                    objectSid  = $sid
                    objectClass = 'user'
                }
                $script:PrincipalStore[$sid] = $user

                $result = Expand-GroupMembership -SidList @($sid)
                $result.Count | Should -Be 1
            }

            It 'should return computer SID unchanged' {
                $sid = 'S-1-5-21-1-2-3-1100'
                $computer = New-MockLS2Principal -Properties @{
                    objectSid  = $sid
                    objectClass = 'computer'
                }
                $script:PrincipalStore[$sid] = $computer

                $result = Expand-GroupMembership -SidList @($sid)
                $result | Should -Contain $sid
            }
        }

        Context 'ExpandedGroupCache hit' {
            It 'should use cached member SIDs when group was previously expanded' {
                $groupSid = 'S-1-5-21-1-2-3-513'
                $memberSid = 'S-1-5-21-1-2-3-1001'

                $group = New-MockLS2Principal -Properties @{
                    objectSid  = $groupSid
                    objectClass = 'group'
                    distinguishedName = 'CN=Domain Users,CN=Users,DC=contoso,DC=com'
                    NTAccountName = 'CONTOSO\Domain Users'
                }
                $script:PrincipalStore[$groupSid] = $group

                # Pre-populate the cache (simulates a prior expansion)
                $script:ExpandedGroupCache[$groupSid] = @($memberSid)

                $result = Expand-GroupMembership -SidList @($groupSid)
                # Should include group SID and cached member SID
                $result | Should -Contain $groupSid
                $result | Should -Contain $memberSid
            }

            It 'should not call New-AuthenticatedDirectoryEntry when cache hit' {
                $groupSid = 'S-1-5-21-1-2-3-513'
                $memberSid = 'S-1-5-21-1-2-3-1001'

                $group = New-MockLS2Principal -Properties @{
                    objectSid  = $groupSid
                    objectClass = 'group'
                    distinguishedName = 'CN=Domain Users,CN=Users,DC=contoso,DC=com'
                }
                $script:PrincipalStore[$groupSid] = $group
                $script:ExpandedGroupCache[$groupSid] = @($memberSid)

                Mock 'New-AuthenticatedDirectoryEntry' { $null }

                Expand-GroupMembership -SidList @($groupSid) | Out-Null
                Should -Invoke 'New-AuthenticatedDirectoryEntry' -Times 0
            }
        }

        Context 'Multiple input SIDs' {
            It 'should return all non-group SIDs from a mixed input list' {
                $userSid1 = 'S-1-5-21-1-2-3-1001'
                $userSid2 = 'S-1-5-21-1-2-3-1002'
                $user1 = New-MockLS2Principal -Properties @{ objectSid = $userSid1; objectClass = 'user' }
                $user2 = New-MockLS2Principal -Properties @{ objectSid = $userSid2; objectClass = 'user' }
                $script:PrincipalStore[$userSid1] = $user1
                $script:PrincipalStore[$userSid2] = $user2

                $result = Expand-GroupMembership -SidList @($userSid1, $userSid2)
                $result | Should -Contain $userSid1
                $result | Should -Contain $userSid2
            }
        }
    }
}
