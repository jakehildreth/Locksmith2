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
}

Describe 'Get-PrincipalRiskBonus' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        # ------------------------------------------------------------------ #
        #  SafePrincipal — always early-return, Score=0, Labels=@()
        # ------------------------------------------------------------------ #
        Context 'SafePrincipal' {
            It 'Domain Admins (-512$) returns Score=0 and empty Labels' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-512' -IdentityReferenceClass 'group'
                $result.Score  | Should -Be 0
                $result.Labels | Should -BeNullOrEmpty
            }

            It 'Enterprise Admins (-519$) returns Score=0 and empty Labels' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-519' -IdentityReferenceClass 'group'
                $result.Score  | Should -Be 0
                $result.Labels | Should -BeNullOrEmpty
            }

            It 'SYSTEM (-18$) returns Score=0 and empty Labels' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-18' -IdentityReferenceClass 'user'
                $result.Score  | Should -Be 0
                $result.Labels | Should -BeNullOrEmpty
            }
        }

        # ------------------------------------------------------------------ #
        #  Unsafe individual — not safe, not group, not dangerous
        # ------------------------------------------------------------------ #
        Context 'Unsafe individual' {
            It 'returns Score=1 with only UnsafePrincipal label' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-1001' -IdentityReferenceClass 'user'
                $result.Score  | Should -Be 1
                $result.Labels | Should -HaveCount 1
                $result.Labels | Should -Contain 'UnsafePrincipal: +1'
            }

            It 'empty SID with user class returns Score=1' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID '' -IdentityReferenceClass 'user'
                $result.Score  | Should -Be 1
                $result.Labels | Should -Contain 'UnsafePrincipal: +1'
            }
        }

        # ------------------------------------------------------------------ #
        #  Unsafe group — not safe, class=group, not dangerous
        # ------------------------------------------------------------------ #
        Context 'Unsafe group' {
            It 'returns Score=2 with UnsafePrincipal and UnsafeGroup labels' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-1001' -IdentityReferenceClass 'group'
                $result.Score  | Should -Be 2
                $result.Labels | Should -HaveCount 2
                $result.Labels | Should -Contain 'UnsafePrincipal: +1'
                $result.Labels | Should -Contain 'UnsafeGroup: +1'
            }

            It 'does not include DangerousPrincipal label for a non-dangerous group' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-1001' -IdentityReferenceClass 'group'
                $result.Labels | Should -Not -Contain 'DangerousPrincipal: +1'
            }
        }

        # ------------------------------------------------------------------ #
        #  DangerousPrincipal individual — not group
        # ------------------------------------------------------------------ #
        Context 'DangerousPrincipal individual' {
            It 'Authenticated Users (S-1-5-11) with user class returns Score=3' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-11' -IdentityReferenceClass 'user'
                $result.Score  | Should -Be 3
                $result.Labels | Should -HaveCount 2
                $result.Labels | Should -Contain 'UnsafePrincipal: +1'
                $result.Labels | Should -Contain 'DangerousPrincipal: +2'
            }

            It 'does not include UnsafeGroup label for a dangerous principal (any class)' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-11' -IdentityReferenceClass 'user'
                $result.Labels | Should -Not -Contain 'UnsafeGroup: +1'
            }
        }

        # ------------------------------------------------------------------ #
        #  DangerousPrincipal group — group modifier does NOT apply; Score=3 flat
        # ------------------------------------------------------------------ #
        Context 'DangerousPrincipal group' {
            It 'Everyone (S-1-1-0) with group class returns Score=3 (no UnsafeGroup modifier)' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-1-0' -IdentityReferenceClass 'group'
                $result.Score  | Should -Be 3
                $result.Labels | Should -HaveCount 2
                $result.Labels | Should -Contain 'UnsafePrincipal: +1'
                $result.Labels | Should -Contain 'DangerousPrincipal: +2'
            }

            It 'Everyone (S-1-1-0) with group class does NOT get UnsafeGroup label' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-1-0' -IdentityReferenceClass 'group'
                $result.Labels | Should -Not -Contain 'UnsafeGroup: +1'
            }

            It 'Domain Users (-513$) with group class returns Score=3' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-513' -IdentityReferenceClass 'group'
                $result.Score  | Should -Be 3
                $result.Labels | Should -Contain 'DangerousPrincipal: +2'
            }

            It 'Domain Computers (-515$) with group class returns Score=3' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-515' -IdentityReferenceClass 'group'
                $result.Score  | Should -Be 3
                $result.Labels | Should -Contain 'DangerousPrincipal: +2'
            }

            It 'BUILTIN\Users (S-1-5-32-545) with group class returns Score=3 with 2 labels' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-32-545' -IdentityReferenceClass 'group'
                $result.Score  | Should -Be 3
                $result.Labels | Should -HaveCount 2
            }
        }

        # ------------------------------------------------------------------ #
        #  Label ordering
        # ------------------------------------------------------------------ #
        Context 'Label ordering' {
            It 'dangerous principal labels are ordered: UnsafePrincipal, DangerousPrincipal' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-1-0' -IdentityReferenceClass 'group'
                $result.Labels[0] | Should -Be 'UnsafePrincipal: +1'
                $result.Labels[1] | Should -Be 'DangerousPrincipal: +2'
            }

            It 'unsafe group labels are ordered: UnsafePrincipal, UnsafeGroup' {
                $result = Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-1001' -IdentityReferenceClass 'group'
                $result.Labels[0] | Should -Be 'UnsafePrincipal: +1'
                $result.Labels[1] | Should -Be 'UnsafeGroup: +1'
            }
        }
    }
}
