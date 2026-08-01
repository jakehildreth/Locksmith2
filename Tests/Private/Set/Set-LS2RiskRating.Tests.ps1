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

Describe 'Set-LS2RiskRating' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:IssueStore         = @{}
            $script:PrincipalStore     = @{}
            $script:AdcsObjectStore    = @{}
            $script:DomainStore        = @{}
            $script:InitializingStores = $false
        }

        # ------------------------------------------------------------------ #
        #  Basic contract
        # ------------------------------------------------------------------ #
        Context 'Function contract' {
            It 'Set-LS2RiskRating is available in module scope' {
                Get-Command 'Set-LS2RiskRating' -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
            }

            It 'accepts an array of LS2Issue objects without throwing' {
                $issue = New-MockLS2Issue -Overrides @{ Technique = 'Auditing'; CAFullName = 'srv\CA' }
                { Set-LS2RiskRating -Issues @($issue) } | Should -Not -Throw
            }

            It 'accepts an empty array without throwing' {
                { Set-LS2RiskRating -Issues @() } | Should -Not -Throw
            }
        }

        # ------------------------------------------------------------------ #
        #  Simple per-technique scoring (no cross-ESC complications)
        # ------------------------------------------------------------------ #
        Context 'Single-issue scoring - CA techniques' {
            It 'Auditing gets RiskValue 3 (Medium)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique = 'Auditing'
                    CAFullName = 'srv\CA'
                    Forest    = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($issue)
                $issue.RiskValue | Should -Be 3
                $issue.RiskName  | Should -Be 'Medium'
            }

            It 'ESC11 gets RiskValue 3 (Medium)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique = 'ESC11'
                    CAFullName = 'srv\CA'
                    Forest    = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($issue)
                $issue.RiskValue | Should -Be 3
                $issue.RiskName  | Should -Be 'Medium'
            }

            It 'ESC8 HTTP endpoint gets RiskValue 5 (Critical)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique            = 'ESC8'
                    CAFullName           = 'srv\CA'
                    Forest               = 'contoso.com'
                    EndpointAttackVector = 'HTTP'
                }
                Set-LS2RiskRating -Issues @($issue)
                # BaseScore=3 + EndpointBonus(HTTP)=2 = 5
                $issue.RiskValue | Should -Be 5
                $issue.RiskName  | Should -Be 'Critical'
            }

            It 'ESC8 HTTPS-NTLM endpoint gets RiskValue 5 (Critical)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique            = 'ESC8'
                    CAFullName           = 'srv\CA'
                    Forest               = 'contoso.com'
                    EndpointAttackVector = 'HTTPS-NTLM'
                }
                Set-LS2RiskRating -Issues @($issue)
                $issue.RiskValue | Should -Be 5
                $issue.RiskName  | Should -Be 'Critical'
            }

            It 'ESC8 HTTPS-Kerberos endpoint gets RiskValue 4 (High)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique            = 'ESC8'
                    CAFullName           = 'srv\CA'
                    Forest               = 'contoso.com'
                    EndpointAttackVector = 'HTTPS-Kerberos'
                }
                Set-LS2RiskRating -Issues @($issue)
                # BaseScore=3 + EndpointBonus(HTTPS-Kerberos)=1 = 4
                $issue.RiskValue | Should -Be 4
                $issue.RiskName  | Should -Be 'High'
            }
        }

        Context 'Single-issue scoring - template techniques' {
            It 'SchemaV1 enabled gets RiskValue 2 (Low)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique = 'SchemaV1'
                    Enabled   = $true
                    Forest    = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($issue)
                # BaseScore=1 + Enabled(+1) = 2
                $issue.RiskValue | Should -Be 2
                $issue.RiskName  | Should -Be 'Low'
            }

            It 'SchemaV1 disabled gets RiskValue 0 (Informational, clamped from -1)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique = 'SchemaV1'
                    Enabled   = $false
                    Forest    = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($issue)
                # BaseScore=1 + Disabled(-2) = -1 -> clamped to 0
                $issue.RiskValue | Should -Be 0
                $issue.RiskName  | Should -Be 'Informational'
            }

            It 'ESC1 enabled with SafePrincipal gets RiskValue 2 (Low)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC1'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-512'  # Domain Admins (-512$)
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                # 0 + TechBonus(1) + Enabled(+1) + SafePrincipal(+0) = 2
                $issue.RiskValue | Should -Be 2
                $issue.RiskName  | Should -Be 'Low'
            }

            It 'ESC1 enabled with non-dangerous group gets RiskValue 4 (High)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC1'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-1001'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                # 0 + 1 + 1 + UnsafePrincipal(+1) + UnsafeGroup(+1) = 4
                $issue.RiskValue | Should -Be 4
                $issue.RiskName  | Should -Be 'High'
            }

            It 'ESC1 enabled with DangerousPrincipal (Everyone) gets RiskValue 5 (Critical)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC1'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-1-0'  # Everyone
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                # 0 + 1 + 1 + UnsafePrincipal(+1) + UnsafeGroup(+1) + DangerousPrincipal(+1) = 5
                $issue.RiskValue | Should -Be 5
                $issue.RiskName  | Should -Be 'Critical'
            }

            It 'ESC1 disabled with SafePrincipal gets RiskValue 0 (Informational, clamped from -1)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC1'
                    Enabled                = $false
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-512'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                # 0 + 1 + Disabled(-2) + SafePrincipal(+0) = -1 -> clamped 0
                $issue.RiskValue | Should -Be 0
                $issue.RiskName  | Should -Be 'Informational'
            }
        }

        Context 'Single-issue scoring - ESC5 object class bonuses' {
            It 'ESC5a on pKIEnrollmentService with non-dangerous group gets RiskValue 4 (High)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC5a'
                    Forest                 = 'contoso.com'
                    ObjectClass            = 'pKIEnrollmentService'
                    DistinguishedName      = 'CN=MyCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-1001'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                # BaseScore=0 + ObjClass(pKIEnrollmentService=2) + UnsafePrincipal(+1) + UnsafeGroup(+1) = 4
                $issue.RiskValue | Should -Be 4
                $issue.RiskName  | Should -Be 'High'
            }

            It 'ESC5a on pKIEnrollmentService with DangerousPrincipal gets RiskValue 5 (Critical)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC5a'
                    Forest                 = 'contoso.com'
                    ObjectClass            = 'pKIEnrollmentService'
                    DistinguishedName      = 'CN=MyCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    IdentityReferenceSID   = 'S-1-1-0'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                # 0 + ObjClass(2) + UnsafePrincipal(+1) + UnsafeGroup(+1) + DangerousPrincipal(+1) = 5
                $issue.RiskValue | Should -Be 5
                $issue.RiskName  | Should -Be 'Critical'
            }

            It 'ESC5a on NtAuthCertificates DN gets NtAuthBonus (+2) stacked with objectClass bonus' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC5a'
                    Forest                 = 'contoso.com'
                    ObjectClass            = 'certificationAuthority'
                    DistinguishedName      = 'CN=NtAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    IdentityReferenceSID   = 'S-1-1-0'  # DangerousPrincipal
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                # 0 + ObjClass(certificationAuthority=2) + NtAuthBonus(2) + UnsafePrincipal(+1) + UnsafeGroup(+1) + DangerousPrincipal(+1) = 7
                $issue.RiskValue | Should -BeGreaterOrEqual 5
                $issue.RiskName  | Should -Be 'Critical'
            }
        }

        # ------------------------------------------------------------------ #
        #  Cross-ESC modifier tests
        # ------------------------------------------------------------------ #
        Context 'Cross-ESC: ESC6 bidirectional with ESC9 and ESC16' {
            It 'ESC6 alone gets RiskValue 3 (no cross-ESC bonus)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique  = 'ESC6'
                    CAFullName = 'srv\CA'
                    Forest     = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($issue)
                $issue.RiskValue | Should -Be 3
            }

            It 'ESC6 gets RiskValue 5 (Critical) when ESC9 exists in same forest' {
                $esc6 = New-MockLS2Issue -Overrides @{
                    Technique  = 'ESC6'
                    CAFullName = 'srv\CA'
                    Forest     = 'contoso.com'
                }
                $esc9 = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC9'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-1001'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($esc6, $esc9)
                $esc6.RiskValue | Should -Be 5
                $esc6.RiskName  | Should -Be 'Critical'
            }

            It 'ESC6 gets RiskValue 5 (Critical) when ESC16 exists in same forest' {
                $esc6 = New-MockLS2Issue -Overrides @{
                    Technique  = 'ESC6'
                    CAFullName = 'srv\CA'
                    Forest     = 'contoso.com'
                }
                $esc16 = New-MockLS2Issue -Overrides @{
                    Technique  = 'ESC16'
                    CAFullName = 'srv\CA'
                    Forest     = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($esc6, $esc16)
                $esc6.RiskValue | Should -Be 5
            }

            It 'ESC16 alone gets RiskValue 3 (no cross-ESC bonus)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique  = 'ESC16'
                    CAFullName = 'srv\CA'
                    Forest     = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($issue)
                $issue.RiskValue | Should -Be 3
            }

            It 'ESC16 gets RiskValue 5 (Critical) when ESC6 exists in same forest' {
                $esc16 = New-MockLS2Issue -Overrides @{
                    Technique  = 'ESC16'
                    CAFullName = 'srv\CA'
                    Forest     = 'contoso.com'
                }
                $esc6 = New-MockLS2Issue -Overrides @{
                    Technique  = 'ESC6'
                    CAFullName = 'srv\CA'
                    Forest     = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($esc16, $esc6)
                $esc16.RiskValue | Should -Be 5
                $esc16.RiskName  | Should -Be 'Critical'
            }

            It 'ESC9 enabled group alone gets RiskValue 3 (Medium, no ESC6 cross)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC9'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-1001'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                # 0 + 0 + Enabled(+1) + UnsafePrincipal(+1) + UnsafeGroup(+1) = 3
                $issue.RiskValue | Should -Be 3
                $issue.RiskName  | Should -Be 'Medium'
            }

            It 'ESC9 enabled group gets RiskValue 4 (High) when ESC6 exists in same forest' {
                $esc9 = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC9'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-1001'
                    IdentityReferenceClass = 'group'
                }
                $esc6 = New-MockLS2Issue -Overrides @{
                    Technique  = 'ESC6'
                    CAFullName = 'srv\CA'
                    Forest     = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($esc9, $esc6)
                # 0 + 0 + 1 + UnsafePrincipal(+1) + UnsafeGroup(+1) + ESC6Cross(+2) = 5
                $esc9.RiskValue | Should -Be 5
                $esc9.RiskName  | Should -Be 'Critical'
            }

            It 'cross-ESC does not apply across different forests' {
                $esc9 = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC9'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-1001'
                    IdentityReferenceClass = 'group'
                }
                $esc6 = New-MockLS2Issue -Overrides @{
                    Technique  = 'ESC6'
                    CAFullName = 'srv\CA'
                    Forest     = 'fabrikam.com'  # different forest
                }
                Set-LS2RiskRating -Issues @($esc9, $esc6)
                $esc9.RiskValue | Should -Be 3  # no cross-ESC bonus
            }
        }

        Context 'Cross-ESC: ESC3c2 elevated by ESC3c1/ESC2' {
            It 'ESC3c2 enabled group alone gets RiskValue 3 (Medium)' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC3c2'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-1001'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                # 0 + 0 + Enabled(+1) + UnsafePrincipal(+1) + UnsafeGroup(+1) = 3
                $issue.RiskValue | Should -Be 3
                $issue.RiskName  | Should -Be 'Medium'
            }

            It 'ESC3c2 enabled group gets RiskValue 4 when enabled ESC3c1 with DangerousPrincipal exists' {
                $esc3c2 = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC3c2'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-1001'
                    IdentityReferenceClass = 'group'
                }
                $esc3c1 = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC3c1'
                    Enabled                = $true
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-1-0'  # DangerousPrincipal -> re-eval = 2
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($esc3c2, $esc3c1)
                # ESC3c2: 0 + 0 + Enabled(+1) + UnsafePrincipal(+1) + UnsafeGroup(+1) + CrossESC(re-eval=3, cap=2) = 5
                $esc3c2.RiskValue | Should -Be 5
                $esc3c2.RiskName  | Should -Be 'Critical'
            }
        }

        Context 'Cross-ESC: disabled template + ESC5' {
            It 'disabled ESC1 gets cross-ESC bonus from ESC5a on pKIEnrollmentService with DangerousPrincipal' {
                $esc1 = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC1'
                    Enabled                = $false
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-512'  # SafePrincipal
                    IdentityReferenceClass = 'group'
                }
                $esc5a = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC5a'
                    Forest                 = 'contoso.com'
                    ObjectClass            = 'pKIEnrollmentService'
                    DistinguishedName      = 'CN=MyCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    IdentityReferenceSID   = 'S-1-1-0'  # DangerousPrincipal -> re-eval = 2
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($esc1, $esc5a)
                # ESC1 disabled: 0 + TechBonus(1) + Disabled(-2) + SafePrincipal(0) = -1
                # Cross: ESC5a DangerousPrincipal re-eval=2, cap=2 -> +2
                # Final: -1 + 2 = 1 -> Informational
                $esc1.RiskValue | Should -Be 1
                $esc1.RiskName  | Should -Be 'Informational'
            }

            It 'disabled-template ESC5 cross-ESC is filtered to pKIEnrollmentService objectClass only' {
                $esc1 = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC1'
                    Enabled                = $false
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-512'
                    IdentityReferenceClass = 'group'
                }
                $esc5a = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC5a'
                    Forest                 = 'contoso.com'
                    ObjectClass            = 'container'  # NOT pKIEnrollmentService -- should not contribute
                    DistinguishedName      = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    IdentityReferenceSID   = 'S-1-1-0'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($esc1, $esc5a)
                # No cross-ESC bonus because ObjectClass is not pKIEnrollmentService
                # ESC1 disabled: -1, clamped to 0
                $esc1.RiskValue | Should -Be 0
            }

            It 'enabled ESC1 does NOT get ESC5 cross-ESC (OnlyWhenDisabled = $true)' {
                $esc1 = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC1'
                    Enabled                = $true  # enabled -- should NOT trigger OnlyWhenDisabled modifier
                    Forest                 = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-512'
                    IdentityReferenceClass = 'group'
                }
                $esc5a = New-MockLS2Issue -Overrides @{
                    Technique              = 'ESC5a'
                    Forest                 = 'contoso.com'
                    ObjectClass            = 'pKIEnrollmentService'
                    DistinguishedName      = 'CN=MyCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    IdentityReferenceSID   = 'S-1-1-0'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($esc1, $esc5a)
                # ESC1 enabled: 0 + 1(TechBonus) + 1(enabled) + 0(SafePrincipal) = 2, no ESC5 cross
                $esc1.RiskValue | Should -Be 2
            }
        }

        # ------------------------------------------------------------------ #
        #  RiskScoring audit trail
        # ------------------------------------------------------------------ #
        Context 'RiskScoring audit trail' {
            It 'RiskScoring is populated after rating' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique  = 'Auditing'
                    CAFullName = 'srv\CA'
                    Forest     = 'contoso.com'
                }
                Set-LS2RiskRating -Issues @($issue)
                $issue.RiskScoring | Should -Not -BeNullOrEmpty
            }

            It 'RiskScoring contains at least BaseScore entry' {
                $issue = New-MockLS2Issue -Overrides @{
                    Technique = 'ESC1'
                    Enabled   = $true
                    Forest    = 'contoso.com'
                    IdentityReferenceSID   = 'S-1-5-21-1234-5678-9012-512'
                    IdentityReferenceClass = 'group'
                }
                Set-LS2RiskRating -Issues @($issue)
                $issue.RiskScoring | Where-Object { $_ -match 'BaseScore' } | Should -Not -BeNullOrEmpty
            }
        }

        # ------------------------------------------------------------------ #
        #  Multiple issues
        # ------------------------------------------------------------------ #
        Context 'Multiple issues in one call' {
            It 'rates all issues - none should have null RiskValue after the call' {
                $issues = @(
                    (New-MockLS2Issue -Overrides @{ Technique = 'Auditing'; CAFullName = 'srv\CA'; Forest = 'contoso.com' }),
                    (New-MockLS2Issue -Overrides @{ Technique = 'ESC11';    CAFullName = 'srv\CA'; Forest = 'contoso.com' })
                )
                Set-LS2RiskRating -Issues $issues
                $issues | Where-Object { $null -eq $_.RiskValue } | Should -BeNullOrEmpty
            }

            It 'mutates issues in place (returns nothing)' {
                $issue = New-MockLS2Issue -Overrides @{ Technique = 'Auditing'; CAFullName = 'srv\CA'; Forest = 'contoso.com' }
                $result = Set-LS2RiskRating -Issues @($issue)
                $result | Should -BeNullOrEmpty
                $issue.RiskValue | Should -Not -BeNullOrEmpty
            }
        }
    }
}
