#requires -Version 5.1
BeforeAll {
    $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'LS2Issue class' -Tag 'Unit' {

    Describe 'Constructor' {
        It 'should construct from a minimal hashtable without throwing' {
            { New-MockLS2Issue } | Should -Not -Throw
        }

        It 'should set Technique from the hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ Technique = 'ESC6' }
            $issue.Technique | Should -Be 'ESC6'
        }

        It 'should set Forest from the hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ Forest = 'fabrikam.com' }
            $issue.Forest | Should -Be 'fabrikam.com'
        }

        It 'should set Name from the hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ Name = 'MyCA' }
            $issue.Name | Should -Be 'MyCA'
        }

        It 'should set IdentityReference from the hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ IdentityReference = 'CONTOSO\Admins' }
            $issue.IdentityReference | Should -Be 'CONTOSO\Admins'
        }

        It 'should set CAFullName from the hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ CAFullName = 'myserver\MyCA' }
            $issue.CAFullName | Should -Be 'myserver\MyCA'
        }

        It 'should set Issue, Fix, and Revert strings from the hashtable' {
            $issue = New-MockLS2Issue -Overrides @{
                Issue  = 'Vulnerability description.'
                Fix    = '# Fix script'
                Revert = '# Revert script'
            }
            $issue.Issue  | Should -Be 'Vulnerability description.'
            $issue.Fix    | Should -Be '# Fix script'
            $issue.Revert | Should -Be '# Revert script'
        }

        It 'should leave unprovided optional properties null' {
            $issue = New-MockLS2Issue
            $issue.CAFullName           | Should -BeNullOrEmpty
            $issue.IdentityReference    | Should -BeNullOrEmpty
            $issue.IdentityReferenceSID | Should -BeNullOrEmpty
            $issue.Owner                | Should -BeNullOrEmpty
            $issue.Enabled              | Should -BeNullOrEmpty
            $issue.MemberCount          | Should -BeNullOrEmpty
        }
    }

    Describe 'GetIdentifier()' {
        It 'should return "Technique: Name - IdentityReference" when IdentityReference is set' {
            $issue = New-MockLS2Issue -Overrides @{
                Technique         = 'ESC1'
                Name              = 'UserTemplate'
                IdentityReference = 'CONTOSO\Domain Users'
            }
            $issue.GetIdentifier() | Should -Be 'ESC1: UserTemplate - CONTOSO\Domain Users'
        }

        It 'should return "Technique: Name - Owner: <owner>" when only Owner is set' {
            $issue = New-MockLS2Issue -Overrides @{
                Technique = 'ESC4o'
                Name      = 'SomeTemplate'
                Owner     = 'CONTOSO\attacker'
            }
            $issue.GetIdentifier() | Should -Be 'ESC4o: SomeTemplate - Owner: CONTOSO\attacker'
        }

        It 'should return "Technique: Name" when neither IdentityReference nor Owner is set' {
            $issue = New-MockLS2Issue -Overrides @{
                Technique = 'ESC11'
                Name      = 'MyCA'
            }
            $issue.GetIdentifier() | Should -Be 'ESC11: MyCA'
        }

        It 'should prefer IdentityReference over Owner when both are set' {
            $issue = New-MockLS2Issue -Overrides @{
                Technique         = 'ESC1'
                Name              = 'T'
                IdentityReference = 'CONTOSO\Users'
                Owner             = 'CONTOSO\Admin'
            }
            $issue.GetIdentifier() | Should -BeLike '*CONTOSO\Users*'
            $issue.GetIdentifier() | Should -Not -BeLike '*Owner:*'
        }
    }

    Describe 'HasPrincipal()' {
        It 'should return true when IdentityReference is set' {
            $issue = New-MockLS2Issue -Overrides @{ IdentityReference = 'CONTOSO\Users' }
            $issue.HasPrincipal() | Should -BeTrue
        }

        It 'should return false when IdentityReference is null' {
            $issue = New-MockLS2Issue
            $issue.HasPrincipal() | Should -BeFalse
        }

        It 'should return false when IdentityReference is an empty string' -Tag 'EdgeCase' {
            $issue = New-MockLS2Issue -Overrides @{ IdentityReference = '' }
            $issue.HasPrincipal() | Should -BeFalse
        }
    }

    Describe 'IsTemplateIssue()' {
        It 'should return true when Enabled is $true' {
            $issue = New-MockLS2Issue -Overrides @{ Enabled = $true }
            $issue.IsTemplateIssue() | Should -BeTrue
        }

        It 'should return true when Enabled is $false (explicitly set, not null)' {
            $issue = New-MockLS2Issue -Overrides @{ Enabled = $false }
            $issue.IsTemplateIssue() | Should -BeTrue
        }

        It 'should return false when Enabled is null' {
            $issue = New-MockLS2Issue
            $issue.IsTemplateIssue() | Should -BeFalse
        }
    }

    Describe 'IsCAIssue()' {
        It 'should return true when CAFullName is set' {
            $issue = New-MockLS2Issue -Overrides @{ CAFullName = 'myserver\MyCA' }
            $issue.IsCAIssue() | Should -BeTrue
        }

        It 'should return false when CAFullName is null' {
            $issue = New-MockLS2Issue
            $issue.IsCAIssue() | Should -BeFalse
        }

        It 'should return false when CAFullName is an empty string' -Tag 'EdgeCase' {
            $issue = New-MockLS2Issue -Overrides @{ CAFullName = '' }
            $issue.IsCAIssue() | Should -BeFalse
        }
    }

    Describe 'Matches()' {
        BeforeAll {
            $script:BaseProps = @{
                Technique             = 'ESC1'
                DistinguishedName     = 'CN=T,CN=Certificate Templates,DC=contoso,DC=com'
                IdentityReferenceSID  = 'S-1-5-21-1234-5678-9012-1001'
                ActiveDirectoryRights = 'ExtendedRight'
                CAFullName            = $null
                Owner                 = $null
            }
        }

        It 'should return true for two issues with identical core properties' {
            $issueA = New-MockLS2Issue -Overrides $script:BaseProps
            $issueB = New-MockLS2Issue -Overrides $script:BaseProps
            $issueA.Matches($issueB) | Should -BeTrue
        }

        It 'should return false when Technique differs' {
            $issueA = New-MockLS2Issue -Overrides $script:BaseProps
            $propsB = $script:BaseProps.Clone(); $propsB['Technique'] = 'ESC2'
            $issueB = New-MockLS2Issue -Overrides $propsB
            $issueA.Matches($issueB) | Should -BeFalse
        }

        It 'should return false when DistinguishedName differs' {
            $issueA = New-MockLS2Issue -Overrides $script:BaseProps
            $propsB = $script:BaseProps.Clone(); $propsB['DistinguishedName'] = 'CN=Other,DC=contoso,DC=com'
            $issueB = New-MockLS2Issue -Overrides $propsB
            $issueA.Matches($issueB) | Should -BeFalse
        }

        It 'should return false when IdentityReferenceSID differs' {
            $issueA = New-MockLS2Issue -Overrides $script:BaseProps
            $propsB = $script:BaseProps.Clone(); $propsB['IdentityReferenceSID'] = 'S-1-5-21-9999-9999-9999-500'
            $issueB = New-MockLS2Issue -Overrides $propsB
            $issueA.Matches($issueB) | Should -BeFalse
        }

        It 'should return false when ActiveDirectoryRights differs' {
            $issueA = New-MockLS2Issue -Overrides $script:BaseProps
            $propsB = $script:BaseProps.Clone(); $propsB['ActiveDirectoryRights'] = 'GenericAll'
            $issueB = New-MockLS2Issue -Overrides $propsB
            $issueA.Matches($issueB) | Should -BeFalse
        }

        It 'should return false when argument is null' -Tag 'EdgeCase' {
            $issue = New-MockLS2Issue -Overrides $script:BaseProps
            $issue.Matches($null) | Should -BeFalse
        }
    }

    Describe 'Risk properties' {
        It 'RiskValue should be null by default' {
            $issue = New-MockLS2Issue
            $issue.RiskValue | Should -BeNullOrEmpty
        }

        It 'RiskName should be null/empty by default' {
            $issue = New-MockLS2Issue
            $issue.RiskName | Should -BeNullOrEmpty
        }

        It 'RiskScoring should be null by default' {
            $issue = New-MockLS2Issue
            $issue.RiskScoring | Should -BeNullOrEmpty
        }

        It 'EndpointURL should be null/empty by default' {
            $issue = New-MockLS2Issue
            $issue.EndpointURL | Should -BeNullOrEmpty
        }

        It 'EndpointAttackVector should be null/empty by default' {
            $issue = New-MockLS2Issue
            $issue.EndpointAttackVector | Should -BeNullOrEmpty
        }

        It 'constructor sets RiskValue from hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ RiskValue = 4 }
            $issue.RiskValue | Should -Be 4
        }

        It 'constructor sets RiskName from hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ RiskName = 'High' }
            $issue.RiskName | Should -Be 'High'
        }

        It 'constructor sets RiskScoring from hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ RiskScoring = @('BaseScore: 3', 'Enabled: +1') }
            $issue.RiskScoring | Should -Be @('BaseScore: 3', 'Enabled: +1')
        }

        It 'constructor sets EndpointURL from hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ EndpointURL = 'http://ca.contoso.com/certsrv/' }
            $issue.EndpointURL | Should -Be 'http://ca.contoso.com/certsrv/'
        }

        It 'constructor sets EndpointAttackVector from hashtable' {
            $issue = New-MockLS2Issue -Overrides @{ EndpointAttackVector = 'HTTP' }
            $issue.EndpointAttackVector | Should -Be 'HTTP'
        }

        It 'RiskValue can be set post-construction' {
            $issue = New-MockLS2Issue
            $issue.RiskValue = 5
            $issue.RiskValue | Should -Be 5
        }

        It 'RiskScoring can be appended post-construction' {
            $issue = New-MockLS2Issue
            $issue.RiskScoring = @('BaseScore: 0', 'TechniqueBonus: +1')
            $issue.RiskScoring.Count | Should -Be 2
        }
    }
}
