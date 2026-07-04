#requires -Version 5.1
BeforeAll {
    $DataPath = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Data\ESCDefinitions.ps1'
    . $DataPath
}

Describe 'ESCDefinitions data' -Tag 'Unit' {
    BeforeAll {
        # Report all failures in this describe block rather than stopping at the first
        $PesterPreference = [PesterConfiguration]::Default
        $PesterPreference.Should.ErrorAction = 'Continue'
    }

    It 'should import without error' {
        $script:ESCDefinitions | Should -Not -BeNullOrEmpty
    }

    It 'should be a hashtable' {
        $script:ESCDefinitions | Should -BeOfType [hashtable]
    }

    Context 'Required techniques are present' {
        $RequiredTechniques = @(
            'ESC1', 'ESC2', 'ESC3c1', 'ESC3c2',
            'ESC4a', 'ESC4o',
            'ESC5a', 'ESC5o',
            'ESC6', 'ESC7a', 'ESC7m',
            'ESC8', 'ESC9', 'ESC11', 'ESC13', 'ESC15', 'ESC16',
            'Auditing', 'SchemaV1'
        )

        It 'should contain technique <_>' -ForEach $RequiredTechniques {
            $script:ESCDefinitions.Keys | Should -Contain $_
        }
    }

    Context 'Each technique has required keys' {
        $RequiredTechniques = @(
            'ESC1', 'ESC2', 'ESC3c1', 'ESC3c2',
            'ESC4a', 'ESC4o',
            'ESC5a', 'ESC5o',
            'ESC6', 'ESC7a', 'ESC7m',
            'ESC8', 'ESC9', 'ESC11', 'ESC13', 'ESC15', 'ESC16',
            'Auditing', 'SchemaV1'
        )

        It '<_> should have a Technique key' -ForEach $RequiredTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'Technique'
        }

        It '<_> should have an IssueTemplate key' -ForEach $RequiredTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'IssueTemplate'
        }

        It '<_> should have a FixTemplate key' -ForEach $RequiredTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'FixTemplate'
        }

        It '<_> should have a RevertTemplate key' -ForEach $RequiredTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'RevertTemplate'
        }

        It '<_> Technique property should match its key' -ForEach $RequiredTechniques {
            $script:ESCDefinitions[$_].Technique | Should -Be $_
        }
    }

    Context 'Techniques with Conditions have valid structure' {
        $TechniquesWithConditions = @('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC9', 'ESC13', 'ESC15', 'Auditing', 'SchemaV1')

        It '<_> should have a non-empty Conditions array' -ForEach $TechniquesWithConditions {
            $script:ESCDefinitions[$_].Conditions | Should -Not -BeNullOrEmpty
        }

        It 'every Condition in <_> should have a Property key' -ForEach $TechniquesWithConditions {
            foreach ($condition in $script:ESCDefinitions[$_].Conditions) {
                $condition.Keys | Should -Contain 'Property' -Because "condition '$($condition | Out-String)' is missing Property"
            }
        }

        It 'every Condition in <_> should have a Value key' -ForEach $TechniquesWithConditions {
            foreach ($condition in $script:ESCDefinitions[$_].Conditions) {
                $condition.Keys | Should -Contain 'Value' -Because "condition '$($condition | Out-String)' is missing Value"
            }
        }
    }

    Context 'IssueTemplate, FixTemplate, RevertTemplate are non-empty' {
        $AllTechniques = @(
            'ESC1', 'ESC2', 'ESC3c1', 'ESC3c2',
            'ESC4a', 'ESC4o',
            'ESC5a', 'ESC5o',
            'ESC6', 'ESC7a', 'ESC7m',
            'ESC8', 'ESC9', 'ESC11', 'ESC13', 'ESC15', 'ESC16',
            'Auditing', 'SchemaV1'
        )

        It '<_> IssueTemplate should not be null or empty' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].IssueTemplate | Should -Not -BeNullOrEmpty
        }

        It '<_> FixTemplate should not be null or empty' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].FixTemplate | Should -Not -BeNullOrEmpty
        }

        It '<_> RevertTemplate should not be null or empty' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].RevertTemplate | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Each technique has required scoring keys' {
        $AllTechniques = @(
            'ESC1', 'ESC2', 'ESC3c1', 'ESC3c2',
            'ESC4a', 'ESC4o',
            'ESC5a', 'ESC5o',
            'ESC6', 'ESC7a', 'ESC7m',
            'ESC8', 'ESC9', 'ESC11', 'ESC13', 'ESC15', 'ESC16',
            'Auditing', 'SchemaV1'
        )

        It '<_> should have a BaseScore key' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'BaseScore'
        }

        It '<_> BaseScore should be an integer between 0 and 3' -ForEach $AllTechniques {
            $def = $script:ESCDefinitions[$_]
            $def.BaseScore | Should -BeOfType [int]
            $def.BaseScore | Should -BeGreaterOrEqual 0
            $def.BaseScore | Should -BeLessOrEqual 3
        }

        It '<_> should have a TechniqueBonus key' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'TechniqueBonus'
        }

        It '<_> TechniqueBonus should be a non-negative integer' -ForEach $AllTechniques {
            $def = $script:ESCDefinitions[$_]
            $def.TechniqueBonus | Should -BeOfType [int]
            $def.TechniqueBonus | Should -BeGreaterOrEqual 0
        }

        It '<_> should have an ApplyEnabledModifier key' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'ApplyEnabledModifier'
        }

        It '<_> ApplyEnabledModifier should be a bool' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].ApplyEnabledModifier | Should -BeOfType [bool]
        }

        It '<_> should have an ApplyPrincipalRisk key' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'ApplyPrincipalRisk'
        }

        It '<_> ApplyPrincipalRisk should be a bool' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].ApplyPrincipalRisk | Should -BeOfType [bool]
        }

        It '<_> should have an ApplyObjectClassBonus key' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'ApplyObjectClassBonus'
        }

        It '<_> ApplyObjectClassBonus should be a bool' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].ApplyObjectClassBonus | Should -BeOfType [bool]
        }

        It '<_> should have an ObjectClassBonuses key' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'ObjectClassBonuses'
        }

        It '<_> ObjectClassBonuses should be a hashtable' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].ObjectClassBonuses | Should -BeOfType [hashtable]
        }

        It '<_> should have a NtAuthBonus key' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'NtAuthBonus'
        }

        It '<_> NtAuthBonus should be a non-negative integer' -ForEach $AllTechniques {
            $def = $script:ESCDefinitions[$_]
            $def.NtAuthBonus | Should -BeOfType [int]
            $def.NtAuthBonus | Should -BeGreaterOrEqual 0
        }

        It '<_> should have an EndpointBonuses key' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'EndpointBonuses'
        }

        It '<_> EndpointBonuses should be a hashtable' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].EndpointBonuses | Should -BeOfType [hashtable]
        }

        It '<_> should have a CrossESCModifiers key' -ForEach $AllTechniques {
            $script:ESCDefinitions[$_].Keys | Should -Contain 'CrossESCModifiers'
        }

        It '<_> CrossESCModifiers should be an array' -ForEach $AllTechniques {
            # array or empty array - just check it's not a scalar non-collection
            $val = $script:ESCDefinitions[$_].CrossESCModifiers
            ($val -is [array]) -or ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) -or ($val.Count -eq 0) | Should -BeTrue
        }
    }

    Context 'ESC5a and ESC5o have populated ObjectClassBonuses' {
        It 'ESC5a ObjectClassBonuses should include pKIEnrollmentService' {
            $script:ESCDefinitions['ESC5a'].ObjectClassBonuses.Keys | Should -Contain 'pKIEnrollmentService'
        }

        It 'ESC5a NtAuthBonus should be 2' {
            $script:ESCDefinitions['ESC5a'].NtAuthBonus | Should -Be 2
        }

        It 'ESC5o ObjectClassBonuses should include pKIEnrollmentService' {
            $script:ESCDefinitions['ESC5o'].ObjectClassBonuses.Keys | Should -Contain 'pKIEnrollmentService'
        }

        It 'ESC5o NtAuthBonus should be 2' {
            $script:ESCDefinitions['ESC5o'].NtAuthBonus | Should -Be 2
        }
    }

    Context 'ESC8 has EndpointBonuses for all three attack vectors' {
        It 'ESC8 EndpointBonuses should contain HTTP' {
            $script:ESCDefinitions['ESC8'].EndpointBonuses.Keys | Should -Contain 'HTTP'
        }

        It 'ESC8 EndpointBonuses should contain HTTPS-NTLM' {
            $script:ESCDefinitions['ESC8'].EndpointBonuses.Keys | Should -Contain 'HTTPS-NTLM'
        }

        It 'ESC8 EndpointBonuses should contain HTTPS-Kerberos' {
            $script:ESCDefinitions['ESC8'].EndpointBonuses.Keys | Should -Contain 'HTTPS-Kerberos'
        }
    }
}
