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
}
