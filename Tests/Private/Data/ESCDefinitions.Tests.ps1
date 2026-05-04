#requires -Version 5.1
BeforeAll {
    $DataPath = Join-Path $PSScriptRoot '..' '..' '..' 'Private' 'Data' 'ESCDefinitions.psd1'
    $script:Definitions = Import-PowerShellDataFile -Path $DataPath
}

Describe 'ESCDefinitions.psd1' -Tag 'Unit' {
    BeforeAll {
        # Report all failures in this describe block rather than stopping at the first
        $PesterPreference = [PesterConfiguration]::Default
        $PesterPreference.Should.ErrorAction = 'Continue'
    }

    It 'should import without error' {
        $script:Definitions | Should -Not -BeNullOrEmpty
    }

    It 'should be a hashtable' {
        $script:Definitions | Should -BeOfType [hashtable]
    }

    Context 'Required techniques are present' {
        $RequiredTechniques = @(
            'ESC1', 'ESC2', 'ESC3c1', 'ESC3c2',
            'ESC4a', 'ESC4o',
            'ESC5a', 'ESC5o',
            'ESC6', 'ESC7a', 'ESC7m',
            'ESC9', 'ESC11', 'ESC16'
        )

        It 'should contain technique <_>' -ForEach $RequiredTechniques {
            $script:Definitions.Keys | Should -Contain $_
        }
    }

    Context 'Each technique has required keys' {
        $RequiredTechniques = @(
            'ESC1', 'ESC2', 'ESC3c1', 'ESC3c2',
            'ESC4a', 'ESC4o',
            'ESC5a', 'ESC5o',
            'ESC6', 'ESC7a', 'ESC7m',
            'ESC9', 'ESC11', 'ESC16'
        )

        It '<_> should have a Technique key' -ForEach $RequiredTechniques {
            $script:Definitions[$_].Keys | Should -Contain 'Technique'
        }

        It '<_> should have an IssueTemplate key' -ForEach $RequiredTechniques {
            $script:Definitions[$_].Keys | Should -Contain 'IssueTemplate'
        }

        It '<_> should have a FixTemplate key' -ForEach $RequiredTechniques {
            $script:Definitions[$_].Keys | Should -Contain 'FixTemplate'
        }

        It '<_> should have a RevertTemplate key' -ForEach $RequiredTechniques {
            $script:Definitions[$_].Keys | Should -Contain 'RevertTemplate'
        }

        It '<_> Technique property should match its key' -ForEach $RequiredTechniques {
            $script:Definitions[$_].Technique | Should -Be $_
        }
    }

    Context 'Techniques with Conditions have valid structure' {
        $TechniquesWithConditions = @('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC9')

        It '<_> should have a non-empty Conditions array' -ForEach $TechniquesWithConditions {
            $script:Definitions[$_].Conditions | Should -Not -BeNullOrEmpty
        }

        It 'every Condition in <_> should have a Property key' -ForEach $TechniquesWithConditions {
            foreach ($condition in $script:Definitions[$_].Conditions) {
                $condition.Keys | Should -Contain 'Property' -Because "condition '$($condition | Out-String)' is missing Property"
            }
        }

        It 'every Condition in <_> should have a Value key' -ForEach $TechniquesWithConditions {
            foreach ($condition in $script:Definitions[$_].Conditions) {
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
            'ESC9', 'ESC11', 'ESC16'
        )

        It '<_> IssueTemplate should not be null or empty' -ForEach $AllTechniques {
            $script:Definitions[$_].IssueTemplate | Should -Not -BeNullOrEmpty
        }

        It '<_> FixTemplate should not be null or empty' -ForEach $AllTechniques {
            $script:Definitions[$_].FixTemplate | Should -Not -BeNullOrEmpty
        }

        It '<_> RevertTemplate should not be null or empty' -ForEach $AllTechniques {
            $script:Definitions[$_].RevertTemplate | Should -Not -BeNullOrEmpty
        }
    }
}
