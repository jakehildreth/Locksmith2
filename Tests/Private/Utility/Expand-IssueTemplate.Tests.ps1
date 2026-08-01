#requires -Version 5.1
BeforeAll {
    # Dot-source via scriptblock to handle UTF-16LE source encoding
    $SourcePath = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Utility\Expand-IssueTemplate.ps1'
    . ([scriptblock]::Create((Get-Content -Path $SourcePath -Raw)))
}

Describe 'Expand-IssueTemplate' -Tag 'Unit' {
    BeforeAll {
        $script:BaseConfig = @{
            IssueTemplate  = @('$(IdentityReference) can enroll in $(TemplateName).')
            FixTemplate    = @('# Fix', 'Set-ADObject $(DistinguishedName)')
            RevertTemplate = @('# Revert', 'Set-ADObject $(DistinguishedName)')
        }
        $script:BaseVars = @{
            IdentityReference = 'CONTOSO\Domain Users'
            TemplateName      = 'WebServer'
            DistinguishedName = 'CN=WebServer,CN=Certificate Templates,DC=contoso,DC=com'
        }
    }

    Describe 'Return value structure' {
        It 'should return a hashtable' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars
            $result | Should -BeOfType [hashtable]
        }

        It 'should return Issue, Fix, and Revert keys' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars
            $result.Keys | Should -Contain 'Issue'
            $result.Keys | Should -Contain 'Fix'
            $result.Keys | Should -Contain 'Revert'
        }
    }

    Describe 'Variable substitution' {
        It 'should substitute IdentityReference in the Issue string' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars
            $result.Issue | Should -BeLike '*CONTOSO\Domain Users*'
        }

        It 'should substitute TemplateName in the Issue string' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars
            $result.Issue | Should -BeLike '*WebServer*'
        }

        It 'should substitute DistinguishedName in the Fix string' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars
            $result.Fix | Should -BeLike '*CN=WebServer*'
        }

        It 'should substitute DistinguishedName in the Revert string' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars
            $result.Revert | Should -BeLike '*CN=WebServer*'
        }

        It 'should perform multiple variable substitutions in one string' {
            $config = @{
                IssueTemplate  = @('$(IdentityReference) abused $(TemplateName) on $(DistinguishedName).')
                FixTemplate    = @('# no-op')
                RevertTemplate = @('# no-op')
            }
            $result = Expand-IssueTemplate -Config $config -Variables $script:BaseVars
            $result.Issue | Should -Be 'CONTOSO\Domain Users abused WebServer on CN=WebServer,CN=Certificate Templates,DC=contoso,DC=com.'
        }

        It 'should replace null variable values with empty string' -Tag 'EdgeCase' {
            $config = @{
                IssueTemplate  = @('Hello $(Name).')
                FixTemplate    = @('# no-op')
                RevertTemplate = @('# no-op')
            }
            $result = Expand-IssueTemplate -Config $config -Variables @{ Name = $null }
            $result.Issue | Should -Be 'Hello .'
        }

        It 'should leave unexpanded placeholders intact when variable is not provided' -Tag 'EdgeCase' {
            $config = @{
                IssueTemplate  = @('Value: $(Missing).')
                FixTemplate    = @('# no-op')
                RevertTemplate = @('# no-op')
            }
            $result = Expand-IssueTemplate -Config $config -Variables @{}
            $result.Issue | Should -Be 'Value: $(Missing).'
        }
    }

    Describe 'Array template joining' {
        It 'should join Issue template array elements with no separator' {
            $config = @{
                IssueTemplate  = @('Part one. ', 'Part two. ', 'Part three.')
                FixTemplate    = @('# no-op')
                RevertTemplate = @('# no-op')
            }
            $result = Expand-IssueTemplate -Config $config -Variables @{}
            $result.Issue | Should -Be 'Part one. Part two. Part three.'
        }

        It 'should join Fix template array elements with newlines' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars
            $result.Fix | Should -Be "# Fix`nSet-ADObject CN=WebServer,CN=Certificate Templates,DC=contoso,DC=com"
        }

        It 'should join Revert template array elements with newlines' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars
            $result.Revert | Should -Be "# Revert`nSet-ADObject CN=WebServer,CN=Certificate Templates,DC=contoso,DC=com"
        }

        It 'should handle a single-string IssueTemplate (not an array)' {
            $config = @{
                IssueTemplate  = 'Single string template.'
                FixTemplate    = @('# no-op')
                RevertTemplate = @('# no-op')
            }
            $result = Expand-IssueTemplate -Config $config -Variables @{}
            $result.Issue | Should -Be 'Single string template.'
        }
    }

    Describe 'IssueTemplate override parameter' {
        It 'should use the override instead of Config.IssueTemplate when provided' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars `
                -IssueTemplate @('Override: $(TemplateName)')
            $result.Issue | Should -Be 'Override: WebServer'
        }

        It 'should still use Config.FixTemplate and Config.RevertTemplate when override is used' {
            $result = Expand-IssueTemplate -Config $script:BaseConfig -Variables $script:BaseVars `
                -IssueTemplate @('Override.')
            $result.Fix    | Should -Not -BeNullOrEmpty
            $result.Revert | Should -Not -BeNullOrEmpty
        }
    }
}
