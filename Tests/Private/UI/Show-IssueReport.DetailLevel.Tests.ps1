#requires -Version 5.1
<#
.SYNOPSIS
    Tests for Show-IssueReport -DetailLevel parameter (Summary/Detailed/Full views).
#>
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

InModuleScope 'Locksmith2' {
    Describe 'Show-IssueReport -DetailLevel' -Tag 'Unit' {
        BeforeAll {
            $script:testIssues = @(
                [LS2Issue]@{
                    Technique              = 'ESC1'
                    Forest                 = 'contoso.com'
                    Name                   = 'VulnTemplate'
                    DistinguishedName      = 'CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    ObjectClass            = 'pKICertificateTemplate'
                    IdentityReference      = 'CONTOSO\Domain Users'
                    IdentityReferenceClass = 'group'
                    Enabled                = $true
                    EnabledOn              = @('CA01')
                    Issue                  = 'Test issue text'
                    Fix                    = 'Test fix script'
                    Revert                 = 'Test revert script'
                }
                [LS2Issue]@{
                    Technique         = 'ESC6'
                    Forest            = 'contoso.com'
                    Name              = 'TestCA'
                    DistinguishedName = 'CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    ObjectClass       = 'pKIEnrollmentService'
                    CAFullName        = 'ca01.contoso.com\TestCA'
                    Issue             = 'Test CA issue'
                    Fix               = 'Test fix'
                    Revert            = 'Test revert'
                }
            )
        }

        BeforeEach {
            Mock 'Write-Host' { }
        }

        It 'does not throw with -DetailLevel <_>' -ForEach @('Summary', 'Detailed', 'Full') {
            { Show-IssueReport -Issues $script:testIssues -DetailLevel $_ } | Should -Not -Throw
        }

        It 'writes per-technique headers' {
            Show-IssueReport -Issues $script:testIssues -DetailLevel Summary
            Should -Invoke 'Write-Host' -ParameterFilter { $Object -match 'ESC1 Issues' }
        }

        It 'rejects invalid detail levels' {
            { Show-IssueReport -Issues $script:testIssues -DetailLevel 'Bogus' } | Should -Throw
        }

        It 'Detailed uses per-technique views' {
            $out = Show-IssueReport -Issues $script:testIssues -DetailLevel Detailed | Out-String
            $out | Should -Match 'IdentityReference'
            $out | Should -Match 'CAFullName'
            $out | Should -Not -Match '(?m)^Fix'
        }

        It 'Detailed falls back to Full for unknown techniques' {
            $unknownIssue = [LS2Issue]@{
                Technique         = 'ESC99'
                Forest            = 'contoso.com'
                Name              = 'Mystery'
                DistinguishedName = 'CN=Mystery,DC=contoso,DC=com'
                ObjectClass       = 'pKICertificateTemplate'
                Issue             = 'Unknown technique issue'
                Fix               = 'Mystery fix'
            }
            $out = Show-IssueReport -Issues @($unknownIssue) -DetailLevel Detailed | Out-String
            $out | Should -Match 'Mystery fix'
        }

        It 'Full includes remediation scripts' {
            $out = Show-IssueReport -Issues $script:testIssues -DetailLevel Full | Out-String
            $out | Should -Match 'Test fix script'
            $out | Should -Match 'Test revert script'
        }

        It 'still supports legacy -Mode 0' {
            { Show-IssueReport -Issues $script:testIssues -Mode 0 } | Should -Not -Throw
        }

        It 'still supports legacy -Mode 1' {
            { Show-IssueReport -Issues $script:testIssues -Mode 1 } | Should -Not -Throw
        }
    }
}
