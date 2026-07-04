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

InModuleScope 'Locksmith2' {
    Describe 'Show-IssueReport' -Tag 'Unit' {
        BeforeAll {
            $script:testIssues = @(
                [LS2Issue]@{
                    Technique         = 'ESC1'
                    Forest            = 'contoso.com'
                    Name              = 'TestTemplate'
                    DistinguishedName = 'CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    ObjectClass       = 'pKICertificateTemplate'
                    IdentityReference = 'Everyone'
                    Issue             = 'Template allows SAN'
                    Fix               = 'Disable SAN flag'
                    Revert            = 'Enable SAN flag'
                }
                [LS2Issue]@{
                    Technique         = 'ESC6'
                    Forest            = 'contoso.com'
                    Name              = 'TestCA'
                    DistinguishedName = 'CN=TestCA,CN=Enrollment Services,...'
                    ObjectClass       = 'pKIEnrollmentService'
                    Issue             = 'EDITF_ATTRIBUTESUBJECTALTNAME2 enabled'
                    Fix               = 'Disable flag'
                    Revert            = 'Enable flag'
                }
            )
        }

        BeforeEach {
            Mock 'Write-Host' { }
        }

        It 'should not throw in Mode 0' {
            { Show-IssueReport -Issues $script:testIssues -Mode 0 } | Should -Not -Throw
        }

        It 'should not throw in Mode 1' {
            { Show-IssueReport -Issues $script:testIssues -Mode 1 } | Should -Not -Throw
        }

        It 'should call Write-Host at least once in Mode 0' {
            Show-IssueReport -Issues $script:testIssues -Mode 0
            Should -Invoke 'Write-Host' -Times 1 -Exactly:$false
        }

        It 'should call Write-Host at least once in Mode 1' {
            Show-IssueReport -Issues $script:testIssues -Mode 1
            Should -Invoke 'Write-Host' -Times 1 -Exactly:$false
        }

        It 'should throw when Issues array is empty (empty strongly-typed array cannot bind)' {
            { Show-IssueReport -Issues @() -Mode 0 } | Should -Throw
        }
    }
}
