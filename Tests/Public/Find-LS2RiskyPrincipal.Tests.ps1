#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {
    Describe 'Find-LS2RiskyPrincipal' -Tag 'Unit' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
            Mock 'Initialize-LS2Scan' { $true }
        }

        Context 'failure paths' {
            It 'should return nothing when Initialize-LS2Scan returns false' {
                Mock 'Initialize-LS2Scan' { $false }
                Mock 'Get-FlattenedIssues' { @() }
                $result = @(Find-LS2RiskyPrincipal)
                $result.Count | Should -Be 0
            }

            It 'should write a warning and return nothing when IssueStore is empty' {
                Mock 'Get-FlattenedIssues' { @() }
                Mock 'Expand-IssueByGroup' { }
                Mock 'Write-Warning' { }
                $result = @(Find-LS2RiskyPrincipal)
                $result.Count | Should -Be 0
                Should -Invoke 'Write-Warning' -Times 1
            }
        }

        Context 'aggregation logic' {
            BeforeEach {
                $issue1 = [LS2Issue]@{
                    Technique = 'ESC1'; Forest = 'contoso.com'; Name = 'Template1'
                    DistinguishedName = 'CN=Template1,...'; ObjectClass = 'pKICertificateTemplate'
                    IdentityReference = 'CONTOSO\Domain Users'
                }
                $issue2 = [LS2Issue]@{
                    Technique = 'ESC2'; Forest = 'contoso.com'; Name = 'Template2'
                    DistinguishedName = 'CN=Template2,...'; ObjectClass = 'pKICertificateTemplate'
                    IdentityReference = 'CONTOSO\Domain Users'
                }
                $issue3 = [LS2Issue]@{
                    Technique = 'ESC1'; Forest = 'contoso.com'; Name = 'Template1'
                    DistinguishedName = 'CN=Template1,...'; ObjectClass = 'pKICertificateTemplate'
                    IdentityReference = 'CONTOSO\Everyone'
                }
                Mock 'Get-FlattenedIssues' { @($issue1, $issue2, $issue3) }
                Mock 'Expand-IssueByGroup' { $Issue }
            }

            It 'should return one entry per unique IdentityReference' {
                $result = @(Find-LS2RiskyPrincipal)
                $result.Count | Should -Be 2
            }

            It 'should aggregate IssueCount correctly per principal' {
                $result = @(Find-LS2RiskyPrincipal)
                $domainUsers = $result | Where-Object Principal -EQ 'CONTOSO\Domain Users'
                $domainUsers.IssueCount | Should -Be 2
            }

            It 'should sort results descending by IssueCount' {
                $result = @(Find-LS2RiskyPrincipal)
                $result[0].IssueCount | Should -BeGreaterOrEqual $result[-1].IssueCount
            }

            It 'should include Techniques array per principal' {
                $result = @(Find-LS2RiskyPrincipal)
                $domainUsers = $result | Where-Object Principal -EQ 'CONTOSO\Domain Users'
                $domainUsers.Techniques | Should -Contain 'ESC1'
                $domainUsers.Techniques | Should -Contain 'ESC2'
            }

            It 'should honour -Top N and return only N principals' {
                $result = @(Find-LS2RiskyPrincipal -Top 1)
                $result.Count | Should -Be 1
            }

            It 'should honour -MinimumIssueCount and exclude principals below threshold' {
                $result = @(Find-LS2RiskyPrincipal -MinimumIssueCount 2)
                # Only Domain Users has 2 issues; Everyone has 1
                $result.Count | Should -Be 1
                $result[0].Principal | Should -Be 'CONTOSO\Domain Users'
            }

            It 'should filter to specified -Technique only' {
                $result = @(Find-LS2RiskyPrincipal -Technique 'ESC2')
                # Only Domain Users has an ESC2 issue
                $result.Count | Should -Be 1
                $result[0].Principal | Should -Be 'CONTOSO\Domain Users'
            }
        }
    }
}
