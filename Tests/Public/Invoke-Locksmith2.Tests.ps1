#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {
    Describe 'Invoke-Locksmith2' -Tag 'Unit' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null

            $script:mockIssue = [LS2Issue]@{
                Technique = 'ESC1'; Forest = 'contoso.com'; Name = 'TestTemplate'
                DistinguishedName = 'CN=TestTemplate,...'; ObjectClass = 'pKICertificateTemplate'
                IdentityReference = 'Everyone'
            }

            Mock 'Show-Logo' { }
            Mock 'Initialize-LS2Scan' { $true }
            Mock 'Get-FlattenedIssues' { @($script:mockIssue) }
            Mock 'Get-IssueCount' { 0 }
            Mock 'Show-IssueReport' { }
            Mock 'Test-PowerShellEnvironment' { [PSCustomObject]@{} }
            Mock 'Repair-PowerShellEnvironment' { }
            Mock 'Expand-IssueByGroup' { $_ }
        }

        It 'should always call Show-Logo' {
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Show-Logo' -Times 1
        }

        It 'should call Initialize-LS2Scan' {
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Initialize-LS2Scan' -Times 1
        }

        It 'should call Test-PowerShellEnvironment when -SkipPowerShellCheck is not specified' {
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Test-PowerShellEnvironment' -Times 1
        }

        It 'should not call Test-PowerShellEnvironment when -SkipPowerShellCheck is specified' {
            Invoke-Locksmith2 -SkipPowerShellCheck | Out-Null
            Should -Invoke 'Test-PowerShellEnvironment' -Times 0
        }

        It 'should return issues to pipeline when Mode is not specified' {
            $result = @(Invoke-Locksmith2)
            $result.Count | Should -Be 1
            Should -Invoke 'Show-IssueReport' -Times 0
        }

        It 'should call Show-IssueReport -Mode 0 when -Mode 0 is specified' {
            Invoke-Locksmith2 -Mode 0
            Should -Invoke 'Show-IssueReport' -Times 1 -ParameterFilter { $Mode -eq 0 }
        }

        It 'should call Show-IssueReport -Mode 1 when -Mode 1 is specified' {
            Invoke-Locksmith2 -Mode 1
            Should -Invoke 'Show-IssueReport' -Times 1 -ParameterFilter { $Mode -eq 1 }
        }

        It 'should write an error and not call Get-FlattenedIssues when Initialize-LS2Scan returns false' {
            Mock 'Initialize-LS2Scan' { $false }
            Mock 'Write-Error' { }
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Write-Error' -Times 1
            Should -Invoke 'Get-FlattenedIssues' -Times 0
        }

        It 'should forward Forest to Initialize-LS2Scan when Forest is specified' {
            Invoke-Locksmith2 -Forest 'contoso.com' | Out-Null
            Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter { $Forest -eq 'contoso.com' }
        }

        It 'should not forward Forest to Initialize-LS2Scan when Forest is not specified' {
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter { -not $PSBoundParameters.ContainsKey('Forest') }
        }

        It 'should pass -Rescan to Initialize-LS2Scan when -Rescan is specified' {
            Invoke-Locksmith2 -Rescan | Out-Null
            Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter { $Rescan -eq $true }
        }

        It 'should call Expand-IssueByGroup per issue when -ExpandGroups is specified' {
            Invoke-Locksmith2 -ExpandGroups | Out-Null
            Should -Invoke 'Expand-IssueByGroup' -Times 1
        }
    }
}
