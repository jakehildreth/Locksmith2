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
    Describe 'New-LS2Dashboard' -Tag 'Unit' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'PSWriteHTML not available' {
            BeforeEach {
                Mock 'Get-Command' { $null } -ParameterFilter { $Name -eq 'New-HTML' }
                Mock 'Write-Error' { }
                Mock 'New-HTML' { }
            }

            It 'should write an error when PSWriteHTML is not loaded' {
                { New-LS2Dashboard } | Should -Not -Throw
                Should -Invoke 'Write-Error' -Times 1
            }

            It 'should return early without calling New-HTML' {
                New-LS2Dashboard
                Should -Invoke 'New-HTML' -Times 0
            }
        }

        Context 'PSWriteHTML available' {
            BeforeEach {
                Mock 'Get-Command' { [PSCustomObject]@{ Name = 'New-HTML' } } -ParameterFilter { $Name -eq 'New-HTML' }
                Mock 'Get-FlattenedIssues' { @() }
                Mock 'Find-LS2RiskyPrincipal' { @() }
                Mock 'New-HTML' { }
                Mock 'New-HTMLTab' { }
                Mock 'New-HTMLSection' { }
                Mock 'New-HTMLPanel' { }
                Mock 'New-HTMLText' { }
                Mock 'New-HTMLTable' { }
                Mock 'New-HTMLTabStyle' { }
                Mock 'New-HTMLTableCondition' { }
                Mock 'Expand-IssueByGroup' { }
            }

            It 'should not throw when PSWriteHTML is available' {
                { New-LS2Dashboard } | Should -Not -Throw
            }

            It 'should call New-HTML to build the dashboard' {
                New-LS2Dashboard
                Should -Invoke 'New-HTML' -Times 1
            }

            It 'should write a warning when IssueStore is empty' {
                Mock 'Write-Warning' { }
                New-LS2Dashboard
                Should -Invoke 'Write-Warning' -Times 1
            }

            It 'should default FilePath to the current working directory' {
                $cwd = (Get-Location).Path
                New-LS2Dashboard
                Should -Invoke 'New-HTML' -Times 1 -ParameterFilter { $FilePath.StartsWith($cwd) -and $FilePath.EndsWith('.html') }
            }

            It 'should include a date and time stamp in the default file name' {
                New-LS2Dashboard
                Should -Invoke 'New-HTML' -Times 1 -ParameterFilter { $FilePath -match 'Locksmith2-Dashboard-\d{4}-\d{2}-\d{2}_\d{6}\.html' }
            }

            It 'should open the browser by default when no parameters are given' {
                New-LS2Dashboard
                Should -Invoke 'New-HTML' -Times 1 -ParameterFilter { $Show -eq $true }
            }

            It 'should include a date and time stamp in the dashboard' {
                New-LS2Dashboard
                Should -Invoke 'New-HTML' -Times 1 -ParameterFilter { $TitleText -match '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}' }
            }
        }
    }
}
