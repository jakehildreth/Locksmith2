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
                Mock 'Get-Module' { $null } -ParameterFilter { $ListAvailable -and $Name -eq 'PSWriteHTML' }
                Mock 'Write-Error' { }
            }

            It 'should write an error when PSWriteHTML is not installed' {
                { New-LS2Dashboard } | Should -Not -Throw
                Should -Invoke 'Write-Error' -Times 1
            }

            It 'should return early without calling Import-Module for PSWriteHTML' {
                Mock 'Import-Module' { } -ParameterFilter { $Name -eq 'PSWriteHTML' }
                New-LS2Dashboard
                Should -Invoke 'Import-Module' -Times 0 -ParameterFilter { $Name -eq 'PSWriteHTML' }
            }
        }

        Context 'PSWriteHTML available' {
            BeforeEach {
                $fakeModule = [PSCustomObject]@{ Name = 'PSWriteHTML'; Version = '1.0.0' }
                Mock 'Get-Module' { $fakeModule } -ParameterFilter { $ListAvailable -and $Name -eq 'PSWriteHTML' }
                Mock 'Import-Module' { } -ParameterFilter { $Name -eq 'PSWriteHTML' }
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

            It 'should call Import-Module for PSWriteHTML' {
                New-LS2Dashboard
                Should -Invoke 'Import-Module' -Times 1 -ParameterFilter { $Name -eq 'PSWriteHTML' }
            }

            It 'should write a warning when IssueStore is empty' {
                Mock 'Write-Warning' { }
                New-LS2Dashboard
                Should -Invoke 'Write-Warning' -Times 1
            }
        }
    }
}
