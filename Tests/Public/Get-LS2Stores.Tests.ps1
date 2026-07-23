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
}

InModuleScope 'Locksmith2' {
    Describe 'Get-LS2Stores' -Tag 'Unit' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        It 'should return a PSCustomObject' {
            $result = Get-LS2Stores
            $result | Should -BeOfType [PSCustomObject]
        }

        It 'should return exactly 8 properties' {
            $result = Get-LS2Stores
            ($result.PSObject.Properties | Measure-Object).Count | Should -Be 8
        }

        It 'should include all expected store property names' {
            $result = Get-LS2Stores
            $result.PSObject.Properties.Name | Should -Contain 'AdcsObjectStore'
            $result.PSObject.Properties.Name | Should -Contain 'DangerousPrincipals'
            $result.PSObject.Properties.Name | Should -Contain 'DomainStore'
            $result.PSObject.Properties.Name | Should -Contain 'Forest'
            $result.PSObject.Properties.Name | Should -Contain 'IssueStore'
            $result.PSObject.Properties.Name | Should -Contain 'PrincipalStore'
            $result.PSObject.Properties.Name | Should -Contain 'SafePrincipals'
            $result.PSObject.Properties.Name | Should -Contain 'StandardOwners'
        }

        It 'should reflect current module Forest value' {
            $script:Forest = 'contoso.com'
            $result = Get-LS2Stores
            $result.Forest | Should -Be 'contoso.com'
        }

        It 'should reflect current module IssueStore contents' {
            $script:IssueStore = @{ 'CN=Test' = @{ ESC1 = @() } }
            $result = Get-LS2Stores
            ($result.IssueStore -is [hashtable]) | Should -BeTrue
            $result.IssueStore.ContainsKey('CN=Test') | Should -BeTrue
        }

        It 'should return null Forest when Forest is not set' {
            $result = Get-LS2Stores
            $result.Forest | Should -BeNullOrEmpty
        }
    }
}
