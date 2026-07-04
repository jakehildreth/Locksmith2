#requires -Version 5.1
# Integration tests — require a live AD CS environment.
# Set $env:LS2_TEST_FOREST to a fully qualified domain/forest name to enable.
# These tests are tagged 'Integration' and skipped automatically in CI when the env var is absent.

BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop

    $script:TestForest = $env:LS2_TEST_FOREST
}

InModuleScope 'Locksmith2' {
    Describe 'Find-LS2VulnerableTemplate — Integration' -Tag 'Integration' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        It 'should return LS2Issue objects or empty array from a live forest' -Skip:([string]::IsNullOrEmpty($script:TestForest)) {
            $results = @(Find-LS2VulnerableTemplate -Forest $script:TestForest)
            foreach ($r in $results) {
                $r | Should -BeOfType [LS2Issue]
                $r.Technique | Should -BeIn @('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC9', 'ESC4a', 'ESC4o')
            }
        }

        It 'should populate AdcsObjectStore with certificate template objects after Initialize-LS2Scan' -Skip:([string]::IsNullOrEmpty($script:TestForest)) {
            Find-LS2VulnerableTemplate -Forest $script:TestForest | Out-Null
            $templates = $script:AdcsObjectStore.Values | Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
            $templates | Should -Not -BeNullOrEmpty
        }

        It 'should return only ESC1 issues when -Technique ESC1 is specified' -Skip:([string]::IsNullOrEmpty($script:TestForest)) {
            $results = @(Find-LS2VulnerableTemplate -Forest $script:TestForest -Technique 'ESC1')
            foreach ($r in $results) {
                $r.Technique | Should -Be 'ESC1'
            }
        }
    }
}
