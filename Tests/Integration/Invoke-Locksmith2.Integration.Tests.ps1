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
    # Optional: populate from environment
    # $script:TestCredential = ...
}

InModuleScope 'Locksmith2' {
    Describe 'Invoke-Locksmith2 — Integration' -Tag 'Integration' {
        It 'should complete a full scan and return LS2Issue objects' -Skip:([string]::IsNullOrEmpty($script:TestForest)) {
            $results = @(Invoke-Locksmith2 -Forest $script:TestForest -SkipPowerShellCheck)
            # Results can be empty (clean forest) but should not throw
            foreach ($r in $results) {
                $r | Should -BeOfType [LS2Issue]
            }
        }

        It 'should populate IssueStore after a full scan' -Skip:([string]::IsNullOrEmpty($script:TestForest)) {
            Invoke-Locksmith2 -Forest $script:TestForest -SkipPowerShellCheck | Out-Null
            # IssueStore may be empty on a clean forest, but should be a hashtable
            $script:IssueStore | Should -BeOfType [hashtable]
        }

        It 'should accept -Rescan and not throw on a second invocation' -Skip:([string]::IsNullOrEmpty($script:TestForest)) {
            Invoke-Locksmith2 -Forest $script:TestForest -SkipPowerShellCheck | Out-Null
            { Invoke-Locksmith2 -Forest $script:TestForest -SkipPowerShellCheck -Rescan | Out-Null } | Should -Not -Throw
        }
    }
}
