#requires -Version 5.1
<#
.SYNOPSIS
    Tests for Invoke-Locksmith2 -DetailLevel parameter plumbing.
#>
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    $script:command = Get-Command -Name 'Invoke-Locksmith2' -Module 'Locksmith2'
}

Describe 'Invoke-Locksmith2 -DetailLevel parameter' -Tag 'Unit' {
    It 'has a DetailLevel parameter' {
        $script:command.Parameters.Keys | Should -Contain 'DetailLevel'
    }

    It 'validates DetailLevel against Summary/Detailed/Full' {
        $validateSet = $script:command.Parameters['DetailLevel'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
        $validateSet.ValidValues | Should -Be @('Summary', 'Detailed', 'Full')
    }

    It 'retains the legacy Mode parameter' {
        $script:command.Parameters.Keys | Should -Contain 'Mode'
    }
}
