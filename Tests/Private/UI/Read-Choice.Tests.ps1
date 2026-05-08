#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {
    Describe 'Read-Choice' -Tag 'Unit' {
        It 'should return the matching option when a valid option is given' {
            Mock 'Read-Host' { 'A' }
            $result = Read-Choice -Question 'Pick one' -Options @('A', 'B', 'C')
            $result | Should -Be 'A'
        }

        It 'should return the default option when an empty string is entered and Default is specified' {
            Mock 'Read-Host' { '' }
            $result = Read-Choice -Question 'Pick one' -Options @('A', 'B', 'C') -Default 'B'
            $result | Should -Be 'B'
        }

        It 'should return the first option when an empty string is entered and no Default is specified' {
            Mock 'Read-Host' { '' }
            $result = Read-Choice -Question 'Pick one' -Options @('A', 'B', 'C')
            $result | Should -Be 'A'
        }

        It 'should write a warning and loop when an invalid option is given before a valid one' {
            $script:callCount = 0
            Mock 'Read-Host' {
                $script:callCount++
                if ($script:callCount -eq 1) { 'INVALID' } else { 'C' }
            }
            Mock 'Write-Warning' { }
            $result = Read-Choice -Question 'Pick one' -Options @('A', 'B', 'C')
            $result | Should -Be 'C'
            Should -Invoke 'Write-Warning' -Times 1
        }

        It 'should accept any of the provided options' {
            Mock 'Read-Host' { 'B' }
            $result = Read-Choice -Question 'Pick one' -Options @('A', 'B', 'C')
            $result | Should -Be 'B'
        }

        It 'should be case-insensitive when matching options' {
            Mock 'Read-Host' { 'a' }
            $result = Read-Choice -Question 'Pick one' -Options @('A', 'B', 'C')
            $result | Should -Be 'A'
        }
    }
}
