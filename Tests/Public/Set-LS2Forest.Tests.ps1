#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {
    Describe 'Set-LS2Forest' -Tag 'Unit' {
        BeforeEach {
            $script:Forest = $null
            Mock 'Read-Host' { 'fabrikam.com' }
        }

        It 'should set script:Forest when Forest parameter is provided' {
            Set-LS2Forest -Forest 'contoso.com'
            $script:Forest | Should -Be 'contoso.com'
        }

        It 'should call Read-Host when Forest parameter is not provided' {
            Set-LS2Forest
            Should -Invoke 'Read-Host' -Times 1
        }

        It 'should set script:Forest from Read-Host when no parameter given' {
            Set-LS2Forest
            $script:Forest | Should -Be 'fabrikam.com'
        }

        It 'should not call Read-Host when Forest parameter is provided' {
            Set-LS2Forest -Forest 'contoso.com'
            Should -Invoke 'Read-Host' -Times 0
        }
    }
}
