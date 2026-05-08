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
    Describe 'Set-LS2Credential' -Tag 'Unit' {
        BeforeEach {
            $script:Credential = $null
            Mock 'Write-Host' { }
        }

        It 'should set script:Credential when Credential parameter is provided' {
            $password = ConvertTo-SecureString 'TestPassword!' -AsPlainText -Force
            $cred = [PSCredential]::new('CONTOSO\testuser', $password)
            Set-LS2Credential -Credential $cred
            $script:Credential | Should -Not -BeNullOrEmpty
            $script:Credential.UserName | Should -Be 'CONTOSO\testuser'
        }

        It 'should set script:Credential as a PSCredential when Credential parameter is provided' {
            $password = ConvertTo-SecureString 'TestPassword!' -AsPlainText -Force
            $cred = [PSCredential]::new('CONTOSO\testuser', $password)
            Set-LS2Credential -Credential $cred
            $script:Credential | Should -BeOfType [PSCredential]
        }

        It 'should call Read-Host twice when no Credential parameter given' {
            Mock 'Read-Host' { 'CONTOSO\testuser' } -ParameterFilter { -not $AsSecureString }
            Mock 'Read-Host' { ConvertTo-SecureString 'TestPass!' -AsPlainText -Force } -ParameterFilter { $AsSecureString }
            Set-LS2Credential
            Should -Invoke 'Read-Host' -Times 2
        }

        It 'should construct a PSCredential from Read-Host input when no parameter given' {
            Mock 'Read-Host' { 'CONTOSO\testuser' } -ParameterFilter { -not $AsSecureString }
            Mock 'Read-Host' { ConvertTo-SecureString 'TestPass!' -AsPlainText -Force } -ParameterFilter { $AsSecureString }
            Set-LS2Credential
            $script:Credential | Should -BeOfType [PSCredential]
            $script:Credential.UserName | Should -Be 'CONTOSO\testuser'
        }

        It 'should not call Read-Host when Credential parameter is provided' {
            Mock 'Read-Host' { }
            $password = ConvertTo-SecureString 'TestPassword!' -AsPlainText -Force
            $cred = [PSCredential]::new('CONTOSO\testuser', $password)
            Set-LS2Credential -Credential $cred
            Should -Invoke 'Read-Host' -Times 0
        }
    }
}
