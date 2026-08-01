#requires -Version 5.1
BeforeAll {
    $PrivateRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot))

    . (Join-Path $PrivateRoot 'Private\Test\Test-IsDomainUser.ps1')
    . (Join-Path $PrivateRoot 'Private\Test\Test-IsDomainComputer.ps1')
    . (Join-Path $PrivateRoot 'Private\Test\Test-IsInteractiveSession.ps1')
    . (Join-Path $PrivateRoot 'Private\Get\Get-RootDSE.ps1')
    . (Join-Path $PrivateRoot 'Private\Utility\Resolve-LS2ConnectionContext.ps1')
}

Describe 'Resolve-LS2ConnectionContext' -Tag 'Unit' {

    BeforeEach {
        # Reset script-scope state between tests
        $script:Forest             = $null
        $script:Credential         = $null
        $script:CredentialResolved = $false
    }

    # ---------------------------------------------------------------------------
    Context 'Both -Forest and -Credential supplied at CLI' {

        It 'should return the supplied forest without running detection' {
            $securePass = ConvertTo-SecureString 'pass' -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new('CONTOSO\user', $securePass)

            Mock Test-IsDomainUser     {}
            Mock Test-IsDomainComputer {}

            $result = Resolve-LS2ConnectionContext -Forest 'contoso.com' -Credential $cred
            $result.Forest     | Should -Be 'contoso.com'
            $result.Credential | Should -Be $cred
            $result.Method     | Should -Be 'Explicit'
        }

        It 'should not call any detection functions when both are supplied' {
            $securePass = ConvertTo-SecureString 'pass' -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new('CONTOSO\user', $securePass)

            Mock Test-IsDomainUser     {}
            Mock Test-IsDomainComputer {}

            Resolve-LS2ConnectionContext -Forest 'contoso.com' -Credential $cred | Out-Null

            Should -Invoke Test-IsDomainUser     -Exactly 0
            Should -Invoke Test-IsDomainComputer -Exactly 0
        }
    }

    # ---------------------------------------------------------------------------
    Context '-Credential only supplied (no -Forest)' {

        It 'should derive forest from the credential UserName domain portion' {
            $securePass = ConvertTo-SecureString 'pass' -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new('CONTOSO\user', $securePass)

            Mock Test-IsDomainUser     {}
            Mock Test-IsDomainComputer {}

            $result = Resolve-LS2ConnectionContext -Credential $cred
            $result.Forest     | Should -Be 'CONTOSO'
            $result.Credential | Should -Be $cred
            $result.Method     | Should -Be 'ExplicitCredential'
        }
    }

    # ---------------------------------------------------------------------------
    Context '-Forest only supplied (no -Credential) — domain user session' {

        It 'should use null credential and supplied forest when current user is domain user' {
            Mock Test-IsDomainUser { $true }

            $result = Resolve-LS2ConnectionContext -Forest 'contoso.com'
            $result.Forest     | Should -Be 'contoso.com'
            $result.Credential | Should -BeNullOrEmpty
            $result.Method     | Should -Be 'DomainUser'
        }
    }

    # ---------------------------------------------------------------------------
    Context 'No CLI overrides — domain user session' -Tag 'Integration' {

        It 'should not throw' {
            Mock Test-IsDomainUser { $true }
            { Resolve-LS2ConnectionContext } | Should -Not -Throw
        }

        It 'should set Method to DomainUser' {
            Mock Test-IsDomainUser { $true }
            $result = Resolve-LS2ConnectionContext
            $result.Method | Should -Be 'DomainUser'
        }

        It 'should set Credential to $null on domain user path' {
            Mock Test-IsDomainUser { $true }
            $result = Resolve-LS2ConnectionContext
            $result.Credential | Should -BeNullOrEmpty
        }
    }

    # ---------------------------------------------------------------------------
    Context 'No CLI overrides — non-domain user, domain-joined machine' {

        BeforeAll {
            Mock Test-IsDomainUser     { $false }
            Mock Test-IsDomainComputer { $true }
            Mock Get-CimInstance {
                [PSCustomObject]@{ Domain = 'contoso.com'; PartOfDomain = $true }
            }
        }

        It 'should set Method to DomainComputer' {
            $result = Resolve-LS2ConnectionContext
            $result.Method | Should -Be 'DomainComputer'
        }

        It 'should set Credential to $null (machine account auth)' {
            $result = Resolve-LS2ConnectionContext
            $result.Credential | Should -BeNullOrEmpty
        }

        It 'should return a non-empty forest derived from Win32_ComputerSystem' {
            $result = Resolve-LS2ConnectionContext
            $result.Forest | Should -Be 'contoso.com'
        }

        It 'should set $script:CredentialResolved to $true' {
            Resolve-LS2ConnectionContext | Out-Null
            $script:CredentialResolved | Should -BeTrue
        }
    }

    # ---------------------------------------------------------------------------
    Context 'No CLI overrides — non-domain user, not domain-joined, interactive' {

        BeforeAll {
            Mock Test-IsDomainUser        { $false }
            Mock Test-IsDomainComputer    { $false }
            Mock Test-IsInteractiveSession { $true }
            Mock Get-RootDSE { [PSCustomObject]@{ Name = 'rootDSE' } }
            Mock Read-Host { 'external.contoso.com' } -ParameterFilter { -not $AsSecureString }
            Mock Read-Host { ConvertTo-SecureString 'pass' -AsPlainText -Force } -ParameterFilter { $AsSecureString }
        }

        It 'should prompt for both forest and credentials' {
            $result = Resolve-LS2ConnectionContext
            # 3 Read-Host calls: forest, username, password
            Should -Invoke Read-Host -Exactly 3
        }

        It 'should set Method to PromptedAll' {
            $result = Resolve-LS2ConnectionContext
            $result.Method | Should -Be 'PromptedAll'
        }

        It 'should use the prompted forest value' {
            $result = Resolve-LS2ConnectionContext
            $result.Forest | Should -Be 'external.contoso.com'
        }
    }

    # ---------------------------------------------------------------------------
    Context 'No CLI overrides — non-domain user, not domain-joined, non-interactive' {

        BeforeAll {
            Mock Test-IsDomainUser        { $false }
            Mock Test-IsDomainComputer    { $false }
            Mock Test-IsInteractiveSession { $false }
        }

        It 'should write a terminating error' {
            { Resolve-LS2ConnectionContext -ErrorAction Stop } | Should -Throw
        }
    }

    # ---------------------------------------------------------------------------
    Context 'Interactive retry on failed RootDSE bind' {

        BeforeAll {
            Mock Test-IsDomainUser        { $false }
            Mock Test-IsDomainComputer    { $false }
            Mock Test-IsInteractiveSession { $true }
        }

        It 'should retry up to 3 times and return result on successful retry' {
            Mock Read-Host { 'contoso.com' } -ParameterFilter { -not $AsSecureString }
            Mock Read-Host { ConvertTo-SecureString 'pass' -AsPlainText -Force } -ParameterFilter { $AsSecureString }
            Mock Get-RootDSE {
                $script:_retryCount++
                if ($script:_retryCount -lt 3) { return $null }
                return [PSCustomObject]@{ Name = 'rootDSE' }
            }
            $script:_retryCount = 0

            $result = Resolve-LS2ConnectionContext
            $result | Should -Not -BeNullOrEmpty
            Should -Invoke Get-RootDSE -Exactly 3
        }

        It 'should write a terminating error after 3 failed attempts' {
            Mock Read-Host { 'bad.domain' } -ParameterFilter { -not $AsSecureString }
            Mock Read-Host { ConvertTo-SecureString 'pass' -AsPlainText -Force } -ParameterFilter { $AsSecureString }
            Mock Get-RootDSE { return $null }

            { Resolve-LS2ConnectionContext -ErrorAction Stop } | Should -Throw
            Should -Invoke Get-RootDSE -Exactly 3
        }
    }
}