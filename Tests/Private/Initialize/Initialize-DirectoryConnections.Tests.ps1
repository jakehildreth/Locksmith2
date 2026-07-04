#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}

Describe 'Initialize-DirectoryConnections' -Tag 'Integration' {
    # Initialize-DirectoryConnections has a strongly-typed [System.DirectoryServices.DirectoryEntry]
    # parameter. A PSCustomObject cannot bind to it, so these tests require a real DirectoryEntry
    # obtained from a live domain controller.  All tests skip automatically when not domain-joined.
    InModuleScope 'Locksmith2' {

        BeforeAll {
            # Attempt a real RootDSE bind.  If AD is unreachable (not domain-joined) every test skips.
            $script:_IDC_RootDSE   = $null
            $script:_IDC_SkipTests = $true
            try {
                $de = [System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE')
                # Accessing rootDomainNamingContext forces the LDAP bind and proves AD is reachable.
                $null = $de.rootDomainNamingContext.Value
                $script:_IDC_RootDSE   = $de
                $script:_IDC_SkipTests = $false
            } catch {
                # Not domain-joined or AD unreachable — all tests will be skipped.
            }
        }

        AfterAll {
            if ($script:_IDC_RootDSE) { $script:_IDC_RootDSE.Dispose() }
            Remove-Variable -Name '_IDC_RootDSE', '_IDC_SkipTests' -Scope Script -ErrorAction SilentlyContinue
        }

        BeforeEach {
            $securePass = ConvertTo-SecureString 'password' -AsPlainText -Force
            $script:Credential = [System.Management.Automation.PSCredential]::new('CONTOSO\admin', $securePass)
            $script:GCDirectoryEntry     = $null
            $script:LDAPDirectoryEntry   = $null
            $script:ConfigDirectoryEntry = $null
            # Mock the actual DirectoryEntry constructor calls so no real bind happens during the test.
            Mock 'New-AuthenticatedDirectoryEntry' { [PSCustomObject]@{ Path = $Path } }
        }

        Context 'Successful initialisation' {
            It 'should create a GC connection entry' -Tag 'Integration' -Skip:($script:_IDC_SkipTests) {
                Initialize-DirectoryConnections -RootDSE $script:_IDC_RootDSE -Credential $script:Credential
                $script:GCDirectoryEntry | Should -Not -BeNullOrEmpty
            }

            It 'should create an LDAP connection entry' -Tag 'Integration' -Skip:($script:_IDC_SkipTests) {
                Initialize-DirectoryConnections -RootDSE $script:_IDC_RootDSE -Credential $script:Credential
                $script:LDAPDirectoryEntry | Should -Not -BeNullOrEmpty
            }

            It 'should create a Config connection entry' -Tag 'Integration' -Skip:($script:_IDC_SkipTests) {
                Initialize-DirectoryConnections -RootDSE $script:_IDC_RootDSE -Credential $script:Credential
                $script:ConfigDirectoryEntry | Should -Not -BeNullOrEmpty
            }

            It 'should build the GC path with GC:// scheme' -Tag 'Integration' -Skip:($script:_IDC_SkipTests) {
                Initialize-DirectoryConnections -RootDSE $script:_IDC_RootDSE -Credential $script:Credential
                $script:GCDirectoryEntry.Path | Should -BeLike 'GC://*'
            }

            It 'should build the LDAP path with LDAP:// scheme' -Tag 'Integration' -Skip:($script:_IDC_SkipTests) {
                Initialize-DirectoryConnections -RootDSE $script:_IDC_RootDSE -Credential $script:Credential
                $script:LDAPDirectoryEntry.Path | Should -BeLike 'LDAP://*'
            }

            It 'should call New-AuthenticatedDirectoryEntry at least 3 times (GC + LDAP + Config)' -Tag 'Integration' -Skip:($script:_IDC_SkipTests) {
                Initialize-DirectoryConnections -RootDSE $script:_IDC_RootDSE -Credential $script:Credential
                Should -Invoke 'New-AuthenticatedDirectoryEntry' -Times 3 -Exactly
            }
        }

        Context 'Invalid RootDSE path' {
            It 'should not throw when RootDSE path is not a valid LDAP path' -Tag 'Integration' -Skip:($script:_IDC_SkipTests) {
                # Requires a real [DirectoryEntry] — the strongly-typed param prevents PSCustomObject.
                # When domain-joined: create a DirectoryEntry with a non-standard path string and
                # verify Initialize-DirectoryConnections handles the failed server-extraction gracefully.
                $badPath = 'LDAP://INVALID_SERVER_THAT_DOES_NOT_EXIST_999/DC=contoso,DC=com'
                $badDE = [System.DirectoryServices.DirectoryEntry]::new($badPath)
                { Initialize-DirectoryConnections -RootDSE $badDE -Credential $script:Credential } |
                    Should -Not -Throw
            }
        }
    }
}
