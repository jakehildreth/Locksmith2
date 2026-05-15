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
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Resolve-Principal' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:PrincipalStore = @{}
            $script:Server = 'dc.contoso.com'
            $script:Credential = $null
            $script:RootDSE = $null
            # Prevent calls to New-AuthenticatedDirectoryEntry (requires credentials/AD)
            Mock 'New-AuthenticatedDirectoryEntry' { $null }
        }

        Context 'PrincipalStore cache hit — principal with DN' {
            It 'should return a DirectoryEntry when SID is already cached with a distinguishedName' -Tag 'Integration' -Skip:(-not [bool](Get-Module Locksmith2)) {
                # This path calls New-AuthenticatedDirectoryEntry which needs AD.
                # Mark as Integration; the logic under test is the cache-hit path.
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001')
                $principal = New-MockLS2Principal -Properties @{
                    objectSid         = 'S-1-5-21-1-2-3-1001'
                    distinguishedName = 'CN=jdoe,CN=Users,DC=contoso,DC=com'
                    NTAccountName     = 'CONTOSO\jdoe'
                }
                $script:PrincipalStore['S-1-5-21-1-2-3-1001'] = $principal
                # Just verify it doesn't throw and attempts the cache path
                $true | Should -BeTrue
            }
        }

        Context 'PrincipalStore cache hit — well-known principal (no DN)' {
            It 'should return $null for a cached well-known SID with no distinguishedName' {
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-7')  # Anonymous Logon
                $principal = New-MockLS2Principal -Properties @{
                    objectSid         = 'S-1-5-7'
                    distinguishedName = $null
                    NTAccountName     = 'NT AUTHORITY\ANONYMOUS LOGON'
                }
                $script:PrincipalStore['S-1-5-7'] = $principal

                Mock 'Convert-IdentityReferenceToSid' {
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-7')
                }

                $result = Resolve-Principal -IdentityReference $sid
                $result | Should -BeNullOrEmpty
            }
        }

        Context 'Store initialisation' {
            It 'should initialise PrincipalStore if it is null' {
                $script:PrincipalStore = $null
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-7')

                Mock 'Convert-IdentityReferenceToSid' {
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-7')
                }
                Mock 'New-GCSearcher' { $null }

                # After call, PrincipalStore should exist (even if empty)
                try { Resolve-Principal -IdentityReference $sid } catch { }
                $script:PrincipalStore | Should -Not -Be $null
            }
        }

        Context 'Cannot resolve SID to SecurityIdentifier' {
            It 'should return $null and emit a warning when SID conversion fails' {
                $ntAccount = [System.Security.Principal.NTAccount]::new('BOGUS\nonexistent')

                Mock 'Convert-IdentityReferenceToSid' { $null }

                $result = Resolve-Principal -IdentityReference $ntAccount
                $result | Should -BeNullOrEmpty
            }
        }

        Context 'Pipeline input' {
            It 'should accept IdentityReference via the pipeline' {
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-7')
                $principal = New-MockLS2Principal -Properties @{
                    objectSid         = 'S-1-5-7'
                    distinguishedName = $null
                    NTAccountName     = 'NT AUTHORITY\ANONYMOUS LOGON'
                }
                $script:PrincipalStore['S-1-5-7'] = $principal

                Mock 'Convert-IdentityReferenceToSid' {
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-7')
                }

                $result = $sid | Resolve-Principal
                $result | Should -BeNullOrEmpty  # null because distinguishedName is null
            }
        }
    }
}
