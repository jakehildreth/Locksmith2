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

# ─────────────────────────────────────────────────────────────────────────────
#  Set-DangerousEditor
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-DangerousEditor' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeAll {
            function New-MockAce {
                param(
                    [string]$IdentityReference = 'S-1-5-21-1-2-3-999',
                    [string]$AccessControlType = 'Allow'
                )
                $identity = [System.Security.Principal.SecurityIdentifier]::new($IdentityReference)
                [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                    $identity,
                    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                    [System.Security.AccessControl.AccessControlType]::$AccessControlType
                )
            }
            function New-MockObjectSecurity {
                param([array]$Access = @())
                [PSCustomObject]@{ Access = $Access }
            }
        }

        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Processes ALL object types (no SchemaClassName filter)' {
            It 'should process template objects' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-999'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-999' }
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $true; MatchedPermission = 'GenericAll' } }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $result = $template | Set-DangerousEditor
                $result.DangerousEditor | Should -Contain 'S-1-5-21-1-2-3-999'
            }

            It 'should also process CA objects' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-999'
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                }
                Add-Member -InputObject $ca -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-999' }
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $true; MatchedPermission = 'GenericAll' } }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $result = $ca | Set-DangerousEditor
                $result.DangerousEditor | Should -Contain 'S-1-5-21-1-2-3-999'
            }
        }

        Context 'Test-IsDangerousAce returns IsDangerous=$true and principal is dangerous' {
            It 'should populate DangerousEditor array with SID' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-999'
                $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $obj -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-999' }
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $true; MatchedPermission = 'GenericAll' } }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $result = $obj | Set-DangerousEditor
                $result.DangerousEditor | Should -Contain 'S-1-5-21-1-2-3-999'
            }

            It 'should build DangerousEditorNames from PrincipalStore' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-999'
                $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $obj -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-999' }
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $true; MatchedPermission = 'GenericAll' } }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Resolve-Principal { }
                $script:PrincipalStore['S-1-5-21-1-2-3-999'] = [PSCustomObject]@{ ntAccountName = 'CONTOSO\DangerousUser' }
                $result = $obj | Set-DangerousEditor
                $result.DangerousEditorNames | Should -Contain 'CONTOSO\DangerousUser (S-1-5-21-1-2-3-999)'
            }
        }

        Context 'Test-IsDangerousAce returns IsDangerous=$false' {
            It 'should not include SID when ACE is not a dangerous ACE' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-500'
                $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $obj -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $false; MatchedPermission = $null } }
                Mock Convert-IdentityReferenceToSid { }
                $result = $obj | Set-DangerousEditor
                $result.DangerousEditor | Should -BeNullOrEmpty
                Should -Invoke Convert-IdentityReferenceToSid -Times 0
            }
        }

        Context 'ACE is dangerous but principal is NOT dangerous' {
            It 'should not include SID when principal is not dangerous' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-512'
                $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $obj -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-512' }
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $true; MatchedPermission = 'GenericAll' } }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $false }
                $result = $obj | Set-DangerousEditor
                $result.DangerousEditor | Should -BeNullOrEmpty
            }
        }

        Context 'ObjectClass passed to Test-IsDangerousAce' {
            It 'should pass SchemaClassName as ObjectClass to Test-IsDangerousAce' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-500'
                $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $obj -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $false } } -ParameterFilter { $ObjectClass -eq 'pKICertificateTemplate' }
                $null = $obj | Set-DangerousEditor
                Should -Invoke Test-IsDangerousAce -Times 1 -Exactly -ParameterFilter { $ObjectClass -eq 'pKICertificateTemplate' }
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  Set-LowPrivilegeEditor
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-LowPrivilegeEditor' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeAll {
            function New-MockAce {
                param(
                    [string]$IdentityReference = 'S-1-5-32-545',
                    [string]$AccessControlType = 'Allow'
                )
                $identity = [System.Security.Principal.SecurityIdentifier]::new($IdentityReference)
                [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                    $identity,
                    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                    [System.Security.AccessControl.AccessControlType]::$AccessControlType
                )
            }
            function New-MockObjectSecurity {
                param([array]$Access = @())
                [PSCustomObject]@{ Access = $Access }
            }
        }

        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'Processes ALL object types' {
            It 'should process template objects' {
                $ace = New-MockAce -IdentityReference 'S-1-5-32-545'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-32-545' }
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $true; MatchedPermission = 'WriteDacl' } }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $true }
                Mock Resolve-Principal { }
                $result = $template | Set-LowPrivilegeEditor
                $result.LowPrivilegeEditor | Should -Contain 'S-1-5-32-545'
            }
        }

        Context 'Low-privilege editor found' {
            It 'should populate LowPrivilegeEditor array with SID' {
                $ace = New-MockAce -IdentityReference 'S-1-5-32-545'
                $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $obj -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-32-545' }
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $true; MatchedPermission = 'WriteDacl' } }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $true }
                Mock Resolve-Principal { }
                $result = $obj | Set-LowPrivilegeEditor
                $result.LowPrivilegeEditor | Should -Contain 'S-1-5-32-545'
            }
        }

        Context 'Principal is NOT low-privilege' {
            It 'should not include SID when principal is not low-privilege' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-512'
                $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $obj -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-512' }
                Mock Test-IsDangerousAce { [PSCustomObject]@{ IsDangerous = $true; MatchedPermission = 'GenericAll' } }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $false }
                $result = $obj | Set-LowPrivilegeEditor
                $result.LowPrivilegeEditor | Should -BeNullOrEmpty
            }
        }
    }
}
