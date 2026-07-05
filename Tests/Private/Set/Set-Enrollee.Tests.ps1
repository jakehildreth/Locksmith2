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
#  Set-DangerousEnrollee
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-DangerousEnrollee' -Tag 'Unit' {
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
                    [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
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

        Context 'Non-template objects are skipped' {
            It 'should not process non-template objects' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                }
                Add-Member -InputObject $ca -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @()) -Force
                Mock Convert-IdentityReferenceToSid { }
                Mock Test-IsDangerousPrincipal { }
                $result = $ca | Set-DangerousEnrollee
                Should -Invoke Convert-IdentityReferenceToSid -Times 0
            }
        }

        Context 'Dangerous enrollee found' {
            It 'should populate DangerousEnrollee array with SID when principal is dangerous and has enrollment ACE' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-999'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-999' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Test-IsEnrollmentAce { $true }
                Mock Resolve-Principal { }
                $result = $template | Set-DangerousEnrollee
                $result.DangerousEnrollee | Should -Contain 'S-1-5-21-1-2-3-999'
            }

            It 'should build DangerousEnrolleeNames from PrincipalStore when SID is known' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-999'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-999' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Test-IsEnrollmentAce { $true }
                Mock Resolve-Principal { }
                $script:PrincipalStore['S-1-5-21-1-2-3-999'] = [PSCustomObject]@{ ntAccountName = 'CONTOSO\DangerousUser' }
                $result = $template | Set-DangerousEnrollee
                $result.DangerousEnrolleeNames | Should -Contain 'CONTOSO\DangerousUser (S-1-5-21-1-2-3-999)'
            }

            It 'should use (could not resolve) in DangerousEnrolleeNames when SID not in PrincipalStore' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-999'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-999' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Test-IsEnrollmentAce { $true }
                Mock Resolve-Principal { }
                $result = $template | Set-DangerousEnrollee
                $result.DangerousEnrolleeNames | Should -Contain 'S-1-5-21-1-2-3-999 (could not resolve)'
            }
        }

        Context 'Principal is dangerous but ACE is not an enrollment ACE' {
            It 'should not include SID in DangerousEnrollee when ACE is not an enrollment ACE' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-999'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-999' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $true }
                Mock Test-IsEnrollmentAce { $false }
                Mock Resolve-Principal { }
                $result = $template | Set-DangerousEnrollee
                $result.DangerousEnrollee | Should -BeNullOrEmpty
            }
        }

        Context 'Principal is NOT dangerous' {
            It 'should not include SID in DangerousEnrollee when principal is not dangerous' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-500'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-500' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsDangerousPrincipal { $false }
                Mock Test-IsEnrollmentAce { }
                $result = $template | Set-DangerousEnrollee
                $result.DangerousEnrollee | Should -BeNullOrEmpty
                Should -Invoke Test-IsEnrollmentAce -Times 0
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
#  Set-LowPrivilegeEnrollee
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Set-LowPrivilegeEnrollee' -Tag 'Unit' {
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
                    [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
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

        Context 'Non-template objects are skipped' {
            It 'should not process non-template objects' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                }
                Add-Member -InputObject $ca -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @()) -Force
                Mock Convert-IdentityReferenceToSid { }
                Mock Test-IsLowPrivilegePrincipal { }
                $result = $ca | Set-LowPrivilegeEnrollee
                Should -Invoke Convert-IdentityReferenceToSid -Times 0
            }
        }

        Context 'Low-privilege enrollee found' {
            It 'should populate LowPrivilegeEnrollee array when principal is low-privilege with enrollment ACE' {
                $ace = New-MockAce -IdentityReference 'S-1-5-32-545'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-32-545' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $true }
                Mock Test-IsEnrollmentAce { $true }
                Mock Resolve-Principal { }
                $result = $template | Set-LowPrivilegeEnrollee
                $result.LowPrivilegeEnrollee | Should -Contain 'S-1-5-32-545'
            }

            It 'should build LowPrivilegeEnrolleeNames from PrincipalStore' {
                $ace = New-MockAce -IdentityReference 'S-1-5-32-545'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-32-545' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $true }
                Mock Test-IsEnrollmentAce { $true }
                Mock Resolve-Principal { }
                $script:PrincipalStore['S-1-5-32-545'] = [PSCustomObject]@{ ntAccountName = 'BUILTIN\Users' }
                $result = $template | Set-LowPrivilegeEnrollee
                $result.LowPrivilegeEnrolleeNames | Should -Contain 'BUILTIN\Users (S-1-5-32-545)'
            }
        }

        Context 'Principal is NOT low-privilege' {
            It 'should not include SID when principal is not low-privilege' {
                $ace = New-MockAce -IdentityReference 'S-1-5-21-1-2-3-512'
                $template = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKICertificateTemplate' }
                Add-Member -InputObject $template -MemberType NoteProperty -Name 'ObjectSecurity' -Value (New-MockObjectSecurity -Access @($ace)) -Force
                $mockSid = [PSCustomObject]@{ Value = 'S-1-5-21-1-2-3-512' }
                Mock Convert-IdentityReferenceToSid { $mockSid }
                Mock Test-IsLowPrivilegePrincipal { $false }
                $result = $template | Set-LowPrivilegeEnrollee
                $result.LowPrivilegeEnrollee | Should -BeNullOrEmpty
            }
        }
    }
}
