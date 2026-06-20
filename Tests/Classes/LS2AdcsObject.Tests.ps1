#requires -Version 5.1
BeforeAll {
    $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'LS2AdcsObject class' -Tag 'Unit' {

    Describe 'IsCertificateTemplate()' {
        It 'should return true when SchemaClassName is pKICertificateTemplate' {
            $obj = New-MockLS2AdcsObject
            $obj.IsCertificateTemplate() | Should -BeTrue
        }

        It 'should return false when SchemaClassName is pKIEnrollmentService' {
            $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'pKIEnrollmentService' }
            $obj.IsCertificateTemplate() | Should -BeFalse
        }

        It 'should return false when SchemaClassName is container' {
            $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = 'container' }
            $obj.IsCertificateTemplate() | Should -BeFalse
        }

        It 'should return false when SchemaClassName is null' -Tag 'EdgeCase' {
            $obj = New-MockLS2AdcsObject -Properties @{ SchemaClassName = $null }
            $obj.IsCertificateTemplate() | Should -BeFalse
        }
    }

    Describe 'IsCertificationAuthority()' {
        It 'should return true when objectClass contains pKIEnrollmentService' {
            $obj = New-MockLS2AdcsObject -Properties @{
                objectClass     = @('top', 'pKIEnrollmentService')
                SchemaClassName = 'pKIEnrollmentService'
            }
            $obj.IsCertificationAuthority() | Should -BeTrue
        }

        It 'should return false when objectClass does not contain pKIEnrollmentService' {
            $obj = New-MockLS2AdcsObject
            $obj.IsCertificationAuthority() | Should -BeFalse
        }

        It 'should return false for a container objectClass' {
            $obj = New-MockLS2AdcsObject -Properties @{
                objectClass     = @('top', 'container')
                SchemaClassName = 'container'
            }
            $obj.IsCertificationAuthority() | Should -BeFalse
        }

        It 'should return false for an empty objectClass array' -Tag 'EdgeCase' {
            $obj = New-MockLS2AdcsObject -Properties @{ objectClass = @() }
            $obj.IsCertificationAuthority() | Should -BeFalse
        }
    }

    Describe 'GetFriendlyName()' {
        It 'should return displayName when it is set' {
            $obj = New-MockLS2AdcsObject -Properties @{ displayName = 'My Display Name' }
            $obj.GetFriendlyName() | Should -Be 'My Display Name'
        }

        It 'should return name when displayName is null' {
            $obj = New-MockLS2AdcsObject -Properties @{
                displayName = $null
                name        = 'MyName'
            }
            $obj.GetFriendlyName() | Should -Be 'MyName'
        }

        It 'should return cn when displayName and name are null' {
            $obj = New-MockLS2AdcsObject -Properties @{
                displayName = $null
                name        = $null
                cn          = 'MyCN'
            }
            $obj.GetFriendlyName() | Should -Be 'MyCN'
        }

        It 'should return distinguishedName when displayName, name, and cn are all null' {
            $obj = New-MockLS2AdcsObject -Properties @{
                displayName       = $null
                name              = $null
                cn                = $null
                distinguishedName = 'CN=Fallback,DC=contoso,DC=com'
            }
            $obj.GetFriendlyName() | Should -Be 'CN=Fallback,DC=contoso,DC=com'
        }

        It 'should prefer displayName over all other properties' {
            $obj = New-MockLS2AdcsObject -Properties @{
                displayName       = 'Winner'
                name              = 'Loser1'
                cn                = 'Loser2'
                distinguishedName = 'CN=Loser3,DC=contoso,DC=com'
            }
            $obj.GetFriendlyName() | Should -Be 'Winner'
        }
    }

    Describe 'Computed property read/write via GetUninitializedObject' {
        It 'should allow SANAllowed to be set to $true and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ SANAllowed = $true }
            $obj.SANAllowed | Should -BeTrue
        }

        It 'should allow SANAllowed to be set to $false and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ SANAllowed = $false }
            $obj.SANAllowed | Should -BeFalse
        }

        It 'should allow AuthenticationEKUExist to be set and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ AuthenticationEKUExist = $true }
            $obj.AuthenticationEKUExist | Should -BeTrue
        }

        It 'should allow ManagerApprovalNotRequired to be set and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ ManagerApprovalNotRequired = $false }
            $obj.ManagerApprovalNotRequired | Should -BeFalse
        }

        It 'should allow DangerousEnrollee to be set as an array and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ DangerousEnrollee = @('S-1-1-0', 'S-1-5-11') }
            $obj.DangerousEnrollee | Should -Contain 'S-1-1-0'
            $obj.DangerousEnrollee | Should -Contain 'S-1-5-11'
        }

        It 'should default DangerousEnrollee to an empty array' {
            $obj = New-MockLS2AdcsObject
            ($null -eq $obj.DangerousEnrollee) | Should -BeFalse -Because 'DangerousEnrollee should be initialized as @(), not $null'
            $obj.DangerousEnrollee.Count | Should -Be 0
        }

        It 'should default LowPrivilegeEnrollee to an empty array' {
            $obj = New-MockLS2AdcsObject
            $obj.LowPrivilegeEnrollee.Count | Should -Be 0
        }

        It 'should default DangerousEditor to an empty array' {
            $obj = New-MockLS2AdcsObject
            $obj.DangerousEditor.Count | Should -Be 0
        }

        It 'should allow Enabled to be set to $true and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ Enabled = $true }
            $obj.Enabled | Should -BeTrue
        }

        It 'should allow RPCEncryptionNotRequired to be set and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ RPCEncryptionNotRequired = $true }
            $obj.RPCEncryptionNotRequired | Should -BeTrue
        }

        It 'should allow SANFlagEnabled to be set and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ SANFlagEnabled = $true }
            $obj.SANFlagEnabled | Should -BeTrue
        }

        It 'should allow CAFullName to be set and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ CAFullName = 'dc01.contoso.com\My-CA' }
            $obj.CAFullName | Should -Be 'dc01.contoso.com\My-CA'
        }

        It 'should allow SecurityExtensionDisabled to be set and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ SecurityExtensionDisabled = $true }
            $obj.SecurityExtensionDisabled | Should -BeTrue
        }

        It 'should allow AuditFilter to be set to an integer and read back' {
            $obj = New-MockLS2AdcsObject -Properties @{ AuditFilter = 127 }
            $obj.AuditFilter | Should -Be 127
        }
    }
}
