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

Describe 'Initialize-AdcsObjectStore' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:AdcsObjectStore = @{}
            $script:PrincipalStore  = @{}
            $script:DomainStore     = @{}

            $securePass = ConvertTo-SecureString 'password' -AsPlainText -Force
            $script:Credential = [System.Management.Automation.PSCredential]::new('CONTOSO\admin', $securePass)

            $fakeRootDSE = [PSCustomObject]@{}
            $fakeRootDSE | Add-Member -MemberType NoteProperty -Name 'configurationNamingContext' -Value (
                [PSCustomObject]@{ Value = 'CN=Configuration,DC=contoso,DC=com' }
            )
            $script:RootDSE = $fakeRootDSE
        }

        Context 'Missing prerequisites' {
            It 'should return without error when Credential is null' {
                $script:Credential = $null
                { Initialize-AdcsObjectStore } | Should -Not -Throw
            }

            It 'should return without populating store when Credential is null' {
                $script:Credential = $null
                Initialize-AdcsObjectStore
                $script:AdcsObjectStore.Count | Should -Be 0
            }

            It 'should return without error when RootDSE is null' {
                $script:RootDSE = $null
                { Initialize-AdcsObjectStore } | Should -Not -Throw
            }

            It 'should return without populating store when RootDSE is null' {
                $script:RootDSE = $null
                Initialize-AdcsObjectStore
                $script:AdcsObjectStore.Count | Should -Be 0
            }
        }

        Context 'Template pipeline processing' {
            It 'should call Set-SANAllowed for certificate templates' {
                $template = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKICertificateTemplate')
                    SchemaClassName = 'pKICertificateTemplate'
                }
                $script:AdcsObjectStore[$template.distinguishedName] = $template

                Mock 'Get-AdcsObject' { }  # AdcsObjectStore already pre-populated
                Mock 'Set-SANAllowed' { $input }
                Mock 'Set-AuthenticationEKUExist' { $input }
                Mock 'Set-AnyPurposeEKUExist' { $input }
                Mock 'Set-EnrollmentAgentEKUExist' { $input }
                Mock 'Set-RequiresEnrollmentAgentSignature' { $input }
                Mock 'Set-NoSecurityExtension' { $input }
                Mock 'Set-DangerousEnrollee' { $input }
                Mock 'Set-LowPrivilegeEnrollee' { $input }
                Mock 'Set-DangerousEditor' { $input }
                Mock 'Set-LowPrivilegeEditor' { $input }
                Mock 'Set-ManagerApprovalNotRequired' { $input }
                Mock 'Set-AuthorizedSignatureNotRequired' { $input }
                Mock 'Set-TemplateEnabled' { $input }
                Mock 'Set-Owner' { $input }
                Mock 'Set-HasNonStandardOwner' { $input }
                Mock 'Set-CAComputerPrincipal' { $input }
                Mock 'Set-CAInterfaceFlags' { $input }
                Mock 'Set-CAEditFlags' { $input }
                Mock 'Set-CAAuditFilter' { $input }
                Mock 'Set-CADisableExtensionList' { $input }
                Mock 'Set-CAAdministrator' { $input }
                Mock 'Set-CACertificateManager' { $input }
                Mock 'Set-DangerousCAAdministrator' { $input }
                Mock 'Set-LowPrivilegeCAAdministrator' { $input }
                Mock 'Set-DangerousCACertificateManager' { $input }
                Mock 'Set-LowPrivilegeCACertificateManager' { $input }

                Initialize-AdcsObjectStore
                Should -Invoke 'Set-SANAllowed' -Times 1
            }
        }

        Context 'CA pipeline processing' {
            It 'should call Set-CAComputerPrincipal for CA objects' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                }
                $script:AdcsObjectStore[$ca.distinguishedName] = $ca

                Mock 'Get-AdcsObject' { }
                Mock 'Set-SANAllowed' { $input }
                Mock 'Set-AuthenticationEKUExist' { $input }
                Mock 'Set-AnyPurposeEKUExist' { $input }
                Mock 'Set-EnrollmentAgentEKUExist' { $input }
                Mock 'Set-RequiresEnrollmentAgentSignature' { $input }
                Mock 'Set-NoSecurityExtension' { $input }
                Mock 'Set-DangerousEnrollee' { $input }
                Mock 'Set-LowPrivilegeEnrollee' { $input }
                Mock 'Set-DangerousEditor' { $input }
                Mock 'Set-LowPrivilegeEditor' { $input }
                Mock 'Set-ManagerApprovalNotRequired' { $input }
                Mock 'Set-AuthorizedSignatureNotRequired' { $input }
                Mock 'Set-TemplateEnabled' { $input }
                Mock 'Set-Owner' { $input }
                Mock 'Set-HasNonStandardOwner' { $input }
                Mock 'Set-CAComputerPrincipal' { $input }
                Mock 'Set-CAInterfaceFlags' { $input }
                Mock 'Set-CAEditFlags' { $input }
                Mock 'Set-CAAuditFilter' { $input }
                Mock 'Set-CADisableExtensionList' { $input }
                Mock 'Set-CAAdministrator' { $input }
                Mock 'Set-CACertificateManager' { $input }
                Mock 'Set-DangerousCAAdministrator' { $input }
                Mock 'Set-LowPrivilegeCAAdministrator' { $input }
                Mock 'Set-DangerousCACertificateManager' { $input }
                Mock 'Set-LowPrivilegeCACertificateManager' { $input }

                Initialize-AdcsObjectStore
                Should -Invoke 'Set-CAComputerPrincipal' -Times 1
            }
        }
    }
}
