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

Describe 'Get-OwningCAHostSid' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeAll {
            $script:pks = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
            $script:hostSid = 'S-1-5-21-1-2-3-1001'
            $script:otherHostSid = 'S-1-5-21-1-2-3-1002'

            function New-TestCA {
                param([string]$Cn, [string]$HostName, [string]$Sid)
                New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', 'pKIEnrollmentService')
                    SchemaClassName   = 'pKIEnrollmentService'
                    cn                = $Cn
                    distinguishedName = "CN=$Cn,CN=Enrollment Services,$($script:pks)"
                    dNSHostName       = $HostName
                    ComputerPrincipal = $Sid
                }
            }
            function New-TestInfraObject {
                param([string]$Cn, [string]$Dn, [string]$Class = 'certificationAuthority')
                New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', $Class)
                    SchemaClassName   = $Class
                    cn                = $Cn
                    distinguishedName = $Dn
                }
            }
        }

        BeforeEach {
            $script:AdcsObjectStore = @{}
            $ca = New-TestCA -Cn 'Contoso-CA' -HostName 'ca01.contoso.com' -Sid $script:hostSid
            $otherCa = New-TestCA -Cn 'Fabrikam-CA' -HostName 'ca02.contoso.com' -Sid $script:otherHostSid
            $script:AdcsObjectStore[$ca.distinguishedName] = $ca
            $script:AdcsObjectStore[$otherCa.distinguishedName] = $otherCa
        }

        It 'returns the CA''s own host SID for a CA object' {
            $ca = $script:AdcsObjectStore.Values | Where-Object cn -eq 'Contoso-CA'
            Get-OwningCAHostSid -AdcsObject $ca | Should -Be $script:hostSid
        }

        It 'returns nothing for a certificate template' {
            $template = New-MockLS2AdcsObject
            Get-OwningCAHostSid -AdcsObject $template | Should -BeNullOrEmpty
        }

        It 'returns nothing for a CA with no resolved ComputerPrincipal' {
            $ca = New-TestCA -Cn 'Orphan-CA' -HostName 'x.contoso.com' -Sid $null
            Get-OwningCAHostSid -AdcsObject $ca | Should -BeNullOrEmpty
        }

        Context 'Objects named after the CA' {
            It 'matches <Name> object for the CA' -ForEach @(
                @{ Name = 'AIA'; Container = 'AIA'; Class = 'certificationAuthority' }
                @{ Name = 'KRA'; Container = 'KRA'; Class = 'msPKI-PrivateKeyRecoveryAgent' }
                @{ Name = 'Certification Authorities'; Container = 'Certification Authorities'; Class = 'certificationAuthority' }
            ) {
                $obj = New-TestInfraObject -Cn 'Contoso-CA' -Class $Class -Dn "CN=Contoso-CA,CN=$Container,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be $script:hostSid
            }

            It 'matches a CA name with a key index suffix' {
                $obj = New-TestInfraObject -Cn 'Contoso-CA(1)' -Dn "CN=Contoso-CA(1),CN=AIA,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be $script:hostSid
            }

            It 'resolves each CA''s AIA object to that CA''s own host' {
                $obj = New-TestInfraObject -Cn 'Fabrikam-CA' -Dn "CN=Fabrikam-CA,CN=AIA,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be $script:otherHostSid
            }

            It 'does not match a similarly named CA' {
                $obj = New-TestInfraObject -Cn 'Contoso-CA2' -Dn "CN=Contoso-CA2,CN=AIA,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }

            It 'does not match a same-named object outside the CA-owned containers' {
                $obj = New-TestInfraObject -Cn 'Contoso-CA' -Class 'container' -Dn "CN=Contoso-CA,CN=Certificate Templates,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }
        }

        Context 'CDP objects' {
            It 'matches the CDP host container' {
                $obj = New-TestInfraObject -Cn 'CA01' -Class 'container' -Dn "CN=CA01,CN=CDP,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be $script:hostSid
            }

            It 'matches a CRL object under the CA''s host container regardless of its name' {
                $obj = New-TestInfraObject -Cn 'Contoso-CA(1)+' -Class 'cRLDistributionPoint' -Dn "CN=Contoso-CA(1)+,CN=CA01,CN=CDP,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be $script:hostSid
            }

            It 'does not match a CRL object under another host''s container' {
                $obj = New-TestInfraObject -Cn 'Legacy-CA' -Class 'cRLDistributionPoint' -Dn "CN=Legacy-CA,CN=OLDHOST,CN=CDP,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }

            It 'does not match the shared CDP container itself' {
                $obj = New-TestInfraObject -Cn 'CDP' -Class 'container' -Dn "CN=CDP,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }
        }
    }
}
