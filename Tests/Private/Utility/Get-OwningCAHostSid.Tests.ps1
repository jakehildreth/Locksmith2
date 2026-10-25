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
                param([string]$Cn, [string]$HostName, [string]$Sid, [string[]]$Subject = @())
                New-MockLS2AdcsObject -Properties @{
                    objectClass          = @('top', 'pKIEnrollmentService')
                    SchemaClassName      = 'pKIEnrollmentService'
                    cn                   = $Cn
                    distinguishedName    = "CN=$Cn,CN=Enrollment Services,$($script:pks)"
                    dNSHostName          = $HostName
                    ComputerPrincipal    = $Sid
                    CACertificateSubject = $Subject
                }
            }
            function New-TestInfraObject {
                param([string]$Cn, [string]$Dn, [string]$Class = 'certificationAuthority', [string[]]$Subject = @(), [string]$CrlIssuer)
                New-MockLS2AdcsObject -Properties @{
                    objectClass          = @('top', $Class)
                    SchemaClassName      = $Class
                    cn                   = $Cn
                    distinguishedName    = $Dn
                    CACertificateSubject = $Subject
                    CRLIssuer            = $CrlIssuer
                }
            }
        }

        BeforeEach {
            $script:AdcsObjectStore = @{}
            $ca = New-TestCA -Cn 'Contoso-CA' -HostName 'ca01.contoso.com' -Sid $script:hostSid -Subject 'CN=Contoso-CA, DC=contoso, DC=com'
            $otherCa = New-TestCA -Cn 'Fabrikam-CA' -HostName 'ca02.contoso.com' -Sid $script:otherHostSid -Subject 'CN=Fabrikam-CA, DC=contoso, DC=com'
            $script:AdcsObjectStore[$ca.distinguishedName] = $ca
            $script:AdcsObjectStore[$otherCa.distinguishedName] = $otherCa
        }

        Context 'Certificate and CRL identity' {
            It 'matches an AIA object whose certificate subject is the CA''s' {
                $obj = New-TestInfraObject -Cn 'Contoso-CA' -Dn "CN=Contoso-CA,CN=AIA,$($script:pks)" -Subject 'CN=Contoso-CA, DC=contoso, DC=com'
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be $script:hostSid
            }

            It 'does not match an AIA object named for the CA but holding another CA''s certificate' {
                $obj = New-TestInfraObject -Cn 'Contoso-CA' -Dn "CN=Contoso-CA,CN=AIA,$($script:pks)" -Subject 'CN=Rogue-CA, DC=contoso, DC=com'
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }

            It 'matches a CRL object by issuer even when its name does not follow the CA name' {
                $obj = New-TestInfraObject -Cn 'Renamed-CA(1)' -Class 'cRLDistributionPoint' -Dn "CN=Renamed-CA(1),CN=CA01,CN=CDP,$($script:pks)" -CrlIssuer 'CN=Contoso-CA, DC=contoso, DC=com'
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be $script:hostSid
            }

            It 'does not match a CRL object named for the CA but issued by another CA' {
                $obj = New-TestInfraObject -Cn 'Contoso-CA(1)' -Class 'cRLDistributionPoint' -Dn "CN=Contoso-CA(1),CN=CA01,CN=CDP,$($script:pks)" -CrlIssuer 'CN=Fabrikam-CA, DC=contoso, DC=com'
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }

            It 'does not match a CRL issued by the CA when it sits in another host''s container' {
                $obj = New-TestInfraObject -Cn 'Contoso-CA(1)' -Class 'cRLDistributionPoint' -Dn "CN=Contoso-CA(1),CN=OLDHOST,CN=CDP,$($script:pks)" -CrlIssuer 'CN=Contoso-CA, DC=contoso, DC=com'
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }

            It 'falls back to the name when the CA has no certificate subject on record' {
                $noCert = New-TestCA -Cn 'Bare-CA' -HostName 'ca03.contoso.com' -Sid 'S-1-5-21-1-2-3-1003'
                $script:AdcsObjectStore[$noCert.distinguishedName] = $noCert
                $obj = New-TestInfraObject -Cn 'Bare-CA' -Dn "CN=Bare-CA,CN=AIA,$($script:pks)" -Subject 'CN=Bare-CA, DC=contoso, DC=com'
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be 'S-1-5-21-1-2-3-1003'
            }
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

            It 'matches a CRL or delta CRL object named for the CA' -ForEach @(
                @{ Cn = 'Contoso-CA' }
                @{ Cn = 'Contoso-CA(1)' }
                @{ Cn = 'Contoso-CA(1)+' }
            ) {
                $obj = New-TestInfraObject -Cn $Cn -Class 'cRLDistributionPoint' -Dn "CN=$Cn,CN=CA01,CN=CDP,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be $script:hostSid
            }

            It 'does not match a CRL object named for a different CA under the same host container' {
                $obj = New-TestInfraObject -Cn 'Legacy-CA(1)' -Class 'cRLDistributionPoint' -Dn "CN=Legacy-CA(1),CN=CA01,CN=CDP,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }

            It 'does not match a CRL object under another host''s container' {
                $obj = New-TestInfraObject -Cn 'Legacy-CA' -Class 'cRLDistributionPoint' -Dn "CN=Legacy-CA,CN=OLDHOST,CN=CDP,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }

            It 'does not match the shared CDP container itself' {
                $obj = New-TestInfraObject -Cn 'CDP' -Class 'container' -Dn "CN=CDP,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
            }

            Context 'Two CAs whose hosts share a short name' {
                BeforeEach {
                    $twin = New-TestCA -Cn 'Child-CA' -HostName 'ca01.child.contoso.com' -Sid 'S-1-5-21-9-9-9-1001'
                    $script:AdcsObjectStore[$twin.distinguishedName] = $twin
                }

                It 'returns both hosts for the shared host container itself' {
                    $obj = New-TestInfraObject -Cn 'CA01' -Class 'container' -Dn "CN=CA01,CN=CDP,$($script:pks)"
                    $sids = @(Get-OwningCAHostSid -AdcsObject $obj)
                    $sids | Should -Contain $script:hostSid
                    $sids | Should -Contain 'S-1-5-21-9-9-9-1001'
                }

                It 'returns only the owning CA''s host for a CRL object inside it' -ForEach @(
                    @{ Cn = 'Contoso-CA(1)'; Expected = 'S-1-5-21-1-2-3-1001' }
                    @{ Cn = 'Child-CA(1)+'; Expected = 'S-1-5-21-9-9-9-1001' }
                ) {
                    $obj = New-TestInfraObject -Cn $Cn -Class 'cRLDistributionPoint' -Dn "CN=$Cn,CN=CA01,CN=CDP,$($script:pks)"
                    @(Get-OwningCAHostSid -AdcsObject $obj) | Should -Be @($Expected)
                }
            }
        }

        Context 'Cost on objects no CA can own' {
            BeforeEach {
                $script:valuesReads = 0
                $store = [PSCustomObject]@{ Inner = $script:AdcsObjectStore }
                Add-Member -InputObject $store -MemberType ScriptProperty -Name Values -Value {
                    $script:valuesReads++
                    $this.Inner.Values
                }
                $script:AdcsObjectStore = $store
            }

            It 'does not scan the object store for <Name>' -ForEach @(
                @{ Name = 'a certificate template'; Dn = 'CN=T1,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com' }
                @{ Name = 'the shared CDP container'; Dn = 'CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com' }
                @{ Name = 'the AIA container'; Dn = 'CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com' }
            ) {
                $obj = New-TestInfraObject -Cn 'Contoso-CA' -Class 'container' -Dn $Dn
                Get-OwningCAHostSid -AdcsObject $obj | Should -BeNullOrEmpty
                $script:valuesReads | Should -Be 0
            }

            It 'still resolves an AIA object after the early exit' {
                $obj = New-TestInfraObject -Cn 'Contoso-CA' -Dn "CN=Contoso-CA,CN=AIA,$($script:pks)"
                Get-OwningCAHostSid -AdcsObject $obj | Should -Be $script:hostSid
            }
        }
    }
}
