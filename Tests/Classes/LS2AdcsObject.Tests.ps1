#requires -Version 5.1
BeforeAll {
    $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
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

    Describe 'CA identity helpers' {
        BeforeAll {
            function New-DerElement {
                param([byte]$Tag, [byte[]]$Content)
                $len = $Content.Length
                $lenBytes = if ($len -lt 128) { , [byte]$len }
                elseif ($len -lt 256) { [byte[]](0x81, $len) }
                else { [byte[]](0x82, ($len -shr 8), ($len -band 0xFF)) }
                [byte[]](@($Tag) + $lenBytes + $Content)
            }

            # Minimal CertificateList: only the parts the parser walks (tbsCertList up to issuer)
            function New-TestCrl {
                param([string]$IssuerDn, [switch]$WithVersion)
                $issuer = ([System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($IssuerDn)).RawData
                $sigAlg = New-DerElement 0x30 ([byte[]](0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00))
                $thisUpdate = New-DerElement 0x17 ([System.Text.Encoding]::ASCII.GetBytes('260101000000Z'))
                $version = if ($WithVersion) { [byte[]](0x02, 0x01, 0x01) } else { [byte[]]@() }
                $tbs = New-DerElement 0x30 ([byte[]]($version + $sigAlg + $issuer + $thisUpdate))
                New-DerElement 0x30 ([byte[]]($tbs + $sigAlg + [byte[]](0x03, 0x02, 0x00, 0x00)))
            }

            function New-TestCaCertBytes {
                param([string]$SubjectDn)
                $rsa = [System.Security.Cryptography.RSA]::Create(2048)
                $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    $SubjectDn, $rsa,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))
                $cert.RawData
            }
        }

        Describe 'GetCRLIssuer()' {
            It 'should return the issuer DN from a CRL' {
                $crl = New-TestCrl -IssuerDn 'CN=Contoso-CA, DC=contoso, DC=com'
                [LS2AdcsObject]::GetCRLIssuer($crl) | Should -Be ([System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=Contoso-CA, DC=contoso, DC=com')).Name
            }

            It 'should skip the optional version field' {
                $crl = New-TestCrl -IssuerDn 'CN=Contoso-CA, DC=contoso, DC=com' -WithVersion
                [LS2AdcsObject]::GetCRLIssuer($crl) | Should -Be ([System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=Contoso-CA, DC=contoso, DC=com')).Name
            }

            It 'should handle long-form lengths' {
                $longDn = 'CN=' + ('A' * 150) + ', DC=contoso, DC=com'
                $crl = New-TestCrl -IssuerDn $longDn
                [LS2AdcsObject]::GetCRLIssuer($crl) | Should -Be ([System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($longDn)).Name
            }

            It 'should return null for garbage' {
                [LS2AdcsObject]::GetCRLIssuer([byte[]](1, 2, 3)) | Should -BeNullOrEmpty
            }

            It 'should return null for an empty array' {
                [LS2AdcsObject]::GetCRLIssuer([byte[]]@()) | Should -BeNullOrEmpty
            }
        }

        Describe 'GetCertificateSubjects()' {
            It 'should return the subject of each certificate' {
                $a = New-TestCaCertBytes -SubjectDn 'CN=Contoso-CA, DC=contoso, DC=com'
                $b = New-TestCaCertBytes -SubjectDn 'CN=Fabrikam-CA, DC=contoso, DC=com'
                $subjects = [LS2AdcsObject]::GetCertificateSubjects(@($a, $b))
                $subjects | Should -Contain ([System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=Contoso-CA, DC=contoso, DC=com')).Name
                $subjects | Should -Contain ([System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=Fabrikam-CA, DC=contoso, DC=com')).Name
            }

            It 'should collapse renewed certificates with the same subject' {
                $a = New-TestCaCertBytes -SubjectDn 'CN=Contoso-CA, DC=contoso, DC=com'
                $b = New-TestCaCertBytes -SubjectDn 'CN=Contoso-CA, DC=contoso, DC=com'
                @([LS2AdcsObject]::GetCertificateSubjects(@($a, $b))).Count | Should -Be 1
            }

            It 'should skip values that are not certificates' {
                $a = New-TestCaCertBytes -SubjectDn 'CN=Contoso-CA, DC=contoso, DC=com'
                @([LS2AdcsObject]::GetCertificateSubjects(@([byte[]](1, 2, 3), $a))).Count | Should -Be 1
            }
        }

        It 'should match a CRL issuer to the subject of that CA''s certificate' {
            $cert = New-TestCaCertBytes -SubjectDn 'CN=Contoso-CA, DC=contoso, DC=com'
            $crl = New-TestCrl -IssuerDn 'CN=Contoso-CA, DC=contoso, DC=com'
            [LS2AdcsObject]::GetCertificateSubjects(@(, $cert)) | Should -Contain ([LS2AdcsObject]::GetCRLIssuer($crl))
        }
    }
}
