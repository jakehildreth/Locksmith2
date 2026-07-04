#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {
    Describe 'Find-LS2VulnerableCA' -Tag 'Unit' {
        BeforeAll {
            $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $script:ESCDefs = $script:ESCDefinitions
        }

        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
            Mock 'Initialize-LS2Scan' { $true }
            Mock 'Expand-IssueByGroup' { $Issue }
        }

        Context 'Path A — no Technique specified' {
            BeforeEach {
                $caIssue = [LS2Issue]@{
                    Technique = 'ESC6'; Forest = 'contoso.com'; Name = 'TestCA'
                    DistinguishedName = 'CN=TestCA,...'; ObjectClass = 'pKIEnrollmentService'
                }
                $templateIssue = [LS2Issue]@{
                    Technique = 'ESC1'; Forest = 'contoso.com'; Name = 'VulnTemplate'
                    DistinguishedName = 'CN=VulnTemplate,...'; ObjectClass = 'pKICertificateTemplate'
                    IdentityReference = 'Everyone'
                }
                Mock 'Get-FlattenedIssues' { @($caIssue, $templateIssue) }
            }

            It 'should return only CA-technique issues when no Technique specified' {
                $result = @(Find-LS2VulnerableCA)
                $result.Count | Should -Be 1
                $result[0].Technique | Should -Be 'ESC6'
            }

            It 'should not return template-technique issues when no Technique specified' {
                $result = @(Find-LS2VulnerableCA)
                $result.Technique | Should -Not -Contain 'ESC1'
            }

            It 'should call Expand-IssueByGroup per CA issue when -ExpandGroups is specified' {
                Find-LS2VulnerableCA -ExpandGroups | Out-Null
                Should -Invoke 'Expand-IssueByGroup' -Times 1
            }

            It 'should return nothing when Initialize-LS2Scan returns false' {
                Mock 'Initialize-LS2Scan' { $false }
                $result = @(Find-LS2VulnerableCA)
                $result.Count | Should -Be 0
            }
        }

        Context 'Path B — ESC6 condition-based scan' {
            BeforeEach {
                Mock 'Test-IssueExists' { $false }
            }

            It 'should return an LS2Issue when CA matches all ESC6 conditions' {
                $mockCA = New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', 'pKIEnrollmentService')
                    SchemaClassName   = 'pKIEnrollmentService'
                    CAFullName        = 'CONTOSO\CA01'
                    cn                = 'CA01'
                    distinguishedName = 'CN=CA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                }
                foreach ($condition in $script:ESCDefs.ESC6.Conditions) {
                    $mockCA.($condition.Property) = $condition.Value
                }
                $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                $result = @(Find-LS2VulnerableCA -Technique 'ESC6')
                $result.Count | Should -Be 1
                $result[0].Technique | Should -Be 'ESC6'
            }

            It 'should skip a CA where any ESC6 condition is not met' {
                $safeCA = New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', 'pKIEnrollmentService')
                    SchemaClassName   = 'pKIEnrollmentService'
                    CAFullName        = 'CONTOSO\SafeCA'
                    cn                = 'SafeCA'
                    distinguishedName = 'CN=SafeCA,...'
                }
                $firstCond = $script:ESCDefs.ESC6.Conditions[0]
                $safeCA.($firstCond.Property) = -not $firstCond.Value
                $script:AdcsObjectStore = @{ $safeCA.distinguishedName = $safeCA }
                $result = @(Find-LS2VulnerableCA -Technique 'ESC6')
                $result.Count | Should -Be 0
            }

            It 'should skip a CA with no CAFullName when conditions are met' {
                $noNameCA = New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', 'pKIEnrollmentService')
                    SchemaClassName   = 'pKIEnrollmentService'
                    cn                = 'CA01'
                    distinguishedName = 'CN=CA01,...'
                }
                foreach ($condition in $script:ESCDefs.ESC6.Conditions) {
                    $noNameCA.($condition.Property) = $condition.Value
                }
                $script:AdcsObjectStore = @{ $noNameCA.distinguishedName = $noNameCA }
                $result = @(Find-LS2VulnerableCA -Technique 'ESC6')
                $result.Count | Should -Be 0
            }
        }

        Context 'Path B — ESC7a role-based scan' {
            BeforeEach {
                Mock 'Test-IssueExists' { $false }
            }

            It 'should return an LS2Issue when CA has dangerous administrator assigned' {
                $mockCA = New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', 'pKIEnrollmentService')
                    SchemaClassName   = 'pKIEnrollmentService'
                    CAFullName        = 'CONTOSO\CA01'
                    cn                = 'CA01'
                    distinguishedName = 'CN=CA01,...'
                }
                foreach ($adminProp in $script:ESCDefs.ESC7a.AdminProperties) {
                    $mockCA.$adminProp = @('S-1-1-0')
                }
                $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                $result = @(Find-LS2VulnerableCA -Technique 'ESC7a')
                $result.Count | Should -BeGreaterOrEqual 1
                $result[0].Technique | Should -Be 'ESC7a'
            }

            It 'should return nothing when Initialize-LS2Scan returns false' {
                Mock 'Initialize-LS2Scan' { $false }
                $result = @(Find-LS2VulnerableCA -Technique 'ESC7a')
                $result.Count | Should -Be 0
            }
        }

        Context 'Path C — ESC8 endpoint-based scan' {
            BeforeEach {
                Mock 'Test-IssueExists' { $false }
            }

            Context 'HTTP endpoint always a finding' {
                It 'should return one LS2Issue for an HTTP certsrv endpoint' {
                    $mockCA = New-MockLS2AdcsObject -Properties @{
                        objectClass            = @('top', 'pKIEnrollmentService')
                        SchemaClassName        = 'pKIEnrollmentService'
                        CAFullName             = 'CONTOSO\CA01'
                        cn                     = 'CA01'
                        distinguishedName      = 'CN=CA01,...'
                        WebEnrollmentEndpoints = @(
                            [PSCustomObject]@{ URL = 'http://ca1.contoso.com/certsrv/'; NtlmOffered = $null; EpaNotRequired = $null }
                        )
                    }
                    $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result.Count | Should -Be 1
                    $result[0].Technique | Should -Be 'ESC8'
                }

                It 'should set Technique to ESC8 on the returned issue' {
                    $mockCA = New-MockLS2AdcsObject -Properties @{
                        objectClass            = @('top', 'pKIEnrollmentService')
                        SchemaClassName        = 'pKIEnrollmentService'
                        CAFullName             = 'CONTOSO\CA01'
                        cn                     = 'CA01'
                        distinguishedName      = 'CN=CA01,...'
                        WebEnrollmentEndpoints = @(
                            [PSCustomObject]@{ URL = 'http://ca1.contoso.com/certsrv/'; NtlmOffered = $null; EpaNotRequired = $null }
                        )
                    }
                    $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result[0].Technique | Should -Be 'ESC8'
                }
            }

            Context 'HTTPS endpoint with NTLM offered' {
                It 'should return one LS2Issue for an HTTPS endpoint where NtlmOffered is true' {
                    $mockCA = New-MockLS2AdcsObject -Properties @{
                        objectClass            = @('top', 'pKIEnrollmentService')
                        SchemaClassName        = 'pKIEnrollmentService'
                        CAFullName             = 'CONTOSO\CA01'
                        cn                     = 'CA01'
                        distinguishedName      = 'CN=CA01,...'
                        WebEnrollmentEndpoints = @(
                            [PSCustomObject]@{ URL = 'https://ca1.contoso.com/certsrv/'; NtlmOffered = $true; EpaNotRequired = $false }
                        )
                    }
                    $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result.Count | Should -Be 1
                }
            }

            Context 'HTTPS endpoint where EPA is not required (Kerberos relay)' {
                It 'should return one LS2Issue for an HTTPS endpoint where EpaNotRequired is true' {
                    $mockCA = New-MockLS2AdcsObject -Properties @{
                        objectClass            = @('top', 'pKIEnrollmentService')
                        SchemaClassName        = 'pKIEnrollmentService'
                        CAFullName             = 'CONTOSO\CA01'
                        cn                     = 'CA01'
                        distinguishedName      = 'CN=CA01,...'
                        WebEnrollmentEndpoints = @(
                            [PSCustomObject]@{ URL = 'https://ca1.contoso.com/certsrv/'; NtlmOffered = $false; EpaNotRequired = $true }
                        )
                    }
                    $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result.Count | Should -Be 1
                }
            }

            Context 'HTTPS endpoint with NTLM and Kerberos relay both applicable' {
                It 'should return one LS2Issue (not two) when both NtlmOffered and EpaNotRequired are true' {
                    $mockCA = New-MockLS2AdcsObject -Properties @{
                        objectClass            = @('top', 'pKIEnrollmentService')
                        SchemaClassName        = 'pKIEnrollmentService'
                        CAFullName             = 'CONTOSO\CA01'
                        cn                     = 'CA01'
                        distinguishedName      = 'CN=CA01,...'
                        WebEnrollmentEndpoints = @(
                            [PSCustomObject]@{ URL = 'https://ca1.contoso.com/certsrv/'; NtlmOffered = $true; EpaNotRequired = $true }
                        )
                    }
                    $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result.Count | Should -Be 1
                }
            }

            Context 'HTTPS endpoint that is safe' {
                It 'should return no issues for an HTTPS endpoint where NtlmOffered=$false and EpaNotRequired=$false' {
                    $mockCA = New-MockLS2AdcsObject -Properties @{
                        objectClass            = @('top', 'pKIEnrollmentService')
                        SchemaClassName        = 'pKIEnrollmentService'
                        CAFullName             = 'CONTOSO\CA01'
                        cn                     = 'CA01'
                        distinguishedName      = 'CN=CA01,...'
                        WebEnrollmentEndpoints = @(
                            [PSCustomObject]@{ URL = 'https://ca1.contoso.com/certsrv/'; NtlmOffered = $false; EpaNotRequired = $false }
                        )
                    }
                    $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result.Count | Should -Be 0
                }
            }

            Context 'CA with no WebEnrollmentEndpoints' {
                It 'should return no issues when WebEnrollmentEndpoints is empty' {
                    $mockCA = New-MockLS2AdcsObject -Properties @{
                        objectClass            = @('top', 'pKIEnrollmentService')
                        SchemaClassName        = 'pKIEnrollmentService'
                        CAFullName             = 'CONTOSO\CA01'
                        cn                     = 'CA01'
                        distinguishedName      = 'CN=CA01,...'
                        WebEnrollmentEndpoints = @()
                    }
                    $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result.Count | Should -Be 0
                }

                It 'should return no issues when WebEnrollmentEndpoints is null' {
                    $mockCA = New-MockLS2AdcsObject -Properties @{
                        objectClass            = @('top', 'pKIEnrollmentService')
                        SchemaClassName        = 'pKIEnrollmentService'
                        CAFullName             = 'CONTOSO\CA01'
                        cn                     = 'CA01'
                        distinguishedName      = 'CN=CA01,...'
                        WebEnrollmentEndpoints = $null
                    }
                    $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result.Count | Should -Be 0
                }
            }

            Context 'Multiple endpoints — mixed vulnerable and safe' {
                It 'should return one issue per vulnerable endpoint' {
                    $mockCA = New-MockLS2AdcsObject -Properties @{
                        objectClass            = @('top', 'pKIEnrollmentService')
                        SchemaClassName        = 'pKIEnrollmentService'
                        CAFullName             = 'CONTOSO\CA01'
                        cn                     = 'CA01'
                        distinguishedName      = 'CN=CA01,...'
                        WebEnrollmentEndpoints = @(
                            [PSCustomObject]@{ URL = 'http://ca1.contoso.com/certsrv/'; NtlmOffered = $null; EpaNotRequired = $null },
                            [PSCustomObject]@{ URL = 'https://ca1.contoso.com/certsrv/'; NtlmOffered = $false; EpaNotRequired = $false },
                            [PSCustomObject]@{ URL = 'https://ca1.contoso.com/certsrv/mscep/'; NtlmOffered = $true; EpaNotRequired = $false }
                        )
                    }
                    $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result.Count | Should -Be 2
                }
            }

            Context 'Initialize-LS2Scan returns false' {
                It 'should return no issues when Initialize-LS2Scan returns false' {
                    Mock 'Initialize-LS2Scan' { $false }
                    $result = @(Find-LS2VulnerableCA -Technique 'ESC8')
                    $result.Count | Should -Be 0
                }
            }
        }

        Context 'Path D — Auditing technique-specific scan' {
            BeforeEach {
                Mock 'Test-IssueExists' { $false }
            }

            It 'should return an LS2Issue when CA has AuditingIncomplete=$true' {
                $mockCA = New-MockLS2AdcsObject -Properties @{
                    objectClass        = @('top', 'pKIEnrollmentService')
                    SchemaClassName    = 'pKIEnrollmentService'
                    CAFullName         = 'CONTOSO\CA01'
                    cn                 = 'CA01'
                    AuditingIncomplete = $true
                    AuditFilter        = 0
                    distinguishedName  = 'CN=CA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                }
                $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }

                $result = @(Find-LS2VulnerableCA -Technique 'Auditing')

                $result.Count | Should -Be 1
                $result[0].GetType().Name | Should -Be 'LS2Issue'
            }

            It 'should return an issue with Technique Auditing' {
                $mockCA = New-MockLS2AdcsObject -Properties @{
                    objectClass        = @('top', 'pKIEnrollmentService')
                    SchemaClassName    = 'pKIEnrollmentService'
                    CAFullName         = 'CONTOSO\CA01'
                    cn                 = 'CA01'
                    AuditingIncomplete = $true
                    AuditFilter        = 0
                    distinguishedName  = 'CN=CA01,...'
                }
                $script:AdcsObjectStore = @{ $mockCA.distinguishedName = $mockCA }

                $result = @(Find-LS2VulnerableCA -Technique 'Auditing')

                $result[0].Technique | Should -Be 'Auditing'
            }

            It 'should not return an issue when AuditingIncomplete is $false' {
                $safeCA = New-MockLS2AdcsObject -Properties @{
                    objectClass        = @('top', 'pKIEnrollmentService')
                    SchemaClassName    = 'pKIEnrollmentService'
                    CAFullName         = 'CONTOSO\SafeCA'
                    cn                 = 'SafeCA'
                    AuditingIncomplete = $false
                    AuditFilter        = 127
                    distinguishedName  = 'CN=SafeCA,...'
                }
                $script:AdcsObjectStore = @{ $safeCA.distinguishedName = $safeCA }

                $result = @(Find-LS2VulnerableCA -Technique 'Auditing')

                $result.Count | Should -Be 0
            }

            It 'should return nothing when Initialize-LS2Scan returns false' {
                Mock 'Initialize-LS2Scan' { $false }
                $result = @(Find-LS2VulnerableCA -Technique 'Auditing')
                $result.Count | Should -Be 0
            }
        }
    }
}

