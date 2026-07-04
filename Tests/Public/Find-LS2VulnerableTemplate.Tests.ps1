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
    Describe 'Find-LS2VulnerableTemplate' -Tag 'Unit' {
        BeforeAll {
            # Recalculate ModuleRoot inside InModuleScope since $ModuleRoot from outer BeforeAll
            # is not accessible via closure here
            $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
            $script:ESCDefs = $script:ESCDefinitions

            function script:New-ESC1VulnerableTemplate {
                $t = New-MockLS2AdcsObject -Properties @{
                    objectClass                    = @('top', 'pKICertificateTemplate')
                    SchemaClassName                = 'pKICertificateTemplate'
                    SANAllowed                     = $true
                    AuthenticationEKUExist         = $true
                    ManagerApprovalNotRequired     = $true
                    AuthorizedSignatureNotRequired = $true
                    DangerousEnrollee              = @('S-1-1-0')
                    distinguishedName              = 'CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                           = 'VulnTemplate'
                    Enabled                        = $true
                    EnabledOn                      = @('CONTOSO-CA\CA01')
                }
                $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                $atype = [System.Security.AccessControl.AccessControlType]::Allow
                $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $rights, $atype)
                $security.AddAccessRule($rule)
                $t.ObjectSecurity = $security
                return $t
            }
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
                $templateIssue = [LS2Issue]@{
                    Technique = 'ESC1'; Forest = 'contoso.com'; Name = 'VulnTemplate'
                    DistinguishedName = 'CN=VulnTemplate,...'; ObjectClass = 'pKICertificateTemplate'
                    IdentityReference = 'Everyone'
                }
                $caIssue = [LS2Issue]@{
                    Technique = 'ESC6'; Forest = 'contoso.com'; Name = 'TestCA'
                    DistinguishedName = 'CN=TestCA,...'; ObjectClass = 'pKIEnrollmentService'
                }
                Mock 'Get-FlattenedIssues' { @($templateIssue, $caIssue) }
            }

            It 'should return only template-technique issues when no Technique specified' {
                $result = @(Find-LS2VulnerableTemplate)
                $result.Count | Should -Be 1
                $result[0].Technique | Should -Be 'ESC1'
            }

            It 'should not return CA-technique issues when no Technique specified' {
                $result = @(Find-LS2VulnerableTemplate)
                $result.Technique | Should -Not -Contain 'ESC6'
            }

            It 'should call Expand-IssueByGroup per issue when -ExpandGroups is specified' {
                Find-LS2VulnerableTemplate -ExpandGroups | Out-Null
                Should -Invoke 'Expand-IssueByGroup' -Times 1
            }

            It 'should return nothing when Initialize-LS2Scan returns false' {
                Mock 'Initialize-LS2Scan' { $false }
                $result = @(Find-LS2VulnerableTemplate)
                $result.Count | Should -Be 0
            }
        }

        Context 'Path B — ESC1 technique-specific scan' {
            BeforeEach {
                Mock 'Convert-IdentityReferenceToSid' {
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                }
                Mock 'Convert-IdentityReferenceToNTAccount' {
                    [System.Security.Principal.NTAccount]::new('Everyone')
                }
                Mock 'Test-IssueExists' { $false }
            }

            It 'should return an LS2Issue when template matches all ESC1 conditions' {
                $vulnTemplate = New-ESC1VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }
                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC1')
                $result.Count | Should -Be 1
                $result[0].GetType().Name | Should -Be 'LS2Issue'
                $result[0].Technique | Should -Be 'ESC1'
            }

            It 'should skip a template where any ESC1 condition is not met' {
                $safeTemplate = New-MockLS2AdcsObject -Properties @{
                    SANAllowed            = $false
                    distinguishedName     = 'CN=SafeTemplate,CN=Certificate Templates,...'
                    Name                  = 'SafeTemplate'
                }
                $script:AdcsObjectStore = @{ $safeTemplate.distinguishedName = $safeTemplate }
                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC1')
                $result.Count | Should -Be 0
            }

            It 'should skip a template with no ObjectSecurity and produce no output' {
                $noSecTemplate = New-MockLS2AdcsObject -Properties @{
                    SANAllowed                     = $true
                    AuthenticationEKUExist         = $true
                    ManagerApprovalNotRequired     = $true
                    AuthorizedSignatureNotRequired = $true
                    DangerousEnrollee              = @('S-1-1-0')
                    distinguishedName              = 'CN=VulnTemplate,...'
                    Name                           = 'VulnTemplate'
                }
                $script:AdcsObjectStore = @{ $noSecTemplate.distinguishedName = $noSecTemplate }
                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC1')
                $result.Count | Should -Be 0
            }

            It 'should still output issue to pipeline even when Test-IssueExists returns true (no double-store)' {
                Mock 'Test-IssueExists' { $true }
                $vulnTemplate = New-ESC1VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }
                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC1')
                # Issue is always output to pipeline regardless of duplicate check
                $result.Count | Should -Be 1
                # The DN entry is created but the issues array remains empty (duplicate skipped)
                $dn = $vulnTemplate.distinguishedName
                $script:IssueStore[$dn]['ESC1'].Count | Should -Be 0
            }

            It 'should add issue to script:IssueStore when not a duplicate' {
                $vulnTemplate = New-ESC1VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }
                Find-LS2VulnerableTemplate -Technique 'ESC1' | Out-Null
                $script:IssueStore.Count | Should -BeGreaterThan 0
            }

            It 'should call Expand-IssueByGroup when -ExpandGroups is specified' {
                $vulnTemplate = New-ESC1VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }
                Find-LS2VulnerableTemplate -Technique 'ESC1' -ExpandGroups | Out-Null
                Should -Invoke 'Expand-IssueByGroup' -Times 1
            }

            It 'should return nothing when Initialize-LS2Scan returns false' {
                Mock 'Initialize-LS2Scan' { $false }
                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC1')
                $result.Count | Should -Be 0
            }
        }

        Context 'Path C — ESC13 technique-specific scan' {
            BeforeAll {
                function script:New-ESC13VulnerableTemplate {
                    $t = New-MockLS2AdcsObject -Properties @{
                        objectClass              = @('top', 'pKICertificateTemplate')
                        SchemaClassName          = 'pKICertificateTemplate'
                        AuthenticationEKUExist   = $true
                        HasLinkedGroupOIDPolicy  = $true
                        LinkedGroupOIDPolicies   = @('CN=PrivilegedGroup,CN=Users,DC=contoso,DC=com')
                        DangerousEnrollee        = @('S-1-1-0')
                        distinguishedName        = 'CN=ESC13Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                        Name                     = 'ESC13Template'
                        Enabled                  = $true
                        EnabledOn                = @('CONTOSO-CA\CA01')
                    }
                    $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                    $rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                    $atype = [System.Security.AccessControl.AccessControlType]::Allow
                    $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $rights, $atype)
                    $security.AddAccessRule($rule)
                    $t.ObjectSecurity = $security
                    return $t
                }
            }

            BeforeEach {
                Mock 'Convert-IdentityReferenceToSid' {
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                }
                Mock 'Convert-IdentityReferenceToNTAccount' {
                    [System.Security.Principal.NTAccount]::new('Everyone')
                }
                Mock 'Test-IssueExists' { $false }
            }

            It 'should return an LS2Issue when template has AuthenticationEKU, HasLinkedGroupOIDPolicy, and DangerousEnrollee' {
                $vulnTemplate = New-ESC13VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC13')

                $result.Count | Should -Be 1
                $result[0].GetType().Name | Should -Be 'LS2Issue'
            }

            It 'should return an issue with Technique ESC13' {
                $vulnTemplate = New-ESC13VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC13')

                $result[0].Technique | Should -Be 'ESC13'
            }

            It 'should include the linked group DN in the issue text' {
                $vulnTemplate = New-ESC13VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC13')

                $result[0].Issue | Should -Match 'CN=PrivilegedGroup,CN=Users,DC=contoso,DC=com'
            }

            It 'should not return an issue when AuthenticationEKUExist is false' {
                $safeTemplate = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName         = 'pKICertificateTemplate'
                    AuthenticationEKUExist  = $false
                    HasLinkedGroupOIDPolicy = $true
                    DangerousEnrollee       = @('S-1-1-0')
                    distinguishedName       = 'CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                    = 'SafeTemplate'
                }
                $script:AdcsObjectStore = @{ $safeTemplate.distinguishedName = $safeTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC13')

                $result.Count | Should -Be 0
            }

            It 'should not return an issue when HasLinkedGroupOIDPolicy is false' {
                $safeTemplate = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName         = 'pKICertificateTemplate'
                    AuthenticationEKUExist  = $true
                    HasLinkedGroupOIDPolicy = $false
                    DangerousEnrollee       = @('S-1-1-0')
                    distinguishedName       = 'CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                    = 'SafeTemplate'
                }
                $script:AdcsObjectStore = @{ $safeTemplate.distinguishedName = $safeTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC13')

                $result.Count | Should -Be 0
            }

            It 'should not return an issue when DangerousEnrollee is empty' {
                $safeTemplate = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName          = 'pKICertificateTemplate'
                    AuthenticationEKUExist   = $true
                    HasLinkedGroupOIDPolicy  = $true
                    LinkedGroupOIDPolicies   = @('CN=PrivilegedGroup,CN=Users,DC=contoso,DC=com')
                    DangerousEnrollee        = @()
                    LowPrivilegeEnrollee     = @()
                    distinguishedName        = 'CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                     = 'SafeTemplate'
                }
                $script:AdcsObjectStore = @{ $safeTemplate.distinguishedName = $safeTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC13')

                $result.Count | Should -Be 0
            }

            It 'should add the issue to script:IssueStore when not a duplicate' {
                $vulnTemplate = New-ESC13VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }

                Find-LS2VulnerableTemplate -Technique 'ESC13' | Out-Null

                $script:IssueStore.Count | Should -BeGreaterThan 0
            }
        }

        Context 'Path D — ESC15 technique-specific scan' {
            BeforeAll {
                function script:New-ESC15VulnerableTemplate {
                    $t = New-MockLS2AdcsObject -Properties @{
                        objectClass                    = @('top', 'pKICertificateTemplate')
                        SchemaClassName                = 'pKICertificateTemplate'
                        TemplateSchemaVersion          = 1
                        AuthenticationEKUExist         = $true
                        ManagerApprovalNotRequired     = $true
                        AuthorizedSignatureNotRequired = $true
                        DangerousEnrollee              = @('S-1-1-0')
                        distinguishedName              = 'CN=ESC15Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                        Name                           = 'ESC15Template'
                        Enabled                        = $true
                        EnabledOn                      = @('CONTOSO-CA\CA01')
                    }
                    $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                    $rights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                    $atype = [System.Security.AccessControl.AccessControlType]::Allow
                    $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $rights, $atype)
                    $security.AddAccessRule($rule)
                    $t.ObjectSecurity = $security
                    return $t
                }
            }

            BeforeEach {
                Mock 'Convert-IdentityReferenceToSid' {
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                }
                Mock 'Convert-IdentityReferenceToNTAccount' {
                    [System.Security.Principal.NTAccount]::new('Everyone')
                }
                Mock 'Test-IssueExists' { $false }
            }

            It 'should return an LS2Issue when template has TemplateSchemaVersion=1, auth EKU, no manager approval, and DangerousEnrollee' {
                $vulnTemplate = New-ESC15VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC15')

                $result.Count | Should -Be 1
                $result[0].GetType().Name | Should -Be 'LS2Issue'
            }

            It 'should return an issue with Technique ESC15' {
                $vulnTemplate = New-ESC15VulnerableTemplate
                $script:AdcsObjectStore = @{ $vulnTemplate.distinguishedName = $vulnTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC15')

                $result[0].Technique | Should -Be 'ESC15'
            }

            It 'should not return an issue when TemplateSchemaVersion is 2' {
                $safeTemplate = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName                = 'pKICertificateTemplate'
                    TemplateSchemaVersion          = 2
                    AuthenticationEKUExist         = $true
                    ManagerApprovalNotRequired     = $true
                    AuthorizedSignatureNotRequired = $true
                    DangerousEnrollee              = @('S-1-1-0')
                    distinguishedName              = 'CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                           = 'SafeTemplate'
                }
                $script:AdcsObjectStore = @{ $safeTemplate.distinguishedName = $safeTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC15')

                $result.Count | Should -Be 0
            }

            It 'should not return an issue when AuthenticationEKUExist is false' {
                $safeTemplate = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName                = 'pKICertificateTemplate'
                    TemplateSchemaVersion          = 1
                    AuthenticationEKUExist         = $false
                    ManagerApprovalNotRequired     = $true
                    AuthorizedSignatureNotRequired = $true
                    DangerousEnrollee              = @('S-1-1-0')
                    distinguishedName              = 'CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                           = 'SafeTemplate'
                }
                $script:AdcsObjectStore = @{ $safeTemplate.distinguishedName = $safeTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'ESC15')

                $result.Count | Should -Be 0
            }
        }

        Context 'Path E — SchemaV1 technique-specific scan' {
            BeforeEach {
                Mock 'Test-IssueExists' { $false }
            }

            It 'should return an LS2Issue for any enabled schema v1 template' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName       = 'pKICertificateTemplate'
                    TemplateSchemaVersion = 1
                    Enabled               = $true
                    distinguishedName     = 'CN=SchemaV1Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                  = 'SchemaV1Template'
                }
                $script:AdcsObjectStore = @{ $template.distinguishedName = $template }

                $result = @(Find-LS2VulnerableTemplate -Technique 'SchemaV1')

                $result.Count | Should -Be 1
                $result[0].GetType().Name | Should -Be 'LS2Issue'
            }

            It 'should return an issue with Technique SchemaV1' {
                $template = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName       = 'pKICertificateTemplate'
                    TemplateSchemaVersion = 1
                    Enabled               = $true
                    distinguishedName     = 'CN=SchemaV1Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                  = 'SchemaV1Template'
                }
                $script:AdcsObjectStore = @{ $template.distinguishedName = $template }

                $result = @(Find-LS2VulnerableTemplate -Technique 'SchemaV1')

                $result[0].Technique | Should -Be 'SchemaV1'
            }

            It 'should not return an issue when TemplateSchemaVersion is 2' {
                $safeTemplate = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName       = 'pKICertificateTemplate'
                    TemplateSchemaVersion = 2
                    Enabled               = $true
                    distinguishedName     = 'CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                  = 'SafeTemplate'
                }
                $script:AdcsObjectStore = @{ $safeTemplate.distinguishedName = $safeTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'SchemaV1')

                $result.Count | Should -Be 0
            }

            It 'should not return an issue when Enabled is $false' {
                $disabledTemplate = New-MockLS2AdcsObject -Properties @{
                    SchemaClassName       = 'pKICertificateTemplate'
                    TemplateSchemaVersion = 1
                    Enabled               = $false
                    distinguishedName     = 'CN=DisabledTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Name                  = 'DisabledTemplate'
                }
                $script:AdcsObjectStore = @{ $disabledTemplate.distinguishedName = $disabledTemplate }

                $result = @(Find-LS2VulnerableTemplate -Technique 'SchemaV1')

                $result.Count | Should -Be 0
            }
        }
    }
}
