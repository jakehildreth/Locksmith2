#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
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
    }
}
