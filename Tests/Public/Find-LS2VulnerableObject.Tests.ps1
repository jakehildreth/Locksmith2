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
    Describe 'Find-LS2VulnerableObject' -Tag 'Unit' {
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
                $objectIssue = [LS2Issue]@{
                    Technique = 'ESC5o'; Forest = 'contoso.com'; Name = 'TestContainer'
                    DistinguishedName = 'CN=Public Key Services,...'; ObjectClass = 'container'
                }
                $templateIssue = [LS2Issue]@{
                    Technique = 'ESC1'; Forest = 'contoso.com'; Name = 'VulnTemplate'
                    DistinguishedName = 'CN=VulnTemplate,...'; ObjectClass = 'pKICertificateTemplate'
                    IdentityReference = 'Everyone'
                }
                Mock 'Get-FlattenedIssues' { @($objectIssue, $templateIssue) }
            }

            It 'should return only object-technique issues when no Technique specified' {
                $result = @(Find-LS2VulnerableObject)
                $result.Count | Should -Be 1
                $result[0].Technique | Should -Be 'ESC5o'
            }

            It 'should not return template-technique issues when no Technique specified' {
                $result = @(Find-LS2VulnerableObject)
                $result.Technique | Should -Not -Contain 'ESC1'
            }

            It 'should call Expand-IssueByGroup per issue when -ExpandGroups is specified' {
                Find-LS2VulnerableObject -ExpandGroups | Out-Null
                Should -Invoke 'Expand-IssueByGroup' -Times 1
            }

            It 'should return nothing when Initialize-LS2Scan returns false' {
                Mock 'Initialize-LS2Scan' { $false }
                $result = @(Find-LS2VulnerableObject)
                $result.Count | Should -Be 0
            }
        }

        Context 'Path B — ESC5o ownership-based scan' {
            BeforeEach {
                Mock 'Convert-IdentityReferenceToNTAccount' {
                    [System.Security.Principal.NTAccount]::new('Everyone')
                }
                Mock 'Test-IssueExists' { $false }
            }

            It 'should return an LS2Issue when object matches all ESC5o conditions' {
                $mockObj = New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', 'container')
                    SchemaClassName   = 'container'
                    name              = 'TestContainer'
                    distinguishedName = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    Owner             = 'S-1-1-0'
                }
                foreach ($condition in $script:ESCDefs.ESC5o.Conditions) {
                    $mockObj.($condition.Property) = $condition.Value
                }
                $script:AdcsObjectStore = @{ $mockObj.distinguishedName = $mockObj }
                $result = @(Find-LS2VulnerableObject -Technique 'ESC5o')
                $result.Count | Should -Be 1
                $result[0].Technique | Should -Be 'ESC5o'
            }

            It 'should skip a template object (objectClass contains pKICertificateTemplate)' {
                $templateObj = New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', 'pKICertificateTemplate')
                    SchemaClassName   = 'pKICertificateTemplate'
                    HasNonStandardOwner = $true
                    distinguishedName = 'CN=VulnTemplate,...'
                }
                $script:AdcsObjectStore = @{ $templateObj.distinguishedName = $templateObj }
                $result = @(Find-LS2VulnerableObject -Technique 'ESC5o')
                $result.Count | Should -Be 0
            }

            It 'should return nothing when Initialize-LS2Scan returns false' {
                Mock 'Initialize-LS2Scan' { $false }
                $result = @(Find-LS2VulnerableObject -Technique 'ESC5o')
                $result.Count | Should -Be 0
            }
        }

        Context 'Path B — ESC5a editor-based scan' {
            BeforeEach {
                Mock 'Convert-IdentityReferenceToSid' {
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                }
                Mock 'Convert-IdentityReferenceToNTAccount' {
                    [System.Security.Principal.NTAccount]::new('Everyone')
                }
                Mock 'Test-IsDangerousAce' {
                    [PSCustomObject]@{
                        IsDangerous       = $true
                        MatchedPermission = 'GenericAll'
                        Description       = 'Full control'
                        ObjectTypeName    = $null
                        Ace               = $InputObject
                    }
                }
                Mock 'Test-IssueExists' { $false }
            }

            It 'should return an LS2Issue when a non-template object has a dangerous editor' {
                $mockObj = New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', 'container')
                    SchemaClassName   = 'container'
                    name              = 'TestContainer'
                    distinguishedName = 'CN=Public Key Services,...'
                }
                foreach ($editorProp in $script:ESCDefs.ESC5a.EditorProperties) {
                    $mockObj.$editorProp = @('S-1-1-0')
                }
                $security = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                $atype = [System.Security.AccessControl.AccessControlType]::Allow
                $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $rights, $atype)
                $security.AddAccessRule($rule)
                $mockObj.ObjectSecurity = $security
                $script:AdcsObjectStore = @{ $mockObj.distinguishedName = $mockObj }
                $result = @(Find-LS2VulnerableObject -Technique 'ESC5a')
                $result.Count | Should -BeGreaterOrEqual 1
                $result[0].Technique | Should -Be 'ESC5a'
            }

            It 'should skip an object with matching editor but no ObjectSecurity' {
                $mockObj = New-MockLS2AdcsObject -Properties @{
                    objectClass       = @('top', 'container')
                    SchemaClassName   = 'container'
                    name              = 'TestContainer'
                    distinguishedName = 'CN=Public Key Services,...'
                }
                foreach ($editorProp in $script:ESCDefs.ESC5a.EditorProperties) {
                    $mockObj.$editorProp = @('S-1-1-0')
                }
                $script:AdcsObjectStore = @{ $mockObj.distinguishedName = $mockObj }
                $result = @(Find-LS2VulnerableObject -Technique 'ESC5a')
                $result.Count | Should -Be 0
            }
        }
    }
}
