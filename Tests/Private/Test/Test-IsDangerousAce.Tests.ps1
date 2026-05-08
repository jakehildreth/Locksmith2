#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}

Describe 'Test-IsDangerousAce' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeAll {
            function New-MockAce {
                param(
                    [System.DirectoryServices.ActiveDirectoryRights]
                    $Rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                    [string]$AccessControlType = 'Allow',
                    [System.Guid]$ObjectTypeGuid = [System.Guid]::Empty,
                    [string]$Identity = 'S-1-5-21-1-2-3-999'
                )
                $sid = [System.Security.Principal.SecurityIdentifier]::new($Identity)
                if ($ObjectTypeGuid -ne [System.Guid]::Empty) {
                    [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                        $sid,
                        $Rights,
                        [System.Security.AccessControl.AccessControlType]::$AccessControlType,
                        $ObjectTypeGuid,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,
                        [System.Guid]::Empty
                    )
                } else {
                    [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                        $sid,
                        $Rights,
                        [System.Security.AccessControl.AccessControlType]::$AccessControlType
                    )
                }
            }
        }

        BeforeEach {
            $script:DangerousAces = $null
        }

        Context 'Return type and shape' {

            It 'should return a [PSCustomObject]' {
                $ace = New-MockAce -Rights GenericRead
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result | Should -BeOfType [PSCustomObject]
            }

            It 'should include IsDangerous, MatchedPermission, Description, and Ace properties' {
                $ace = New-MockAce -Rights GenericRead
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.PSObject.Properties.Name | Should -Contain 'IsDangerous'
                $result.PSObject.Properties.Name | Should -Contain 'MatchedPermission'
                $result.PSObject.Properties.Name | Should -Contain 'Description'
                $result.PSObject.Properties.Name | Should -Contain 'Ace'
            }

            It 'should include the original Ace object in the result' {
                $ace = New-MockAce -Rights GenericRead
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.Ace | Should -Be $ace
            }
        }

        Context 'Deny ACEs are never dangerous' {

            It 'should return IsDangerous=$false for a Deny ACE with GenericAll rights' {
                $ace = New-MockAce -Rights GenericAll -AccessControlType Deny
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.IsDangerous | Should -BeFalse
            }

            It 'should return MatchedPermission=$null for a Deny ACE' {
                $ace = New-MockAce -Rights GenericAll -AccessControlType Deny
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.MatchedPermission | Should -BeNullOrEmpty
            }
        }

        Context 'Dangerous Allow ACEs — universal rights' {

            It 'should detect GenericAll on a certificate template' {
                $ace = New-MockAce -Rights GenericAll
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.IsDangerous | Should -BeTrue
                $result.MatchedPermission | Should -Be 'GenericAll'
            }

            It 'should detect WriteDacl on a certificate template' {
                $ace = New-MockAce -Rights WriteDacl
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.IsDangerous | Should -BeTrue
                $result.MatchedPermission | Should -Be 'WriteDacl'
            }

            It 'should detect WriteOwner on a certificate template' {
                $ace = New-MockAce -Rights WriteOwner
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.IsDangerous | Should -BeTrue
                $result.MatchedPermission | Should -Be 'WriteOwner'
            }

            It 'should detect GenericWrite on a certificate template' {
                $ace = New-MockAce -Rights GenericWrite
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.IsDangerous | Should -BeTrue
                $result.MatchedPermission | Should -Be 'GenericWrite'
            }

            It 'should detect GenericAll on a CA (pKIEnrollmentService)' {
                $ace = New-MockAce -Rights GenericAll
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKIEnrollmentService'
                $result.IsDangerous | Should -BeTrue
            }

            It 'should detect WriteDacl on a computer account' {
                $ace = New-MockAce -Rights WriteDacl
                $result = $ace | Test-IsDangerousAce -ObjectClass 'computer'
                $result.IsDangerous | Should -BeTrue
            }
        }

        Context 'Dangerous Allow ACEs — template-specific WriteProperty' {

            It 'should detect WriteProperty on msPKI-Certificate-Name-Flag GUID for templates' {
                $guid = [System.Guid]::new('ea1dddc4-60ff-416e-8cc0-17cee534bce7')
                $ace = New-MockAce -Rights WriteProperty -ObjectTypeGuid $guid
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.IsDangerous | Should -BeTrue
                $result.MatchedPermission | Should -Be 'WriteProperty-CertificateNameFlag'
            }

            It 'should NOT flag WriteProperty on msPKI-Certificate-Name-Flag GUID for computer objects (wrong class)' {
                $guid = [System.Guid]::new('ea1dddc4-60ff-416e-8cc0-17cee534bce7')
                $ace = New-MockAce -Rights WriteProperty -ObjectTypeGuid $guid
                $result = $ace | Test-IsDangerousAce -ObjectClass 'computer'
                $result.IsDangerous | Should -BeFalse
            }
        }

        Context 'Non-dangerous ACEs' {

            It 'should return IsDangerous=$false for GenericRead' {
                $ace = New-MockAce -Rights GenericRead
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.IsDangerous | Should -BeFalse
                $result.MatchedPermission | Should -BeNullOrEmpty
            }

            It 'should return Description=$null for a non-dangerous ACE' {
                $ace = New-MockAce -Rights GenericRead
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.Description | Should -BeNullOrEmpty
            }
        }

        Context 'Pipeline processing' {

            It 'should return one result per ACE piped in' {
                $ace1 = New-MockAce -Rights GenericAll
                $ace2 = New-MockAce -Rights GenericRead
                $results = @($ace1, $ace2) | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $results.Count | Should -Be 2
                $results[0].IsDangerous | Should -BeTrue
                $results[1].IsDangerous | Should -BeFalse
            }
        }

        Context 'Caching behaviour' {

            It 'should populate $script:DangerousAces after first call' {
                $script:DangerousAces = $null
                New-MockAce -Rights GenericRead | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate' | Out-Null
                $script:DangerousAces | Should -Not -BeNullOrEmpty
            }

            It 'should use an existing $script:DangerousAces cache instead of reloading from file' {
                $script:DangerousAces = @(
                    @{
                        Name                = 'GenericAll'
                        Rights              = 'GenericAll'
                        ObjectTypeGUID      = $null
                        ObjectTypeName      = $null
                        ApplicableToClasses = @('pKICertificateTemplate')
                        Description         = 'Cached test entry'
                    }
                )
                $ace = New-MockAce -Rights GenericAll
                $result = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                $result.IsDangerous | Should -BeTrue
                $result.Description | Should -Be 'Cached test entry'
            }
        }
    }
}
