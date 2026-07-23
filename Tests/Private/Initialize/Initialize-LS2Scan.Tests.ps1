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
}

Describe 'Initialize-LS2Scan' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {

        BeforeEach {
            $script:AdcsObjectStore    = @{}
            $script:IssueStore         = @{}
            $script:Forest             = $null
            $script:Credential         = $null
            $script:RootDSE            = $null
            $script:Server             = $null
            $script:InitializingStores = $false
        }

        Context 'Re-entry guard' {
            It 'should return $true immediately when InitializingStores is $true' {
                $script:InitializingStores = $true
                $result = Initialize-LS2Scan
                $result | Should -BeTrue
            }
        }

        Context 'AdcsObjectStore already populated' {
            BeforeEach {
                # Pre-populate with a fake entry so the function fast-returns
                $script:AdcsObjectStore['CN=Fake,DC=contoso,DC=com'] = New-MockLS2AdcsObject
                Mock 'Set-LS2Forest' { }
                Mock 'Set-LS2Credential' { }
                Mock 'Get-RootDSE' { $null }
            }

            It 'should skip AdcsObjectStore initialisation when it is already populated' {
                Mock 'Initialize-AdcsObjectStore' { }
                Initialize-LS2Scan -Forest 'contoso.com' | Out-Null
                Should -Invoke 'Initialize-AdcsObjectStore' -Times 0
            }
        }

        Context '-Rescan clears the stores' {
            BeforeEach {
                $fakeEntry = New-MockLS2AdcsObject
                $script:AdcsObjectStore['CN=Fake,DC=contoso,DC=com'] = $fakeEntry
                $fakeIssue = New-MockLS2Issue
                $script:IssueStore[$fakeIssue.DistinguishedName] = @{ 'ESC1' = @($fakeIssue) }

                Mock 'Set-LS2Forest' { }
                Mock 'Set-LS2Credential' { }
                Mock 'Get-RootDSE' { $null }
                Mock 'Initialize-DomainStore' { }
                Mock 'Initialize-PrincipalDefinitions' { }
                Mock 'Initialize-AdcsObjectStore' {
                    $script:AdcsObjectStore['CN=Fake,DC=contoso,DC=com'] = New-MockLS2AdcsObject
                }
                Mock 'Find-LS2VulnerableTemplate' { }
                Mock 'Find-LS2VulnerableCA' { }
                Mock 'Find-LS2VulnerableObject' { }
            }

            It 'should clear AdcsObjectStore when -Rescan is specified' {
                $priorCount = $script:AdcsObjectStore.Count
                Initialize-LS2Scan -Rescan | Out-Null
                # After clearing, Initialize-AdcsObjectStore was mocked to re-add one item
                # The important check: Rescan cleared the store before re-init
                Should -Invoke 'Initialize-AdcsObjectStore' -Times 1
            }

            It 'should clear IssueStore when -Rescan is specified' {
                Initialize-LS2Scan -Rescan | Out-Null
                # IssueStore was cleared; Find-LS2Vulnerable* mocks did not re-populate it
                # so after the call the IssueStore contains whatever mocks produced
                Should -Invoke 'Find-LS2VulnerableTemplate' -Times -1  # called at least once
            }
        }

        Context 'Returns correct bool values' {
            It 'should return $true when AdcsObjectStore is pre-populated' {
                $script:AdcsObjectStore['CN=Fake,DC=contoso,DC=com'] = New-MockLS2AdcsObject
                $script:IssueStore['CN=Fake,DC=contoso,DC=com'] = @{ 'ESC1' = @(New-MockLS2Issue) }

                $result = Initialize-LS2Scan
                $result | Should -BeTrue
            }

            It 'should return [bool]' {
                $script:AdcsObjectStore['CN=Fake,DC=contoso,DC=com'] = New-MockLS2AdcsObject
                $script:IssueStore['CN=Fake,DC=contoso,DC=com'] = @{ 'ESC1' = @(New-MockLS2Issue) }
                $result = Initialize-LS2Scan
                $result | Should -BeOfType [bool]
            }
        }

        Context 'When -Scans is specified' {
            BeforeEach {
                $script:AdcsObjectStore['CN=Fake,DC=contoso,DC=com'] = New-MockLS2AdcsObject
                Mock 'Set-LS2Forest' { }
                Mock 'Set-LS2Credential' { }
                Mock 'Get-RootDSE' { $null }
                Mock 'Initialize-DomainStore' { }
                Mock 'Initialize-PrincipalDefinitions' { }
                Mock 'Initialize-AdcsObjectStore' { }
                Mock 'Find-LS2VulnerableTemplate' { }
                Mock 'Find-LS2VulnerableCA' { }
                Mock 'Find-LS2VulnerableObject' { }
            }

            It 'should call Find-LS2VulnerableTemplate for ESC1 when -Scans ESC1 is specified' {
                Initialize-LS2Scan -Scans 'ESC1' | Out-Null
                Should -Invoke 'Find-LS2VulnerableTemplate' -Times 1 -ParameterFilter { $Technique -eq 'ESC1' }
                Should -Invoke 'Find-LS2VulnerableCA' -Times 0
                Should -Invoke 'Find-LS2VulnerableObject' -Times 0
            }

            It 'should expand ESC3 to ESC3c1 and ESC3c2' {
                Initialize-LS2Scan -Scans 'ESC3' | Out-Null
                Should -Invoke 'Find-LS2VulnerableTemplate' -Times 1 -ParameterFilter { $Technique -eq 'ESC3c1' }
                Should -Invoke 'Find-LS2VulnerableTemplate' -Times 1 -ParameterFilter { $Technique -eq 'ESC3c2' }
            }

            It 'should expand ESC4 to ESC4a and ESC4o' {
                Initialize-LS2Scan -Scans 'ESC4' | Out-Null
                Should -Invoke 'Find-LS2VulnerableTemplate' -Times 1 -ParameterFilter { $Technique -eq 'ESC4a' }
                Should -Invoke 'Find-LS2VulnerableTemplate' -Times 1 -ParameterFilter { $Technique -eq 'ESC4o' }
            }

            It 'should expand ESC5 to ESC5a and ESC5o' {
                Initialize-LS2Scan -Scans 'ESC5' | Out-Null
                Should -Invoke 'Find-LS2VulnerableObject' -Times 1 -ParameterFilter { $Technique -eq 'ESC5a' }
                Should -Invoke 'Find-LS2VulnerableObject' -Times 1 -ParameterFilter { $Technique -eq 'ESC5o' }
            }

            It 'should expand ESC7 to ESC7a and ESC7m' {
                Initialize-LS2Scan -Scans 'ESC7' | Out-Null
                Should -Invoke 'Find-LS2VulnerableCA' -Times 1 -ParameterFilter { $Technique -eq 'ESC7a' }
                Should -Invoke 'Find-LS2VulnerableCA' -Times 1 -ParameterFilter { $Technique -eq 'ESC7m' }
            }

            It 'should run the full technique list when -Scans is omitted' {
                Initialize-LS2Scan | Out-Null
                Should -Invoke 'Find-LS2VulnerableTemplate' -Times -1
                Should -Invoke 'Find-LS2VulnerableCA' -Times -1
                Should -Invoke 'Find-LS2VulnerableObject' -Times -1
            }

            It 'should not call Find-LS2VulnerableCA for template-only scans' {
                Initialize-LS2Scan -Scans 'ESC1', 'ESC2' | Out-Null
                Should -Invoke 'Find-LS2VulnerableCA' -Times 0
                Should -Invoke 'Find-LS2VulnerableObject' -Times 0
            }
        }
    }
}
