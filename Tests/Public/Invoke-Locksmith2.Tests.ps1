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
    Describe 'Invoke-Locksmith2' -Tag 'Unit' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null

            $script:mockIssue = [LS2Issue]@{
                Technique = 'ESC1'; Forest = 'contoso.com'; Name = 'TestTemplate'
                DistinguishedName = 'CN=TestTemplate,...'; ObjectClass = 'pKICertificateTemplate'
                IdentityReference = 'Everyone'
            }

            Mock 'Initialize-LS2Scan' { $true }
            Mock 'Get-FlattenedIssues' { @($script:mockIssue) }
            Mock 'Get-IssueCount' { 0 }
            Mock 'Show-IssueReport' { }
            Mock 'Show-ConnectionContext' { $true }
            Mock 'Show-PrivilegeContext' { $true }
            Mock 'Test-PowerShellEnvironment' { [PSCustomObject]@{} }
            Mock 'Repair-PowerShellEnvironment' { }
            Mock 'Expand-IssueByGroup' { $_ }
        }

        It 'should call Initialize-LS2Scan' {
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Initialize-LS2Scan' -Times 1
        }

        It 'should expose Invoke-LS2 alias' {
            (Get-Alias Invoke-LS2).ResolvedCommandName | Should -Be 'Invoke-Locksmith2'
        }

        It 'should expose Locksmith2 alias' {
            (Get-Alias Locksmith2).ResolvedCommandName | Should -Be 'Invoke-Locksmith2'
        }

        It 'should expose Start-Locksmith2 alias' {
            (Get-Alias Start-Locksmith2).ResolvedCommandName | Should -Be 'Invoke-Locksmith2'
        }

        It 'should expose Start-LS2 alias' {
            (Get-Alias Start-LS2).ResolvedCommandName | Should -Be 'Invoke-Locksmith2'
        }

        It 'should call Test-PowerShellEnvironment when -SkipPowerShellCheck is not specified' {
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Test-PowerShellEnvironment' -Times 1
        }

        It 'should not call Test-PowerShellEnvironment when -SkipPowerShellCheck is specified' {
            Invoke-Locksmith2 -SkipPowerShellCheck | Out-Null
            Should -Invoke 'Test-PowerShellEnvironment' -Times 0
        }

        It 'should return issues to pipeline when Mode is not specified' {
            $result = @(Invoke-Locksmith2)
            $result.Count | Should -Be 1
            Should -Invoke 'Show-IssueReport' -Times 0
        }

        It 'should call Show-IssueReport -Mode 0 when -Mode 0 is specified' {
            Invoke-Locksmith2 -Mode 0
            Should -Invoke 'Show-IssueReport' -Times 1 -ParameterFilter { $Mode -eq 0 }
        }

        It 'should call Show-IssueReport -Mode 1 when -Mode 1 is specified' {
            Invoke-Locksmith2 -Mode 1
            Should -Invoke 'Show-IssueReport' -Times 1 -ParameterFilter { $Mode -eq 1 }
        }

        It 'should write an error and not call Get-FlattenedIssues when Initialize-LS2Scan returns false' {
            Mock 'Initialize-LS2Scan' { $false }
            Mock 'Write-Error' { }
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Write-Error' -Times 1
            Should -Invoke 'Get-FlattenedIssues' -Times 0
        }

        It 'should forward Forest to Initialize-LS2Scan when Forest is specified' {
            Invoke-Locksmith2 -Forest 'contoso.com' | Out-Null
            Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter { $Forest -eq 'contoso.com' }
        }

        It 'should not forward Forest to Initialize-LS2Scan when Forest is not specified' {
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter { -not $PSBoundParameters.ContainsKey('Forest') }
        }

        It 'should pass -Rescan to Initialize-LS2Scan when -Rescan is specified' {
            Invoke-Locksmith2 -Rescan | Out-Null
            Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter { $Rescan -eq $true }
        }

        It 'should call Expand-IssueByGroup per issue when -ExpandGroups is specified' {
            Invoke-Locksmith2 -ExpandGroups | Out-Null
            Should -Invoke 'Expand-IssueByGroup' -Times 1
        }

        It 'should call Show-ConnectionContext with the resolved context' {
            Invoke-Locksmith2 -Forest 'contoso.com' | Out-Null
            Should -Invoke 'Show-ConnectionContext' -Times 1 -ParameterFilter {
                $Context.Forest -eq 'contoso.com'
            }
        }

        It 'should not call Show-PrivilegeContext when Initialize-LS2Scan returns false' {
            Mock 'Initialize-LS2Scan' { $false }
            Mock 'Write-Error' { }
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Show-PrivilegeContext' -Times 0
        }

        It 'should call Show-PrivilegeContext after Initialize-LS2Scan succeeds' {
            $script:RootDSE = [System.DirectoryServices.DirectoryEntry]::new()
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Show-PrivilegeContext' -Times 1
        }

        It 'should pass RootDSE to Show-PrivilegeContext' {
            $script:RootDSE = [System.DirectoryServices.DirectoryEntry]::new()
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Show-PrivilegeContext' -Times 1 -ParameterFilter {
                $RootDSE -ne $null
            }
        }

        It 'should return early when Show-PrivilegeContext returns false' {
            Mock 'Show-PrivilegeContext' { $false }
            $script:RootDSE = [System.DirectoryServices.DirectoryEntry]::new()
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Show-PrivilegeContext' -Times 1
        }

        It 'should return early when Show-ConnectionContext returns false' {
            Mock 'Show-ConnectionContext' { $false }
            Invoke-Locksmith2 | Out-Null
            Should -Invoke 'Initialize-LS2Scan' -Times 0
            Should -Invoke 'Show-PrivilegeContext' -Times 0
        }

        Context 'When -Scans is specified' {
            It 'should default -Scans to All and forward all techniques to Initialize-LS2Scan' {
                Invoke-Locksmith2 | Out-Null
                Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter {
                    $Scans -contains 'ESC1' -and
                    $Scans -contains 'ESC3c1' -and
                    $Scans -contains 'ESC3c2' -and
                    $Scans -contains 'ESC4a' -and
                    $Scans -contains 'ESC4o' -and
                    $Scans -contains 'ESC5a' -and
                    $Scans -contains 'ESC5o' -and
                    $Scans -contains 'ESC6' -and
                    $Scans -contains 'ESC7a' -and
                    $Scans -contains 'ESC7m' -and
                    $Scans -contains 'ESC8' -and
                    $Scans -contains 'ESC9' -and
                    $Scans -contains 'ESC11' -and
                    $Scans -contains 'ESC13' -and
                    $Scans -contains 'ESC15' -and
                    $Scans -contains 'ESC16' -and
                    $Scans -contains 'Auditing' -and
                    $Scans -contains 'SchemaV1'
                }
            }

            It 'should forward only ESC1 to Initialize-LS2Scan when -Scans ESC1 is specified' {
                Invoke-Locksmith2 -Scans 'ESC1' | Out-Null
                Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter {
                    $Scans.Count -eq 1 -and $Scans[0] -eq 'ESC1'
                }
            }

            It 'should expand ESC3 to ESC3c1 and ESC3c2 when forwarded to Initialize-LS2Scan' {
                Invoke-Locksmith2 -Scans 'ESC3' | Out-Null
                Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter {
                    $Scans.Count -eq 2 -and
                    $Scans -contains 'ESC3c1' -and
                    $Scans -contains 'ESC3c2'
                }
            }

            It 'should expand ESC4 to ESC4a and ESC4o when forwarded to Initialize-LS2Scan' {
                Invoke-Locksmith2 -Scans 'ESC4' | Out-Null
                Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter {
                    $Scans.Count -eq 2 -and
                    $Scans -contains 'ESC4a' -and
                    $Scans -contains 'ESC4o'
                }
            }

            It 'should expand ESC5 to ESC5a and ESC5o when forwarded to Initialize-LS2Scan' {
                Invoke-Locksmith2 -Scans 'ESC5' | Out-Null
                Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter {
                    $Scans.Count -eq 2 -and
                    $Scans -contains 'ESC5a' -and
                    $Scans -contains 'ESC5o'
                }
            }

            It 'should expand ESC7 to ESC7a and ESC7m when forwarded to Initialize-LS2Scan' {
                Invoke-Locksmith2 -Scans 'ESC7' | Out-Null
                Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter {
                    $Scans.Count -eq 2 -and
                    $Scans -contains 'ESC7a' -and
                    $Scans -contains 'ESC7m'
                }
            }

            It 'should map EKUwu to ESC15 when forwarded to Initialize-LS2Scan' {
                Invoke-Locksmith2 -Scans 'EKUwu' | Out-Null
                Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter {
                    $Scans.Count -eq 1 -and $Scans[0] -eq 'ESC15'
                }
            }

            It 'should accept multiple -Scans values and resolve them' {
                Invoke-Locksmith2 -Scans 'ESC1', 'ESC3' | Out-Null
                Should -Invoke 'Initialize-LS2Scan' -Times 1 -ParameterFilter {
                    $Scans.Count -eq 3 -and
                    $Scans -contains 'ESC1' -and
                    $Scans -contains 'ESC3c1' -and
                    $Scans -contains 'ESC3c2'
                }
            }

            It 'should call Get-IssueCount only for the requested techniques' {
                Mock 'Get-IssueCount' { 0 }
                Invoke-Locksmith2 -Scans 'ESC1' | Out-Null
                Should -Invoke 'Get-IssueCount' -Times 1 -ParameterFilter { $Technique -eq 'ESC1' }
            }

            It 'should filter returned issues to the requested techniques' {
                $script:mockIssue2 = [LS2Issue]@{
                    Technique = 'ESC6'; Forest = 'contoso.com'; Name = 'TestCA'
                    DistinguishedName = 'CN=TestCA,...'; ObjectClass = 'pKIEnrollmentService'
                    IdentityReference = 'Everyone'
                }
                Mock 'Get-FlattenedIssues' { @($script:mockIssue, $script:mockIssue2) }
                $result = @(Invoke-Locksmith2 -Scans 'ESC1')
                $result.Count | Should -Be 1
                $result[0].Technique | Should -Be 'ESC1'
            }
        }
    }
}
