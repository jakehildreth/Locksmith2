#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot))
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot))
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

InModuleScope 'Locksmith2' {
    Describe 'Get-AdcsObjectName' -Tag 'Unit' {

        Context 'LS2AdcsObject input — delegates to GetFriendlyName()' {

            It 'should return displayName when set' {
                $obj = New-MockLS2AdcsObject -Properties @{ displayName = 'My Certificate Template' }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'My Certificate Template'
            }

            It 'should return name when displayName is null' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    displayName = $null
                    name        = 'WebServer'
                }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'WebServer'
            }

            It 'should return cn when displayName and name are null' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    displayName = $null
                    name        = $null
                    cn          = 'CN-Value'
                }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'CN-Value'
            }

            It 'should return distinguishedName when displayName, name, and cn are null' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    displayName       = $null
                    name              = $null
                    cn                = $null
                    distinguishedName = 'CN=Template,DC=contoso,DC=com'
                }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'CN=Template,DC=contoso,DC=com'
            }

            It 'should return empty string when GetFriendlyName returns empty (all name properties null)' {
                $obj = New-MockLS2AdcsObject -Properties @{
                    displayName       = $null
                    name              = $null
                    cn                = $null
                    distinguishedName = $null
                }
                # LS2AdcsObject.GetFriendlyName() returns '' when all name props are null;
                # Get-AdcsObjectName delegates entirely to GetFriendlyName() for LS2AdcsObject inputs.
                Get-AdcsObjectName -AdcsObject $obj | Should -Be ''
            }
        }

        Context 'PSCustomObject input — direct property inspection' {

            It 'should return displayName when set' {
                $obj = [PSCustomObject]@{ displayName = 'Display Name Value' }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'Display Name Value'
            }

            It 'should return name when displayName is absent' {
                $obj = [PSCustomObject]@{ name = 'NameValue' }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'NameValue'
            }

            It 'should return cn when displayName and name are absent' {
                $obj = [PSCustomObject]@{ cn = 'CnValue' }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'CnValue'
            }

            It 'should return distinguishedName when displayName, name, and cn are absent' {
                $obj = [PSCustomObject]@{ distinguishedName = 'CN=X,DC=test,DC=com' }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'CN=X,DC=test,DC=com'
            }

            It 'should return Unknown Object when object has no name properties' {
                $obj = [PSCustomObject]@{ someOtherProp = 'irrelevant' }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'Unknown Object'
            }

            It 'should prefer displayName over name, cn, and distinguishedName' {
                $obj = [PSCustomObject]@{
                    displayName       = 'Winner'
                    name              = 'Loser1'
                    cn                = 'Loser2'
                    distinguishedName = 'CN=Loser3,DC=test,DC=com'
                }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'Winner'
            }

            It 'should prefer name over cn and distinguishedName when displayName is absent' {
                $obj = [PSCustomObject]@{
                    name              = 'Winner'
                    cn                = 'Loser1'
                    distinguishedName = 'CN=Loser2,DC=test,DC=com'
                }
                Get-AdcsObjectName -AdcsObject $obj | Should -Be 'Winner'
            }
        }

        Context 'Pipeline input' {

            It 'should process a single object via pipeline' {
                $obj = [PSCustomObject]@{ displayName = 'PipelineName' }
                $result = $obj | Get-AdcsObjectName
                $result | Should -Be 'PipelineName'
            }

            It 'should process multiple objects via pipeline' {
                $obj1 = [PSCustomObject]@{ displayName = 'First' }
                $obj2 = [PSCustomObject]@{ displayName = 'Second' }
                $results = @($obj1, $obj2 | Get-AdcsObjectName)
                $results[0] | Should -Be 'First'
                $results[1] | Should -Be 'Second'
            }

            It 'should return a string for each input object' {
                $obj = [PSCustomObject]@{ displayName = 'StringCheck' }
                ($obj | Get-AdcsObjectName) | Should -BeOfType [string]
            }
        }
    }
}
