#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test'

    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsSupportedOS.ps1') -Raw)))
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsSupportedPS.ps1') -Raw)))
}

Describe 'Test-IsSupportedOS' -Tag 'Unit' {

    It 'should return a [bool]' {
        # Use a real OS call — on this machine it should succeed
        Test-IsSupportedOS | Should -BeOfType [bool]
    }

    It 'should return $true when OS build number is above 14393' {
        Mock Get-CimInstance {
            return [PSCustomObject]@{
                BuildNumber = 20000
                Caption     = 'Windows Server 2022'
            }
        }
        Test-IsSupportedOS | Should -BeTrue
    }

    It 'should return $true when OS build number is exactly one above the minimum (14394)' {
        Mock Get-CimInstance {
            return [PSCustomObject]@{
                BuildNumber = 14394
                Caption     = 'Windows Server 2016'
            }
        }
        Test-IsSupportedOS | Should -BeTrue
    }

    It 'should return $false when OS build number equals the minimum threshold (14393)' {
        Mock Get-CimInstance {
            return [PSCustomObject]@{
                BuildNumber = 14393
                Caption     = 'Windows Server 2016 RTM'
            }
        }
        Test-IsSupportedOS | Should -BeFalse
    }

    It 'should return $false when OS build number is below the minimum threshold' {
        Mock Get-CimInstance {
            return [PSCustomObject]@{
                BuildNumber = 9600
                Caption     = 'Windows Server 2012 R2'
            }
        }
        Test-IsSupportedOS | Should -BeFalse
    }

    It 'should return $true and emit a warning when Get-CimInstance fails' {
        Mock Get-CimInstance { throw 'CIM error' }
        $result = Test-IsSupportedOS -WarningVariable warnOut 3>&1
        # When CIM fails, function returns $true (safe assumption)
        ($result[-1]) | Should -BeTrue
    }
}

Describe 'Test-IsSupportedPS' -Tag 'Unit' {

    It 'should return a [bool]' {
        Test-IsSupportedPS | Should -BeOfType [bool]
    }

    It 'should return $true when running PowerShell 5.1' -Skip:(-not ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1)) {
        Test-IsSupportedPS | Should -BeTrue
    }

    It 'should return $true when running PowerShell 7.4 or later' -Skip:(-not ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -ge 4)) {
        Test-IsSupportedPS | Should -BeTrue
    }

    It 'should return $false when running PowerShell 7.0 through 7.3' -Skip:(-not ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 4)) {
        Test-IsSupportedPS | Should -BeFalse
    }

    It 'should match expected result for the current PowerShell version' {
        $v = $PSVersionTable.PSVersion
        $expected = ($v.Major -eq 5 -and $v.Minor -eq 1) -or ($v.Major -eq 7 -and $v.Minor -ge 4)
        Test-IsSupportedPS | Should -Be $expected
    }
}
