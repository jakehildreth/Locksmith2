#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test'
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsDomainComputer.ps1') -Raw)))
}

Describe 'Test-IsDomainComputer' -Tag 'Unit' {

    It 'should return a [bool]' {
        Mock Get-CimInstance {
            return [PSCustomObject]@{ Name = 'MYPC'; Domain = 'contoso.com'; PartOfDomain = $true }
        }
        Test-IsDomainComputer | Should -BeOfType [bool]
    }

    It 'should return $true when PartOfDomain is $true' {
        Mock Get-CimInstance {
            return [PSCustomObject]@{ Name = 'MYPC'; Domain = 'contoso.com'; PartOfDomain = $true }
        }
        Test-IsDomainComputer | Should -BeTrue
    }

    It 'should return $false when PartOfDomain is $false' {
        Mock Get-CimInstance {
            return [PSCustomObject]@{ Name = 'STANDALONE'; Domain = 'WORKGROUP'; PartOfDomain = $false }
        }
        Test-IsDomainComputer | Should -BeFalse
    }

    It 'should return $false and write a non-terminating error when Get-CimInstance throws' {
        Mock Get-CimInstance { throw 'WMI unavailable' }
        $result = Test-IsDomainComputer -ErrorVariable errOut -ErrorAction SilentlyContinue
        $result | Should -BeFalse
        $errOut | Should -Not -BeNullOrEmpty
    }
}
