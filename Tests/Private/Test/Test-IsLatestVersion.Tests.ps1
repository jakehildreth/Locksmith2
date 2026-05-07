#requires -Version 5.1
BeforeAll {
    $SourcePath = Join-Path $PSScriptRoot '..' '..' '..' 'Private' 'Test' 'Test-IsLatestVersion.ps1'
    . ([scriptblock]::Create((Get-Content -Path $SourcePath -Raw)))
}

Describe 'Test-IsLatestVersion' -Tag 'Unit' {

    Context 'Module not loaded' {

        It 'should return $false when the named module is not loaded' {
            Mock Get-Module { return $null }
            $result = Test-IsLatestVersion -Name 'SomeModule' -ErrorVariable errOut 2>$null
            $result | Should -BeFalse
        }

        It 'should emit an error when the named module is not loaded' {
            Mock Get-Module { return $null }
            $errorRecord = $null
            Test-IsLatestVersion -Name 'SomeModule' -ErrorVariable errorRecord 2>$null
            $errorRecord | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Module loaded, gallery reachable' {

        It 'should return $true when the running version equals the gallery version' {
            Mock Get-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'2.0.0' }
            }
            Mock Find-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'2.0.0' }
            }
            Test-IsLatestVersion -Name 'TestModule' | Should -BeTrue
        }

        It 'should return $true when the running version is newer than the gallery version' {
            Mock Get-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'2.1.0' }
            }
            Mock Find-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'2.0.0' }
            }
            Test-IsLatestVersion -Name 'TestModule' | Should -BeTrue
        }

        It 'should return $false when the running version is older than the gallery version' {
            Mock Get-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'1.0.0' }
            }
            Mock Find-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'2.0.0' }
            }
            Test-IsLatestVersion -Name 'TestModule' | Should -BeFalse
        }

        It 'should return a [bool]' {
            Mock Get-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'1.0.0' }
            }
            Mock Find-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'1.0.0' }
            }
            Test-IsLatestVersion -Name 'TestModule' | Should -BeOfType [bool]
        }
    }

    Context 'Module loaded, gallery unreachable' {

        It 'should return $true when Find-Module fails (gallery unreachable)' {
            Mock Get-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'1.0.0' }
            }
            Mock Find-Module { throw 'Network error' }
            $result = Test-IsLatestVersion -Name 'TestModule' -WarningVariable warnOut 3>&1
            ($result[-1]) | Should -BeTrue
        }

        It 'should emit a warning when the gallery is unreachable' {
            Mock Get-Module {
                return [PSCustomObject]@{ Name = 'TestModule'; Version = [version]'1.0.0' }
            }
            Mock Find-Module { throw 'Network error' }
            $warnings = @()
            Test-IsLatestVersion -Name 'TestModule' -WarningVariable warnings 3>$null
            $warnings | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Pipeline input' {

        It 'should accept module name via pipeline' {
            Mock Get-Module {
                return [PSCustomObject]@{ Name = 'PipelineModule'; Version = [version]'1.0.0' }
            }
            Mock Find-Module {
                return [PSCustomObject]@{ Name = 'PipelineModule'; Version = [version]'1.0.0' }
            }
            'PipelineModule' | Test-IsLatestVersion | Should -BeTrue
        }
    }
}
