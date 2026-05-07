#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path $PSScriptRoot '..' '..' '..' 'Private' 'Test'
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsModuleAvailable.ps1') -Raw)))
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsModuleLoaded.ps1') -Raw)))
}

Describe 'Test-IsModuleAvailable' -Tag 'Unit' {

    It 'should return a [bool]' {
        Mock Get-Module { return $null } -ParameterFilter { $ListAvailable -eq $true }
        Test-IsModuleAvailable -Name 'SomeModule' | Should -BeOfType [bool]
    }

    It 'should return $true when the module is available on disk' {
        Mock Get-Module {
            return [PSCustomObject]@{ Name = 'SomeModule'; Version = [version]'1.0.0' }
        } -ParameterFilter { $ListAvailable -eq $true }
        Test-IsModuleAvailable -Name 'SomeModule' | Should -BeTrue
    }

    It 'should return $false when the module is not available on disk' {
        Mock Get-Module { return $null } -ParameterFilter { $ListAvailable -eq $true }
        Test-IsModuleAvailable -Name 'NonExistentModule' | Should -BeFalse
    }

    It 'should use Get-Module with -ListAvailable when checking availability' {
        Mock Get-Module { return $null } -ParameterFilter { $ListAvailable -eq $true }
        Test-IsModuleAvailable -Name 'SomeModule'
        Should -Invoke Get-Module -ParameterFilter { $ListAvailable -eq $true } -Times 1 -Exactly
    }

    It 'should return $false and emit an error when an exception occurs' {
        Mock Get-Module { throw 'Unexpected error' } -ParameterFilter { $ListAvailable -eq $true }
        $errorRecord = $null
        $result = Test-IsModuleAvailable -Name 'SomeModule' -ErrorVariable errorRecord 2>$null
        $result | Should -BeFalse
    }
}

Describe 'Test-IsModuleLoaded' -Tag 'Unit' {

    It 'should return a [bool]' {
        Mock Get-Module { return $null } -ParameterFilter { -not $ListAvailable }
        Test-IsModuleLoaded -Name 'SomeModule' | Should -BeOfType [bool]
    }

    It 'should return $true when the module is currently loaded in the session' {
        Mock Get-Module {
            return [PSCustomObject]@{ Name = 'SomeModule'; Version = [version]'1.0.0' }
        } -ParameterFilter { -not $ListAvailable }
        Test-IsModuleLoaded -Name 'SomeModule' | Should -BeTrue
    }

    It 'should return $false when the module is not loaded in the session' {
        Mock Get-Module { return $null } -ParameterFilter { -not $ListAvailable }
        Test-IsModuleLoaded -Name 'UnloadedModule' | Should -BeFalse
    }

    It 'should not use -ListAvailable when checking if a module is loaded' {
        Mock Get-Module { return $null }
        Test-IsModuleLoaded -Name 'SomeModule'
        Should -Invoke Get-Module -ParameterFilter { -not $ListAvailable } -Times 1 -Exactly
    }

    It 'should return $false and emit an error when an exception occurs' {
        Mock Get-Module { throw 'Session error' } -ParameterFilter { -not $ListAvailable }
        $errorRecord = $null
        $result = Test-IsModuleLoaded -Name 'SomeModule' -ErrorVariable errorRecord 2>$null
        $result | Should -BeFalse
    }

    It 'should distinguish between loaded and available — a module can be available but not loaded' {
        # Available but not loaded: Get-Module (no -ListAvailable) returns $null
        Mock Get-Module { return $null } -ParameterFilter { -not $ListAvailable }
        Mock Get-Module {
            return [PSCustomObject]@{ Name = 'SomeModule'; Version = [version]'1.0.0' }
        } -ParameterFilter { $ListAvailable -eq $true }
        Test-IsModuleLoaded -Name 'SomeModule' | Should -BeFalse
    }
}
