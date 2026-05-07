#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path $PSScriptRoot '..' '..' '..' 'Private' 'Test'

    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsWindows.ps1') -Raw)))
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsPowerShellCore.ps1') -Raw)))
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsWindowsTerminal.ps1') -Raw)))
}

Describe 'Test-IsWindows' -Tag 'Unit' {

    It 'should return a [bool]' {
        Test-IsWindows | Should -BeOfType [bool]
    }

    It 'should return $true when running PowerShell 5 or earlier (Windows only)' -Skip:($PSVersionTable.PSVersion.Major -gt 5) {
        Test-IsWindows | Should -BeTrue
    }

    It 'should return $true on any Windows environment' -Skip:(-not $IsWindows -and $PSVersionTable.PSVersion.Major -gt 5) {
        # On Windows (any PS version) the result must be $true
        Test-IsWindows | Should -BeTrue
    }

    It 'should return $false on non-Windows systems with PS 6+' -Skip:($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) {
        Test-IsWindows | Should -BeFalse
    }
}

Describe 'Test-IsPowerShellCore' -Tag 'Unit' {

    It 'should return a [bool]' {
        Test-IsPowerShellCore | Should -BeOfType [bool]
    }

    It 'should return $true when PSEdition is Core' -Skip:($PSEdition -ne 'Core') {
        Test-IsPowerShellCore | Should -BeTrue
    }

    It 'should return $false when PSEdition is Desktop' -Skip:($PSEdition -ne 'Desktop') {
        Test-IsPowerShellCore | Should -BeFalse
    }

    It 'should reflect the current session PSEdition' {
        $expected = [bool]($PSEdition -eq 'Core')
        Test-IsPowerShellCore | Should -Be $expected
    }
}

Describe 'Test-IsWindowsTerminal' -Tag 'Unit' {

    BeforeEach {
        $script:OriginalWtSession = $env:WT_SESSION
    }

    AfterEach {
        $env:WT_SESSION = $script:OriginalWtSession
    }

    It 'should return a [bool]' {
        Test-IsWindowsTerminal | Should -BeOfType [bool]
    }

    It 'should return $true when WT_SESSION environment variable is set to a non-empty value' {
        $env:WT_SESSION = '12345678-1234-1234-1234-123456789012'
        Test-IsWindowsTerminal | Should -BeTrue
    }

    It 'should return $false when WT_SESSION environment variable is null' {
        $env:WT_SESSION = $null
        Test-IsWindowsTerminal | Should -BeFalse
    }

    It 'should return $false when WT_SESSION environment variable is empty string' {
        $env:WT_SESSION = ''
        Test-IsWindowsTerminal | Should -BeFalse
    }

    It 'should reflect any non-empty WT_SESSION value as $true' {
        $env:WT_SESSION = 'anyvalue'
        Test-IsWindowsTerminal | Should -BeTrue
    }
}
