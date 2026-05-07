#requires -Version 5.1
BeforeAll {
    $SourcePath = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test\Test-IsUtf8.ps1'
    . ([scriptblock]::Create((Get-Content -Path $SourcePath -Raw)))
}

Describe 'Test-IsUtf8' -Tag 'Unit' {

    BeforeEach {
        $script:OriginalEncoding = [Console]::OutputEncoding
    }

    AfterEach {
        [Console]::OutputEncoding = $script:OriginalEncoding
    }

    It 'should return a [bool]' {
        Test-IsUtf8 | Should -BeOfType [bool]
    }

    It 'should return $true when console output encoding is UTF-8 (CodePage 65001)' {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        Test-IsUtf8 | Should -BeTrue
    }

    It 'should return $false when console output encoding is ASCII (CodePage 20127)' {
        [Console]::OutputEncoding = [System.Text.Encoding]::ASCII
        Test-IsUtf8 | Should -BeFalse
    }

    It 'should return $false when console output encoding is Unicode UTF-16 (CodePage 1200)' {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        Test-IsUtf8 | Should -BeFalse
    }

    It 'should return $false when console output encoding is Latin-1 (CodePage 1252)' {
        [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(1252)
        Test-IsUtf8 | Should -BeFalse
    }

    It 'should correctly identify UTF-8 encoding by CodePage 65001 only' {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        [Console]::OutputEncoding.CodePage | Should -Be 65001
        Test-IsUtf8 | Should -BeTrue
    }
}
