#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $SettingsPath = Join-Path $ModuleRoot 'PSScriptAnalyzerSettings.psd1'
    $fileCases = Get-ChildItem -Recurse -Include '*.ps1', '*.psm1' -Path @(
        (Join-Path $ModuleRoot 'Classes'),
        (Join-Path $ModuleRoot 'Private'),
        (Join-Path $ModuleRoot 'Public')
    ) | Sort-Object FullName | ForEach-Object {
        @{
            Name         = $_.Name
            FullName     = $_.FullName
            SettingsPath = $SettingsPath
        }
    }
}

Describe 'PSScriptAnalyzer' -Tag 'ScriptAnalyzer' {
    BeforeAll {
        $ModuleRoot = Split-Path $PSScriptRoot -Parent
    }

    It 'PSScriptAnalyzer module should be available' {
        Get-Module -Name PSScriptAnalyzer -ListAvailable | Should -Not -BeNullOrEmpty
    }

    It 'PSScriptAnalyzerSettings.psd1 should exist at module root' {
        Join-Path $ModuleRoot 'PSScriptAnalyzerSettings.psd1' | Should -Exist
    }

    It 'should pass PSScriptAnalyzer for <Name>' -ForEach $fileCases {
        $violations = Invoke-ScriptAnalyzer -Path $FullName -Settings $SettingsPath -Severity Warning, Error
        if ($violations) {
            $detail = ($violations | ForEach-Object {
                "  [$($_.Severity)] $($_.RuleName) at line $($_.Line): $($_.Message)"
            }) -join "`n"
            $violations | Should -BeNullOrEmpty -Because "`n$detail"
        } else {
            $violations | Should -BeNullOrEmpty
        }
    }
}
