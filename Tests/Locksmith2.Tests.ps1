#requires -Version 5.1
BeforeAll {
    $ModuleRoot   = Split-Path -Parent $PSScriptRoot
    $ManifestPath = Join-Path $ModuleRoot 'Locksmith2.psd1'
    Import-Module $ManifestPath -Force -ErrorAction Stop
}

Describe 'Locksmith2 Module Manifest' -Tag 'Unit' {
    BeforeAll {
        $ManifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Locksmith2.psd1'
    }

    It 'should have a valid module manifest' {
        { Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'should import without errors' {
        { Import-Module $ManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
    }

    It 'should target PowerShell 5.1 or higher' {
        $manifest = Test-ModuleManifest -Path $ManifestPath -ErrorAction SilentlyContinue
        [version]$manifest.PowerShellVersion | Should -BeLessOrEqual ([version]'5.1')
    }

    It 'should declare both Desktop and Core compatible editions' {
        $manifest = Test-ModuleManifest -Path $ManifestPath -ErrorAction SilentlyContinue
        $manifest.CompatiblePSEditions | Should -Contain 'Desktop'
        $manifest.CompatiblePSEditions | Should -Contain 'Core'
    }
}

Describe 'Locksmith2 Public API' -Tag 'Unit' {
    $ExpectedFunctions = @(
        'Find-LS2VulnerableTemplate'
        'Find-LS2VulnerableCA'
        'Find-LS2VulnerableObject'
        'Find-LS2RiskyPrincipal'
        'Get-LS2Stores'
        'Invoke-Locksmith2'
        'New-LS2Dashboard'
        'Set-LS2Credential'
        'Set-LS2Forest'
    )

    It 'should export <_>' -ForEach $ExpectedFunctions {
        Get-Command -Module Locksmith2 -Name $_ -ErrorAction SilentlyContinue |
            Should -Not -BeNullOrEmpty -Because "the public cmdlet '$_' must be accessible"
    }
}

Describe 'Locksmith2 PSScriptAnalyzer' -Tag 'Unit', 'ScriptAnalyzer' {
    BeforeAll {
        $ModuleRoot   = Split-Path -Parent $PSScriptRoot
        $PSAAvailable = $null -ne (Get-Module PSScriptAnalyzer -ListAvailable -ErrorAction SilentlyContinue)
    }

    It 'should have no PSScriptAnalyzer errors or warnings' -Skip:(-not $PSAAvailable) {
        $violations = Invoke-ScriptAnalyzer -Path $ModuleRoot -Recurse -Severity Warning, Error -ErrorAction SilentlyContinue
        # Exclude the Tests directory from analysis
        $violations = $violations | Where-Object { $_.ScriptPath -notlike '*Tests*' }
        $violations | Format-List ScriptPath, RuleName, Message | Out-String | Write-Verbose -Verbose
        $violations | Should -BeNullOrEmpty
    }
}
