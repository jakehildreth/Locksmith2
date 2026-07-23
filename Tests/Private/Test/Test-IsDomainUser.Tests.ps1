#requires -Version 5.1
BeforeAll {
    $PrivateTestRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Test'
    . ([scriptblock]::Create((Get-Content -Path (Join-Path $PrivateTestRoot 'Test-IsDomainUser.ps1') -Raw)))
}

# Pre-compute domain status at script scope so -Skip: expressions have a simple bool variable.
# try/catch is not allowed inline in Pester's -Skip: argument during discovery.
$script:IsDomainUserEnv = $false
try {
    [void][System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $script:IsDomainUserEnv = $true
} catch {
    $script:IsDomainUserEnv = $false
}

Describe 'Test-IsDomainUser' -Tag 'Integration' {

    It 'should return a [bool]' {
        Test-IsDomainUser | Should -BeOfType [bool]
    }

    It 'should return $true when running as a domain account' -Skip:(-not $script:IsDomainUserEnv) {
        Test-IsDomainUser | Should -BeTrue
    }

    It 'should return $false when running as a non-domain account' -Skip:($script:IsDomainUserEnv) {
        Test-IsDomainUser | Should -BeFalse
    }
}
