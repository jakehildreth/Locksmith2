#requires -Version 5.1
# Integration tests — require a live AD CS environment.
# Set $env:LS2_TEST_FOREST to enable all integration tests.
# Set $env:LS2_TEST_CA_HOST to target a specific CA host (e.g., 'ca1.contoso.com').
# Tests tagged 'Integration' and auto-skipped in CI when env vars are absent.

BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop

    $script:TestForest = $env:LS2_TEST_FOREST
    $script:TestCaHost = $env:LS2_TEST_CA_HOST
}

InModuleScope 'Locksmith2' {
    Describe 'Get-WebEnrollmentEndpointStatus — Integration' -Tag 'Integration' {
        Context 'Endpoint existence probe (HTTP)' {
            It 'should return null for a URL that does not respond' -Skip:([string]::IsNullOrEmpty($script:TestCaHost)) {
                $result = Get-WebEnrollmentEndpointStatus -Url "http://does-not-exist.invalid/certsrv/"
                $result | Should -BeNullOrEmpty
            }

            It 'should return a hashtable with URL, NtlmOffered, EpaNotRequired when HTTP certsrv responds' -Skip:([string]::IsNullOrEmpty($script:TestCaHost)) {
                $url = "http://$($script:TestCaHost)/certsrv/"
                $result = Get-WebEnrollmentEndpointStatus -Url $url
                if ($null -ne $result) {
                    $result.URL | Should -Be $url
                    $result.NtlmOffered | Should -BeNullOrEmpty
                    $result.EpaNotRequired | Should -BeNullOrEmpty
                }
            }
        }

        Context 'Endpoint existence probe (local HttpListener)' {
            BeforeAll {
                $script:port = Get-Random -Minimum 20000 -Maximum 40000
                $script:serverJob = Start-Job -ArgumentList $script:port -ScriptBlock {
                    param($port)
                    $listener = [System.Net.HttpListener]::new()
                    $listener.Prefixes.Add("http://localhost:$port/")
                    $listener.Start()
                    try {
                        while ($true) {
                            $ctx = $listener.GetContext()
                            $ctx.Response.StatusCode = if ($ctx.Request.Url.AbsolutePath -eq '/certsrv/') { 401 } else { 404 }
                            $ctx.Response.Close()
                        }
                    } finally {
                        $listener.Stop()
                    }
                }
                $deadline = [datetime]::UtcNow.AddSeconds(10)
                do {
                    Start-Sleep -Milliseconds 200
                    $ready = $null -ne (Get-WebEnrollmentEndpointStatus -Url "http://localhost:$($script:port)/certsrv/")
                } until ($ready -or [datetime]::UtcNow -gt $deadline)
            }
            AfterAll {
                Stop-Job $script:serverJob
                Remove-Job $script:serverJob -Force
            }

            It 'should return null when nothing is listening' {
                Get-WebEnrollmentEndpointStatus -Url 'http://localhost:1/certsrv/' | Should -BeNullOrEmpty
            }

            It 'should return null when the server answers 404 (path not served)' {
                $result = Get-WebEnrollmentEndpointStatus -Url "http://localhost:$($script:port)/missing/"
                $result | Should -BeNullOrEmpty
            }

            It 'should return the endpoint when the server answers 401 (auth challenge)' {
                $result = Get-WebEnrollmentEndpointStatus -Url "http://localhost:$($script:port)/certsrv/"
                $result.URL | Should -Be "http://localhost:$($script:port)/certsrv/"
            }
        }

        Context 'NTLM detection (HTTPS)' {
            It 'should return NtlmOffered=$true or $false for a responding HTTPS endpoint' -Skip:([string]::IsNullOrEmpty($script:TestCaHost)) {
                $url = "https://$($script:TestCaHost)/certsrv/"
                $result = Get-WebEnrollmentEndpointStatus -Url $url
                if ($null -ne $result) {
                    $result.NtlmOffered | Should -BeIn @($true, $false)
                }
            }
        }

        Context 'EPA detection (HTTPS + Negotiate)' {
            It 'should return EpaNotRequired=$true or $false for a responding HTTPS endpoint' -Skip:([string]::IsNullOrEmpty($script:TestCaHost)) {
                $url = "https://$($script:TestCaHost)/certsrv/"
                $result = Get-WebEnrollmentEndpointStatus -Url $url
                if ($null -ne $result) {
                    $result.EpaNotRequired | Should -BeIn @($true, $false)
                }
            }
        }
    }
}
