BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force -ErrorAction Stop
}

Describe 'Set-CAWebEnrollmentEndpoints' -Tag 'Unit' {
    InModuleScope 'Locksmith2' {
        BeforeEach {
            $script:IssueStore = @{}; $script:PrincipalStore = @{}; $script:AdcsObjectStore = @{}
            $script:DomainStore = @{}; $script:SafePrincipals = @(); $script:DangerousPrincipals = @()
            $script:StandardOwners = @(); $script:DangerousAces = $null; $script:InitializingStores = $false
            $script:RootDSE = $null; $script:Server = $null; $script:Forest = $null; $script:Credential = $null
        }

        Context 'CA with no responding endpoints' {
            It 'should set WebEnrollmentEndpoints to an empty array when all probes return null' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    dNSHostName     = 'ca1.contoso.com'
                }
                Mock Get-WebEnrollmentEndpointStatus { $null }
                $result = $ca | Set-CAWebEnrollmentEndpoints
                $result.WebEnrollmentEndpoints.Count | Should -Be 0
            }
        }

        Context 'CA with an HTTP endpoint' {
            It 'should add an entry to WebEnrollmentEndpoints for a responding HTTP endpoint' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    dNSHostName     = 'ca1.contoso.com'
                }
                Mock Get-WebEnrollmentEndpointStatus {
                    param([string]$Url)
                    if ($Url -match '^http://') {
                        [PSCustomObject]@{ URL = $Url; NtlmOffered = $null; EpaNotRequired = $null }
                    } else {
                        $null
                    }
                }
                $result = $ca | Set-CAWebEnrollmentEndpoints
                $result.WebEnrollmentEndpoints | Should -Not -BeNullOrEmpty
                $result.WebEnrollmentEndpoints[0].URL | Should -Match '^http://'
            }

            It 'should set NtlmOffered=$null for HTTP endpoints' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    dNSHostName     = 'ca1.contoso.com'
                }
                Mock Get-WebEnrollmentEndpointStatus {
                    param([string]$Url)
                    if ($Url -match '^http://') {
                        [PSCustomObject]@{ URL = $Url; NtlmOffered = $null; EpaNotRequired = $null }
                    } else {
                        $null
                    }
                }
                $result = $ca | Set-CAWebEnrollmentEndpoints
                $httpEndpoint = $result.WebEnrollmentEndpoints | Where-Object { $_.URL -match '^http://' } | Select-Object -First 1
                $httpEndpoint.NtlmOffered | Should -BeNullOrEmpty
            }
        }

        Context 'CA with an HTTPS endpoint offering NTLM' {
            It 'should set NtlmOffered=$true on the endpoint entry' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    dNSHostName     = 'ca1.contoso.com'
                }
                Mock Get-WebEnrollmentEndpointStatus {
                    param([string]$Url)
                    if ($Url -match '^https://.*certsrv') {
                        [PSCustomObject]@{ URL = $Url; NtlmOffered = $true; EpaNotRequired = $false }
                    } else {
                        $null
                    }
                }
                $result = $ca | Set-CAWebEnrollmentEndpoints
                $httpsEndpoint = $result.WebEnrollmentEndpoints | Where-Object { $_.URL -match '^https://' } | Select-Object -First 1
                $httpsEndpoint.NtlmOffered | Should -BeTrue
            }
        }

        Context 'CA with an HTTPS endpoint where EPA is not required' {
            It 'should set EpaNotRequired=$true on the endpoint entry' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    dNSHostName     = 'ca1.contoso.com'
                }
                Mock Get-WebEnrollmentEndpointStatus {
                    param([string]$Url)
                    if ($Url -match '^https://.*certsrv') {
                        [PSCustomObject]@{ URL = $Url; NtlmOffered = $false; EpaNotRequired = $true }
                    } else {
                        $null
                    }
                }
                $result = $ca | Set-CAWebEnrollmentEndpoints
                $httpsEndpoint = $result.WebEnrollmentEndpoints | Where-Object { $_.URL -match '^https://' } | Select-Object -First 1
                $httpsEndpoint.EpaNotRequired | Should -BeTrue
            }
        }

        Context 'CA with multiple responding endpoints' {
            It 'should collect all responding endpoints into WebEnrollmentEndpoints' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    dNSHostName     = 'ca1.contoso.com'
                }
                Mock Get-WebEnrollmentEndpointStatus {
                    param([string]$Url)
                    if ($Url -match 'certsrv' -or $Url -match 'mscep') {
                        [PSCustomObject]@{ URL = $Url; NtlmOffered = $null; EpaNotRequired = $null }
                    } else {
                        $null
                    }
                }
                $result = $ca | Set-CAWebEnrollmentEndpoints
                $result.WebEnrollmentEndpoints.Count | Should -BeGreaterThan 1
            }
        }

        Context 'Non-CA objects (passthrough)' {
            It 'should pass through certificate template objects unchanged' {
                $template = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKICertificateTemplate')
                    SchemaClassName = 'pKICertificateTemplate'
                    cn              = 'MyTemplate'
                }
                Mock Get-WebEnrollmentEndpointStatus { throw 'should not be called for templates' }
                $result = $template | Set-CAWebEnrollmentEndpoints
                $result.cn | Should -Be 'MyTemplate'
                Should -Invoke 'Get-WebEnrollmentEndpointStatus' -Times 0
            }
        }

        Context 'CA with no dNSHostName' -Tag 'EdgeCase' {
            It 'should pass through the CA object without probing when dNSHostName is absent' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    dNSHostName     = $null
                }
                Mock Get-WebEnrollmentEndpointStatus { throw 'should not be called without dNSHostName' }
                $result = $ca | Set-CAWebEnrollmentEndpoints
                $result.cn | Should -Be 'MyCA'
                Should -Invoke 'Get-WebEnrollmentEndpointStatus' -Times 0
            }
        }

        Context 'Get-WebEnrollmentEndpointStatus throws on one URL' -Tag 'EdgeCase' {
            It 'should skip the failing URL and still collect other responding endpoints' {
                $ca = New-MockLS2AdcsObject -Properties @{
                    objectClass     = @('top', 'pKIEnrollmentService')
                    SchemaClassName = 'pKIEnrollmentService'
                    cn              = 'MyCA'
                    dNSHostName     = 'ca1.contoso.com'
                }
                # Throw only for the first URL probed; all other certsrv URLs succeed
                Mock Get-WebEnrollmentEndpointStatus {
                    param([string]$Url)
                    if ($Url -eq 'http://ca1.contoso.com/certsrv/') { throw 'simulated network error' }
                    if ($Url -match 'certsrv') {
                        [PSCustomObject]@{ URL = $Url; NtlmOffered = $null; EpaNotRequired = $null }
                    } else {
                        $null
                    }
                }
                { $ca | Set-CAWebEnrollmentEndpoints } | Should -Not -Throw
                $result = $ca | Set-CAWebEnrollmentEndpoints
                $result.WebEnrollmentEndpoints | Should -Not -BeNullOrEmpty
            }
        }
    }
}
