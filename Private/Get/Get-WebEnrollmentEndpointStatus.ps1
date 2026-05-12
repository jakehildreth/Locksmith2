function Get-WebEnrollmentEndpointStatus {
    <#
    .SYNOPSIS
        Probes a single web enrollment URL and returns its authentication posture.

    .DESCRIPTION
        Sends anonymous and (for HTTPS) Negotiate HTTP requests to the given URL using
        System.Net.Http.HttpClient. Returns $null when the endpoint does not respond.
        For responding endpoints, returns a PSCustomObject describing whether NTLM is
        offered and whether Extended Protection for Authentication (EPA) is not required.

        Probe 1 (anonymous GET):
          - Determines whether the endpoint exists.
          - Reads the WWW-Authenticate header to detect NTLM.
          - HTTP endpoints stop here; NtlmOffered and EpaNotRequired are both $null.

        Probe 2 (Negotiate GET, HTTPS only):
          - Uses HttpClientHandler with DefaultNetworkCredentials and Negotiate.
          - A 200 response indicates channel binding (EPA) was not required.
          - A 401/403 response indicates EPA may be enforced (conservative $false).

    .PARAMETER Url
        The full URL to probe (e.g., 'http://ca1.contoso.com/certsrv/').

    .OUTPUTS
        PSCustomObject with properties URL, NtlmOffered, EpaNotRequired.
        Returns $null when the endpoint is unreachable or times out.

    .NOTES
        Intentionally has no unit tests - HttpClient cannot be mocked in Pester.
        Use integration tests (Get-WebEnrollmentEndpointStatus.Integration.Tests.ps1)
        against a live AD CS environment.
        SSL certificate validation is intentionally disabled to probe self-signed certs.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    $isHttps = $Url -match '^https://'

    # --- Probe 1: anonymous GET ---
    $anonHandler = $null
    $anonClient = $null
    try {
        $anonHandler = [System.Net.Http.HttpClientHandler]::new()
        $anonHandler.AllowAutoRedirect = $false
        $anonHandler.UseDefaultCredentials = $false

        if ($isHttps) {
            try {
                # .NET 4.6.1+ / Core: disable SSL cert validation for self-signed certs
                $anonHandler.ServerCertificateCustomValidationCallback = {
                    param($sender, $cert, $chain, $sslPolicyErrors)
                    return $true
                }
            } catch {
                # PS5.1 fallback - ServicePointManager is process-wide but necessary
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
        }

        $anonClient = [System.Net.Http.HttpClient]::new($anonHandler)
        $anonClient.Timeout = [System.TimeSpan]::FromSeconds(10)

        $anonResponse = $anonClient.GetAsync($Url).GetAwaiter().GetResult()

        if ($isHttps) {
            # Detect NTLM in WWW-Authenticate
            $wwwAuth = ''
            if ($anonResponse.Headers.Contains('WWW-Authenticate')) {
                $wwwAuth = $anonResponse.Headers.GetValues('WWW-Authenticate') -join ', '
            }
            $ntlmOffered = $wwwAuth -match '(?i)\bNTLM\b'
        } else {
            # HTTP: always exists, no auth probing
            return [PSCustomObject]@{
                URL           = $Url
                NtlmOffered   = $null
                EpaNotRequired = $null
            }
        }
    } catch [System.Net.Http.HttpRequestException] {
        Write-Verbose "Get-WebEnrollmentEndpointStatus: connection failed for $Url - $($_.Exception.Message)"
        return $null
    } catch [System.OperationCanceledException] {
        Write-Verbose "Get-WebEnrollmentEndpointStatus: timeout for $Url"
        return $null
    } catch {
        Write-Verbose "Get-WebEnrollmentEndpointStatus: unexpected error for $Url - $($_.Exception.Message)"
        return $null
    } finally {
        if ($null -ne $anonClient) { $anonClient.Dispose() }
        if ($null -ne $anonHandler) { $anonHandler.Dispose() }
    }

    # --- Probe 2 (HTTPS only): Negotiate auth to detect EPA ---
    $authHandler = $null
    $authClient = $null
    $epaNotRequired = $false
    try {
        $authHandler = [System.Net.Http.HttpClientHandler]::new()
        $authHandler.AllowAutoRedirect = $false

        try {
            $authHandler.ServerCertificateCustomValidationCallback = {
                param($sender, $cert, $chain, $sslPolicyErrors)
                return $true
            }
        } catch {
            # ServicePointManager already set above - no-op
        }

        $credentialCache = [System.Net.CredentialCache]::new()
        $credentialCache.Add([System.Uri]::new($Url), 'Negotiate', [System.Net.CredentialCache]::DefaultNetworkCredentials)
        $authHandler.Credentials = $credentialCache
        $authHandler.PreAuthenticate = $false

        $authClient = [System.Net.Http.HttpClient]::new($authHandler)
        $authClient.Timeout = [System.TimeSpan]::FromSeconds(10)

        $authResponse = $authClient.GetAsync($Url).GetAwaiter().GetResult()
        $statusCode = [int]$authResponse.StatusCode

        # 200 = auth succeeded without EPA -- not required
        # 401/403 = server rejected -- EPA may be enforced (conservative)
        $epaNotRequired = ($statusCode -eq 200)
    } catch {
        Write-Verbose "Get-WebEnrollmentEndpointStatus: Negotiate probe failed for $Url - $($_.Exception.Message)"
        $epaNotRequired = $false
    } finally {
        if ($null -ne $authClient) { $authClient.Dispose() }
        if ($null -ne $authHandler) { $authHandler.Dispose() }
    }

    return [PSCustomObject]@{
        URL            = $Url
        NtlmOffered    = [bool]$ntlmOffered
        EpaNotRequired = [bool]$epaNotRequired
    }
}
