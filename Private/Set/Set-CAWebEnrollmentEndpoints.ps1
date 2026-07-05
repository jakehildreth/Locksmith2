function Set-CAWebEnrollmentEndpoints {
    <#
    .SYNOPSIS
        Probes web enrollment endpoints on each CA and stores results on the CA object.

    .DESCRIPTION
        For each pKIEnrollmentService (CA) object, constructs candidate URLs from the known
        web enrollment paths and the CA's dNSHostName, then probes each URL using
        Get-WebEnrollmentEndpointStatus. Responding endpoints are collected into the
        WebEnrollmentEndpoints property on the CA object.

        Paths probed (both http:// and https://):
            certsrv/
            {CAName}_CES_Kerberos/service.svc
            {CAName}_CES_Kerberos/service.svc/CES
            ADPolicyProvider_CEP_Kerberos/service.svc
            certsrv/mscep/

    .PARAMETER AdcsObject
        One or more LS2AdcsObject instances. Non-CA objects are passed through unchanged.

    .INPUTS
        LS2AdcsObject[]

    .OUTPUTS
        LS2AdcsObject[]

    .EXAMPLE
        $CAs | Set-CAWebEnrollmentEndpoints

    .NOTES
        Requires Get-WebEnrollmentEndpointStatus (Private/Get).
        CAs without dNSHostName are passed through without probing.
        Probe errors on individual URLs are suppressed; remaining URLs still probed.
    #>
    [CmdletBinding()]
    [OutputType([LS2AdcsObject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [LS2AdcsObject[]]$AdcsObject
    )

    begin {
        Write-Verbose 'Set-CAWebEnrollmentEndpoints: probing web enrollment endpoints...'
    }

    process {
        foreach ($object in $AdcsObject) {
            if (-not $object.IsCertificationAuthority()) {
                $object
                continue
            }

            $hostName = $object.dNSHostName
            if ([string]::IsNullOrEmpty($hostName)) {
                Write-Verbose "Set-CAWebEnrollmentEndpoints: skipping $($object.cn) - no dNSHostName"
                $object
                continue
            }

            $caName = $object.cn
            $paths = @(
                'certsrv/',
                "${caName}_CES_Kerberos/service.svc",
                "${caName}_CES_Kerberos/service.svc/CES",
                'ADPolicyProvider_CEP_Kerberos/service.svc',
                'certsrv/mscep/'
            )

            $endpoints = [System.Collections.Generic.List[object]]::new()

            foreach ($path in $paths) {
                foreach ($scheme in @('http', 'https')) {
                    $url = "${scheme}://${hostName}/${path}"
                    try {
                        $status = Get-WebEnrollmentEndpointStatus -Url $url
                        if ($null -ne $status) {
                            $endpoints.Add($status)
                        }
                    } catch {
                        Write-Verbose "Set-CAWebEnrollmentEndpoints: probe error for $url - $($_.Exception.Message)"
                    }
                }
            }

            $object.WebEnrollmentEndpoints = $endpoints.ToArray()
            $object
        }
    }

    end {
        Write-Verbose 'Set-CAWebEnrollmentEndpoints: done.'
    }
}
