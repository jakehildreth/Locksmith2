function Get-OwningCAHostSid {
    <#
        .SYNOPSIS
        Returns the SID of the CA host computer account that legitimately manages an AD CS object.

        .DESCRIPTION
        A CA host's computer account routinely holds broad rights on the AD objects that belong to
        its own CA. Those rights are expected self-management, not an ESC5 finding.

        An object is considered owned by a CA host when it is:
        - the pKIEnrollmentService (CA) object itself
        - the CA's certificationAuthority object under CN=AIA or CN=Certification Authorities
        - the CA's key recovery agent object under CN=KRA
        - the CA's CRL and delta CRL objects under its host's CDP container
        - the host's CDP container itself (CN=<hostname>,CN=CDP)

        AIA, KRA and Certification Authorities objects must be named for the CA (optionally with a
        key index such as "(1)"), and when both the object and the CA carry certificates
        (CACertificateSubject) their subjects must agree. CRL objects must sit in the host's CDP
        container and be issued by the CA (CRLIssuer matches the CA certificate's subject); when the
        issuer is unknown they fall back to the name, CN=<CAName>(n)[+]. The CDP container is matched
        on the host's short name taken from the CA's dNSHostName. Matching is limited to the
        container the object lives in, so a same-named object elsewhere (for example a certificate
        template) is never matched.

        Only CA objects in the AdcsObjectStore that have a resolved ComputerPrincipal are considered.
        A host never matches objects belonging to a different CA. The one exception is the CDP host
        container: CAs on hosts that share a short name (different domains) share that container,
        so each of their hosts is returned for it.

        .PARAMETER AdcsObject
        The AD CS object to evaluate.

        .INPUTS
        LS2AdcsObject

        .OUTPUTS
        System.String
        The host computer account SID(s), or nothing when the object is not owned by any CA host.

        .EXAMPLE
        $ownHostSids = @(Get-OwningCAHostSid -AdcsObject $object)
        if ($ownHostSids -contains $aceSid.Value) { continue }

        .NOTES
        Requires the CAs in AdcsObjectStore to have been processed by Set-CAComputerPrincipal.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [LS2AdcsObject]$AdcsObject
    )

    process {
        if ($AdcsObject.IsCertificationAuthority()) {
            if ($AdcsObject.ComputerPrincipal) {
                $AdcsObject.ComputerPrincipal
            }
            return
        }

        if (-not $AdcsObject.distinguishedName -or -not $script:AdcsObjectStore) {
            return
        }

        $dn = $AdcsObject.distinguishedName
        $leafName = $AdcsObject.cn
        $objectSubjects = @($AdcsObject.CACertificateSubject)

        # Only objects inside these containers can belong to a CA; skip the store scan for the rest
        if ($dn -notmatch ',CN=(AIA|KRA|Certification Authorities|CDP),CN=Public Key Services,') {
            return
        }

        $script:AdcsObjectStore.Values | Where-Object {
            $_.IsCertificationAuthority() -and $_.ComputerPrincipal
        } | ForEach-Object {
            $caName = [regex]::Escape($_.cn)
            $caSubjects = @($_.CACertificateSubject)
            $hostName = if ($_.dNSHostName) { [regex]::Escape($_.dNSHostName.Split('.')[0]) } else { $null }
            # CA name, optional key index, optional delta CRL marker: "CA", "CA(1)", "CA(1)+"
            $isNamedForCA = $leafName -and $leafName -match "^$caName(\(\d+\))?\+?$"
            $isOwned = $false

            if ($dn -match ',CN=(AIA|KRA|Certification Authorities),CN=Public Key Services,') {
                # When both sides carry certificates, they must agree on the CA's subject
                $certificatesAgree = if ($objectSubjects.Count -and $caSubjects.Count) {
                    @($objectSubjects | Where-Object { $caSubjects -contains $_ }).Count -gt 0
                } else { $true }
                $isOwned = $isNamedForCA -and $certificatesAgree
            } elseif ($hostName -and $dn -match "^CN=$hostName,CN=CDP,CN=Public Key Services,") {
                # The host's CDP container is shared by every CA on that host
                $isOwned = $true
            } elseif ($hostName -and $dn -match "^CN=[^,]+,CN=$hostName,CN=CDP,CN=Public Key Services,") {
                # The CRL's issuer is authoritative; the object name is only a fallback
                $isOwned = if ($AdcsObject.CRLIssuer -and $caSubjects.Count) {
                    $caSubjects -contains $AdcsObject.CRLIssuer
                } else { $isNamedForCA }
            }

            if ($isOwned) {
                $_.ComputerPrincipal
            }
        }
    }
}
