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
        - the CA host's CRL container (CN=<hostname>,CN=CDP) or any object beneath it

        AIA, KRA and Certification Authorities objects are matched on the CA's cn (optionally with a
        key index suffix such as "(1)"). CDP objects are matched on the host's short name taken from
        the CA's dNSHostName. Matching is limited to the container the object lives in, so a
        same-named object elsewhere (for example a certificate template) is never matched.

        Only CA objects in the AdcsObjectStore that have a resolved ComputerPrincipal are considered.
        A host never matches objects belonging to a different CA.

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

        $script:AdcsObjectStore.Values | Where-Object {
            $_.IsCertificationAuthority() -and $_.ComputerPrincipal
        } | ForEach-Object {
            $caName = [regex]::Escape($_.cn)
            $hostName = if ($_.dNSHostName) { [regex]::Escape($_.dNSHostName.Split('.')[0]) } else { $null }
            $isOwned = $false

            if ($leafName -and $leafName -match "^$caName(\(\d+\))?$" -and
                $dn -match ",CN=(AIA|KRA|Certification Authorities),CN=Public Key Services,") {
                $isOwned = $true
            } elseif ($hostName -and $dn -match "(^|,)CN=$hostName,CN=CDP,CN=Public Key Services,") {
                $isOwned = $true
            }

            if ($isOwned) {
                $_.ComputerPrincipal
            }
        }
    }
}
