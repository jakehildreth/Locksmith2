function Set-LinkedGroupOIDPolicy {
    <#
        .SYNOPSIS
        Adds HasLinkedGroupOIDPolicy and LinkedGroupOIDPolicies properties to AD CS certificate
        template objects.

        .DESCRIPTION
        Examines the CertificatePolicy property (msPKI-Certificate-Policy) of each certificate
        template against the set of msPKI-Enterprise-Oid objects in the AdcsObjectStore.

        An msPKI-Enterprise-Oid object that has msDS-OIDToGroupLink set links its OID value to
        a universal group. When a certificate template lists such an OID as an application
        policy and supports Client Authentication, any principal who enrolls and uses the issued
        certificate gains the rights of the linked group while that group's membership appears
        empty — the ESC13 attack path.

        This function adds two synthetic properties to each certificate template:
        1. HasLinkedGroupOIDPolicy: Boolean indicating whether at least one policy OID on the
           template is linked to a group via msDS-OIDToGroupLink.
        2. LinkedGroupOIDPolicies: Array of group DNs linked to the template's policy OIDs.

        IMPORTANT: This function requires $script:AdcsObjectStore to be fully populated before
        it is called. It must run after Get-AdcsObject has completed so that all
        msPKI-Enterprise-Oid objects are present in the store.

        .PARAMETER AdcsObject
        One or more LS2AdcsObject instances representing AD CS certificate templates.
        Non-template objects are passed through unmodified.

        .INPUTS
        LS2AdcsObject[]

        .OUTPUTS
        LS2AdcsObject[]
        Returns the input objects. Templates have HasLinkedGroupOIDPolicy and
        LinkedGroupOIDPolicies set. Non-templates are passed through unchanged.

        .EXAMPLE
        $templates | Set-LinkedGroupOIDPolicy
        Processes all certificate templates and adds the linked group OID properties.

        .EXAMPLE
        Get-AdcsObject | Where-Object { $_.IsCertificateTemplate() } | Set-LinkedGroupOIDPolicy
        Retrieves all templates and evaluates which ones have group-linked application policy OIDs.

        .NOTES
        Author: Jake Hildreth (@jakehildreth)
        Module: Locksmith2
        Requires: PowerShell 5.1+

        Requires script-scope variable set by Initialize-AdcsObjectStore:
        - $script:AdcsObjectStore: Cache of all AD CS objects (must include msPKI-Enterprise-Oid objects)

        Used by ESC13 detection in Find-LS2VulnerableTemplate.

        Reference: https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53

        .LINK
        Set-AuthenticationEKUExist

        .LINK
        Find-LS2VulnerableTemplate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [LS2AdcsObject[]]$AdcsObject
    )

    begin {
        Write-Verbose 'Building OID-to-group lookup map from AdcsObjectStore...'

        # Build a map of CertTemplateOID -> OIDToGroupLink for all OID objects that have a group link.
        # msPKI-Enterprise-Oid objects live in CN=OID,CN=Public Key Services,... and are collected
        # by Get-AdcsObject as part of its full subtree search.
        $oidGroupMap = @{}
        if ($script:AdcsObjectStore) {
            $script:AdcsObjectStore.Values | Where-Object { $_.OIDToGroupLink } | ForEach-Object {
                if ($_.CertTemplateOID) {
                    $oidGroupMap[$_.CertTemplateOID] = $_.OIDToGroupLink
                    Write-Verbose "  OID '$($_.CertTemplateOID)' -> group '$($_.OIDToGroupLink)'"
                }
            }
        }
        Write-Verbose "OID-to-group map has $($oidGroupMap.Count) entry/entries"
    }

    process {
        foreach ($obj in $AdcsObject) {
            if ($obj.SchemaClassName -ne 'pKICertificateTemplate') {
                $obj
                continue
            }

            try {
                $linkedGroups = [System.Collections.Generic.List[string]]::new()

                if ($oidGroupMap.Count -gt 0 -and $obj.CertificatePolicy -and $obj.CertificatePolicy.Count -gt 0) {
                    foreach ($oid in $obj.CertificatePolicy) {
                        if ($oidGroupMap.ContainsKey($oid)) {
                            $linkedGroups.Add($oidGroupMap[$oid])
                            Write-Verbose "  Template '$($obj.Name)': policy OID '$oid' links to group '$($oidGroupMap[$oid])'"
                        }
                    }
                }

                $obj.LinkedGroupOIDPolicies  = $linkedGroups.ToArray()
                $obj.HasLinkedGroupOIDPolicy = ($linkedGroups.Count -gt 0)

                Write-Verbose "  Template '$($obj.Name)': HasLinkedGroupOIDPolicy=$($obj.HasLinkedGroupOIDPolicy)"
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'SetLinkedGroupOIDPolicyFailed',
                    [System.Management.Automation.ErrorCategory]::NotSpecified,
                    $obj.distinguishedName
                )
                $PSCmdlet.WriteError($errorRecord)
            }

            $obj
        }
    }
}
