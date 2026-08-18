function Set-IsCATemplate {
    <#
        .SYNOPSIS
        Adds the IsCATemplate property to AD CS certificate template objects.

        .DESCRIPTION
        Examines the pKIDefaultKeySpec attribute of certificate template objects to
        determine whether a template is CA-shaped (intended to issue CA certificates).

        A template is considered CA-shaped when pKIDefaultKeySpec -eq 2 (AT_SIGNATURE),
        which is the key specification used for CA signing keys. End-entity templates
        use pKIDefaultKeySpec -eq 1 (AT_KEYEXCHANGE) or leave the attribute unset.

        This distinction matters for remediation guidance: superseding a schema v1
        end-entity template is routine, but supersession has not been observed to
        work reliably for CA templates in live environments.

        .PARAMETER AdcsObject
        One or more LS2AdcsObject objects representing AD CS objects.

        .INPUTS
        LS2AdcsObject objects.

        .OUTPUTS
        LS2AdcsObject objects with the IsCATemplate property set.

        .EXAMPLE
        $templates | Set-IsCATemplate
        Sets IsCATemplate on all certificate template objects.

        .NOTES
        pKIDefaultKeySpec values:
          1 = AT_KEYEXCHANGE (end-entity)
          2 = AT_SIGNATURE   (CA-shaped)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [LS2AdcsObject[]]$AdcsObject
    )

    process {
        $AdcsObject | Where-Object SchemaClassName -EQ 'pKICertificateTemplate' | ForEach-Object {
            $_.IsCATemplate = ($_.pKIDefaultKeySpec -eq 2)
            Write-Verbose "Template '$($_.cn)': IsCATemplate = $($_.IsCATemplate)"
            $_
        }
    }
}
