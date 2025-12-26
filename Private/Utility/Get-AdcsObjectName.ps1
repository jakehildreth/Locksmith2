function Get-AdcsObjectName {
    <#
    .SYNOPSIS
        Gets a display name for an AD CS object using fallback resolution.

    .DESCRIPTION
        Extracts the best available name for an AD CS object by checking
        displayName, name, cn, and distinguishedName properties in order.
        This eliminates the repeated name resolution pattern across Set-* functions.

    .PARAMETER AdcsObject
        The AD CS object (DirectoryEntry or PSCustomObject) to get the name from.

    .EXAMPLE
        $name = Get-AdcsObjectName -AdcsObject $template
        Returns the display name, name, cn, or DN of the template.

    .EXAMPLE
        $templates | ForEach-Object { Get-AdcsObjectName -AdcsObject $_ }
        Gets names for all templates in a pipeline.

    .OUTPUTS
        [string] The resolved name of the AD CS object.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $AdcsObject
    )

    process {
        # Handle DirectoryEntry objects with Properties collection
        if ($AdcsObject.Properties) {
            if ($AdcsObject.Properties.displayName.Count -gt 0) {
                return $AdcsObject.Properties.displayName[0]
            }
            if ($AdcsObject.Properties.name.Count -gt 0) {
                return $AdcsObject.Properties.name[0]
            }
            if ($AdcsObject.Properties.cn.Count -gt 0) {
                return $AdcsObject.Properties.cn[0]
            }
            if ($AdcsObject.Properties.distinguishedName.Count -gt 0) {
                return $AdcsObject.Properties.distinguishedName[0]
            }
        }

        # Handle PSCustomObject or plain objects
        if ($AdcsObject.displayName) {
            return $AdcsObject.displayName
        }
        if ($AdcsObject.name) {
            return $AdcsObject.name
        }
        if ($AdcsObject.cn) {
            return $AdcsObject.cn
        }
        if ($AdcsObject.distinguishedName) {
            return $AdcsObject.distinguishedName
        }

        return 'Unknown Object'
    }
}
