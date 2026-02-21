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
        # Handle LS2AdcsObject with GetFriendlyName() method
        if ($AdcsObject -is [LS2AdcsObject]) {
            return $AdcsObject.GetFriendlyName()
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
