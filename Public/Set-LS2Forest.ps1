function Set-LS2Forest {
    <#
        .SYNOPSIS
        Sets the script-scope Forest variable for Locksmith2.

        .DESCRIPTION
        Prompts for or sets the fully qualified domain controller, domain, or forest name
        that will be used for all LDAP/GC queries during the Locksmith2 scan. Stores the
        value in $script:Forest.

        .PARAMETER Forest
        The fully qualified domain controller, domain, or forest name to use for the scan.
        If not provided, the user will be prompted to enter a value.

        .INPUTS
        None

        .OUTPUTS
        None
        Sets the module-level $script:Forest variable.

        .EXAMPLE
        Set-LS2Forest -Forest 'contoso.com'
        Sets the forest to contoso.com without prompting.

        .EXAMPLE
        Set-LS2Forest
        Prompts the user to enter the forest name.

        .NOTES
        This function should be called before Initialize-DomainStore or any AD queries.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Forest
    )

    #requires -Version 5.1

    if (-not $Forest) {
        $script:Forest = Read-Host 'Enter fully qualified domain controller/domain/forest name'
    } else {
        $script:Forest = $Forest
    }

    Write-Verbose "Forest set to: $($script:Forest)"
}
