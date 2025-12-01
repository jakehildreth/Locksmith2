function New-AuthenticatedDirectoryEntry {
    <#
        .SYNOPSIS
        Creates an authenticated DirectoryEntry object using module credentials.

        .DESCRIPTION
        Helper function that creates a System.DirectoryServices.DirectoryEntry object
        authenticated with the module-level credentials ($script:Credential). This eliminates
        duplication of the credential extraction pattern throughout the codebase.

        .PARAMETER Path
        The LDAP or GC path for the DirectoryEntry (e.g., "LDAP://server/DN" or "GC://server/DN").

        .INPUTS
        None

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry
        Returns an authenticated DirectoryEntry object.

        .EXAMPLE
        $entry = New-AuthenticatedDirectoryEntry -Path "LDAP://dc.domain.com/DC=domain,DC=com"
        Creates an authenticated DirectoryEntry for the specified path.

        .EXAMPLE
        $gcEntry = New-AuthenticatedDirectoryEntry -Path "GC://dc.domain.com/DC=domain,DC=com"
        Creates an authenticated Global Catalog DirectoryEntry.

        .NOTES
        Requires $script:Credential to be set before calling.
        The caller is responsible for disposing the returned DirectoryEntry object.
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param(
        [Parameter(Mandatory)]
        [string]
        $Path
    )

    return New-Object System.DirectoryServices.DirectoryEntry(
        $Path,
        $script:Credential.UserName,
        $script:Credential.GetNetworkCredential().Password
    )
}
