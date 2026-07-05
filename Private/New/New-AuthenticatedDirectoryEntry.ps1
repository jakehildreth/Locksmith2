function New-AuthenticatedDirectoryEntry {
    <#
        .SYNOPSIS
        Creates an authenticated DirectoryEntry object using module credentials.

        .DESCRIPTION
        Helper function that creates a System.DirectoryServices.DirectoryEntry object
        authenticated with the module-level credentials ($script:Credential) or an
        explicitly supplied credential. This eliminates duplication of the credential
        extraction pattern throughout the codebase.

        .PARAMETER Path
        The LDAP or GC path for the DirectoryEntry (e.g., "LDAP://server/DN" or "GC://server/DN").

        .PARAMETER Credential
        Optional PSCredential to use for authentication. When omitted, the function
        falls back to $script:Credential, and if that is also unset, uses the current
        Windows identity.

        .INPUTS
        None

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry
        Returns an authenticated DirectoryEntry object.

        .EXAMPLE
        $entry = New-AuthenticatedDirectoryEntry -Path "LDAP://dc.domain.com/DC=domain,DC=com"
        Creates an authenticated DirectoryEntry for the specified path using
        $script:Credential or the current Windows identity.

        .EXAMPLE
        $gcEntry = New-AuthenticatedDirectoryEntry -Path "GC://dc.domain.com/DC=domain,DC=com"
        Creates an authenticated Global Catalog DirectoryEntry.

        .EXAMPLE
        $cred = Get-Credential
        $entry = New-AuthenticatedDirectoryEntry -Path "LDAP://dc.domain.com/DC=domain,DC=com" -Credential $cred
        Creates an authenticated DirectoryEntry using the supplied credential.

        .NOTES
        The caller is responsible for disposing the returned DirectoryEntry object.
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param(
        [Parameter(Mandatory)]
        [string]
        $Path,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    $effectiveCredential = if ($Credential) { $Credential } elseif ($script:Credential) { $script:Credential } else { $null }

    if ($effectiveCredential) {
        return New-Object System.DirectoryServices.DirectoryEntry(
            $Path,
            $effectiveCredential.UserName,
            $effectiveCredential.GetNetworkCredential().Password
        )
    } else {
        return New-Object System.DirectoryServices.DirectoryEntry($Path)
    }
}
