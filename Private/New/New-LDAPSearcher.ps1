function New-LDAPSearcher {
    <#
        .SYNOPSIS
        Creates a configured DirectorySearcher for LDAP queries.

        .DESCRIPTION
        Factory function that creates a DirectorySearcher object configured for
        LDAP searches with standard settings (Subtree scope, PageSize 1000).
        This eliminates code duplication across conversion functions.
        
        Uses module-level $script:Credential and $script:Forest variables set by
        Invoke-Locksmith2 to establish authenticated connections via
        New-AuthenticatedDirectoryEntry.

        .PARAMETER DomainDN
        The distinguished name of the domain to search (e.g., "DC=contoso,DC=com").

        .PARAMETER Filter
        The LDAP filter string for the search (e.g., "(objectSid=S-1-5-21-...)").

        .PARAMETER PropertiesToLoad
        Array of property names to load from matching objects.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        System.DirectoryServices.DirectorySearcher
        Configured searcher ready for FindOne() or FindAll() operations.

        .EXAMPLE
        $searcher = New-LDAPSearcher -DomainDN "DC=contoso,DC=com" -Filter "(sAMAccountName=jdoe)" -PropertiesToLoad @('distinguishedName', 'objectSid')
        $result = $searcher.FindOne()

        .NOTES
        Requires $script:Server to be initialized.
        SearchRoot is set using New-AuthenticatedDirectoryEntry with current credentials.
    #>
    
    #requires -Version 5.1
    
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectorySearcher])]
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN,
        
        [Parameter(Mandatory)]
        [string]$Filter,
        
        [Parameter(Mandatory)]
        [string[]]$PropertiesToLoad
    )
    
    begin {
        Write-Verbose "Creating LDAP searcher for domain: $DomainDN with filter: $Filter"
    }
    
    process {
        # Create searcher with LDAP path
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $ldapPath = "LDAP://$script:Server/$DomainDN"
        
        Write-Verbose "LDAP search path: $ldapPath"
        
        $searcher.SearchRoot = New-AuthenticatedDirectoryEntry -Path $ldapPath
        $searcher.Filter = $Filter
        $searcher.PropertiesToLoad.AddRange($PropertiesToLoad) | Out-Null
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.PageSize = 1000
        
        return $searcher
    }
}
