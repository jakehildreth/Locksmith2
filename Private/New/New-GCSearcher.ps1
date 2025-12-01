function New-GCSearcher {
    <#
        .SYNOPSIS
        Creates a configured DirectorySearcher for Global Catalog queries.

        .DESCRIPTION
        Factory function that creates a DirectorySearcher object configured for
        Global Catalog searches with standard settings (Subtree scope, PageSize 1000).
        This eliminates code duplication across conversion functions.

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
        $searcher = New-GCSearcher -Filter "(objectSid=$sidString)" -PropertiesToLoad @('distinguishedName', 'sAMAccountName')
        $result = $searcher.FindOne()

        .NOTES
        Requires $script:Server and $script:RootDSE to be initialized.
        SearchRoot is set using New-AuthenticatedDirectoryEntry with current credentials.
    #>
    
    #requires -Version 5.1
    
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectorySearcher])]
    param(
        [Parameter(Mandatory)]
        [string]$Filter,
        
        [Parameter(Mandatory)]
        [string[]]$PropertiesToLoad
    )
    
    begin {
        Write-Verbose "Creating Global Catalog searcher with filter: $Filter"
    }
    
    process {
        # Get root domain DN from RootDSE
        $rootDomainDN = if ($script:RootDSE) { 
            $script:RootDSE.rootDomainNamingContext.Value 
        } else { 
            $null 
        }
        
        if (-not $rootDomainDN) {
            Write-Warning "Unable to retrieve root domain DN from RootDSE"
            return $null
        }
        
        # Create searcher with GC path
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $gcPath = "GC://$script:Server/$rootDomainDN"
        
        Write-Verbose "GC search path: $gcPath"
        
        $searcher.SearchRoot = New-AuthenticatedDirectoryEntry -Path $gcPath
        $searcher.Filter = $Filter
        $searcher.PropertiesToLoad.AddRange($PropertiesToLoad) | Out-Null
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.PageSize = 1000
        
        return $searcher
    }
}
