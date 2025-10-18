function Get-AdcsObjects {
    <#
        .SYNOPSIS
        Retrieves all objects from the Public Key Services Container in the Active Directory Configuration partition.

        .DESCRIPTION
        This function queries the Active Directory Configuration partition to retrieve all objects from the
        Public Key Services Container (CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com).
        This container typically contains Certificate Authority objects, Certificate Templates, and other PKI-related objects.

        .PARAMETER Server
        The domain controller to query. If not specified, the function will use the default domain controller.

        .INPUTS
        None

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry
        Returns DirectoryEntry objects from the Public Key Services container via the pipeline.

        .EXAMPLE
        Get-AdcsObjects
        Retrieves all objects from the Public Key Services container using the default domain controller.

        .EXAMPLE
        Get-AdcsObjects -Server "dc01.contoso.com"
        Retrieves all objects from the Public Key Services container using the specified domain controller.

        .LINK
        https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server
    )

    #requires -Version 5.1 -Modules Microsoft.PowerShell.Security

    # Get the configuration naming context
    if ($Server) {
        $rootDSE = [ADSI]"LDAP://$Server/RootDSE"
        $Solution = 'Check the value provided for -Server.'
    } else {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $Server = 'localhost'
        $Solution = 'Provide a value for -Server.'
    }
    $configNC = $rootDSE.configurationNamingContext

    # Getting configNC fails silently, so we have to check this manually instead of a try/catch
    if ($null -eq $configNC){
        Write-Error "Could not connect to Active Directory forest: $Server. $Solution"
        return
    }

    try {
        # Build the LDAP search base for the Public Key Services container
        $searchBase = "CN=Public Key Services,CN=Services,$configNC"
        
        Write-Verbose "Searching: $searchBase"
        
        # Create DirectorySearcher for recursive search
        if ($Server) {
            $searcherDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$searchBase")
        } else {
            $searcherDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$searchBase")
        }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searcherDirectoryEntry)
        $searcher.Filter = "(objectClass=*)"  # Get all objects
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree  # Recursive search
        $searcher.PageSize = 1000  # Handle large result sets
        
        # Get all results
        $searchResults = $searcher.FindAll()
        
        # Convert paths into DirectoryEntry objects
        $objectCount = 0
        $searchResults | ForEach-Object {
            $objectDirectoryEntry = $_.GetDirectoryEntry()
            Write-Verbose "`nFound object: $($objectDirectoryEntry.distinguishedName)`nClass: $($objectDirectoryEntry.objectClass -join ', ')"
            $objectDirectoryEntry
            $objectCount++
        }
        Write-Verbose "Found $objectCount total objects in the Public Key Services container and its subtree"
        
        # Clean up
        $searcher.Dispose()
        $searcherDirectoryEntry.Dispose()
        $searchResults.Dispose()
    } catch {
        Write-Error "Failed to retrieve objects from Public Key Services container: $_"
    }
}