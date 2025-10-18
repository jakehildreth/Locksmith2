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
        System.DirectoryServices.DirectoryEntry[]
        Returns an array of DirectoryEntry objects from the Public Key Services container.

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

    #requires -Version 7.4 -Modules Microsoft.PowerShell.Security

    begin {
        # Get the configuration naming context
        try {
            if ($Server) {
                $rootDSE = [ADSI]"LDAP://$Server/RootDSE"
            } else {
                $rootDSE = [ADSI]"LDAP://RootDSE"
            }
            $configNC = $rootDSE.configurationNamingContext
            Write-Verbose "Configuration Naming Context: $configNC"
        }
        catch {
            Write-Error "Failed to connect to Active Directory: $_"
        }
    }

    process {
        try {
            # Build the LDAP search base for the Public Key Services container
            $searchBase = "CN=Public Key Services,CN=Services,$configNC"
            
            Write-Verbose "Searching base: $searchBase"
            
            # Create DirectorySearcher for recursive search
            if ($Server) {
                $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$searchBase")
            } else {
                $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$searchBase")
            }
            
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
            $searcher.Filter = "(objectClass=*)"  # Get all objects
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree  # Recursive search
            $searcher.PageSize = 1000  # Handle large result sets
            
            # Get all results
            $searchResults = $searcher.FindAll()
            $objects = @()
            
            foreach ($result in $searchResults) {
                $obj = $result.GetDirectoryEntry()
                $objects += $obj
                Write-Verbose "Found object: $($obj.distinguishedName) (Class: $($obj.objectClass -join ', '))"
            }
            
            Write-Verbose "Found $($objects.Count) total objects in the Public Key Services container and its subtree"
            
            # Clean up
            $searcher.Dispose()
            $directoryEntry.Dispose()
            $searchResults.Dispose()
            
            return $objects
        }
        catch {
            Write-Error "Failed to retrieve objects from Public Key Services container: $_"
        }
    }

    end {
    }
}