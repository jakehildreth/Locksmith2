function Get-AdcsObject {
    <#
        .SYNOPSIS
        Retrieves all objects from the Public Key Services Container in Active Directory.

        .DESCRIPTION
        Queries the Active Directory Configuration partition to retrieve all objects from the
        Public Key Services Container (CN=Public Key Services,CN=Services,CN=Configuration).
        This container contains Certificate Authority objects, Certificate Templates, and other 
        PKI-related objects used by Active Directory Certificate Services (AD CS).
        
        The function performs a recursive LDAP search and returns DirectoryEntry objects for 
        all discovered PKI objects, including their properties and ACLs.

        .PARAMETER RootDSE
        A DirectoryEntry object for the RootDSE. Used to determine the configuration naming 
        context for LDAP queries. This parameter is mandatory.

        .PARAMETER Credential
        PSCredential for authenticating to Active Directory. Used to create authenticated 
        LDAP connections to the directory service.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry
        Returns DirectoryEntry objects for all objects found in the Public Key Services 
        container and its subtree.

        .EXAMPLE
        $rootDSE = Get-RootDSE -Forest 'contoso.com' -Credential $cred
        Get-AdcsObject -RootDSE $rootDSE -Credential $cred
        Retrieves all AD CS objects using the specified forest and credentials.

        .EXAMPLE
        $rootDSE = Get-RootDSE
        $templates = Get-AdcsObject -RootDSE $rootDSE -Credential $cred | 
            Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        Retrieves only certificate template objects from the PKI container.

        .LINK
        https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $RootDSE,
        [System.Management.Automation.PSCredential]$Credential
    )

    #requires -Version 5.1 -Modules Microsoft.PowerShell.Security

    try {
        # Build the LDAP search base for the Public Key Services container
        $searchBase = "CN=Public Key Services,CN=Services,$($RootDSE.configurationNamingContext)"
        
        Write-Verbose "Searching $searchBase for AD CS objects."
        
        # Create DirectorySearcher for recursive search
        $searcherDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
            "$($RootDSE.Parent)/$searchBase",
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
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
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'ADCSObjectRetrievalFailed',
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $searchBase
        )
        $PSCmdlet.WriteError($errorRecord)
    }
}