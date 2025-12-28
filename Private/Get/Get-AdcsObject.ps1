function Get-AdcsObject {
    <#
        .SYNOPSIS
        Retrieves all objects from the Public Key Services Container in Active Directory.

        .DESCRIPTION
        Queries the Active Directory Configuration partition to retrieve all objects from the
        Public Key Services Container (CN=Public Key Services,CN=Services,CN=Configuration).
        This container contains Certificate Authority objects, Certificate Templates, and other 
        PKI-related objects used by Active Directory Certificate Services (AD CS).
        
        Uses module-level $script:Credential, $script:RootDSE, and $script:AdcsObjectStore
        variables set by Invoke-Locksmith2. The function performs a recursive LDAP search and
        returns LS2AdcsObject instances for all discovered PKI objects, including their
        properties and ACLs.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        LS2AdcsObject
        Returns LS2AdcsObject instances for all objects found in the Public Key Services 
        container and its subtree.

        .EXAMPLE
        Get-AdcsObject
        Retrieves all AD CS objects using script-scope credentials and root DSE.

        .EXAMPLE
        $templates = Get-AdcsObject | Where-Object { $_.IsCertificateTemplate() }
        Retrieves all certificate template objects from the PKI container.

        .NOTES
        Requires script-scope variables set by Invoke-Locksmith2:
        - $script:Credential: Credentials for AD access
        - $script:RootDSE: Forest configuration naming context
        - $script:AdcsObjectStore: Cache of retrieved objects

        .LINK
        https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/
    #>
    [CmdletBinding()]
    param ()

    #requires -Version 5.1 -Modules Microsoft.PowerShell.Security

    begin {
        # Initialize the AD CS Object Store if it doesn't exist
        if (-not $script:AdcsObjectStore) {
            $script:AdcsObjectStore = @{}
        }
    }

    process {
        try {
            # Build the LDAP search base for the Public Key Services container
            $searchBase = "CN=Public Key Services,CN=Services,$($script:RootDSE.configurationNamingContext)"
            
            Write-Verbose "Searching $searchBase for AD CS objects."
            Write-Verbose "AD CS Object Store currently has $($script:AdcsObjectStore.Count) entries"
            
            # Create DirectorySearcher for recursive search
            $searcherDirectoryEntry = New-AuthenticatedDirectoryEntry -Path "$($script:RootDSE.Parent)/$searchBase"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($searcherDirectoryEntry)
            $searcher.Filter = "(objectClass=*)"  # Get all objects
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree  # Recursive search
            $searcher.PageSize = 1000  # Handle large result sets
            
            # Get all results
            $searchResults = $searcher.FindAll()
            
            # Convert paths into DirectoryEntry objects and store them
            $objectCount = 0
            $cachedCount = 0
            $searchResults | ForEach-Object {
                $objectDirectoryEntry = $_.GetDirectoryEntry()
                $distinguishedName = $objectDirectoryEntry.distinguishedName.Value
                
                Write-Verbose "`nFound object: $distinguishedName`nClass: $($objectDirectoryEntry.objectClass -join ', ')"
                
                # Store the AD CS object if not already stored
                if (-not $script:AdcsObjectStore.ContainsKey($distinguishedName)) {
                    # Create LS2AdcsObject from DirectoryEntry
                    $adcsObject = [LS2AdcsObject]::new($objectDirectoryEntry)
                    
                    $script:AdcsObjectStore[$distinguishedName] = $adcsObject
                    $cachedCount++
                    Write-Verbose "Stored AD CS object: $distinguishedName"
                }
                
                $objectDirectoryEntry
                $objectCount++
            }
            Write-Verbose "Found $objectCount total objects in the Public Key Services container and its subtree"
            Write-Verbose "Stored $cachedCount new AD CS objects (Total store size: $($script:AdcsObjectStore.Count))"
            
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
}