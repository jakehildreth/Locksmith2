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
    param ()

    #requires -Version 5.1 -Modules Microsoft.PowerShell.Security

    begin {
        # Initialize the AdcsObjectStore if it doesn't exist
        if (-not $script:AdcsObjectStore) {
            $script:AdcsObjectStore = @{}
        }
    }

    process {
        try {
            # Build the LDAP search base for the Public Key Services container
            $searchBase = "CN=Public Key Services,CN=Services,$($script:RootDSE.configurationNamingContext)"
            
            Write-Verbose "Searching $searchBase for AD CS objects."
            Write-Verbose "ADCS Object Store currently has $($script:AdcsObjectStore.Count) entries"
            
            # Create DirectorySearcher for recursive search
            $searcherDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
                "$($script:RootDSE.Parent)/$searchBase",
                $script:Credential.UserName,
                $script:Credential.GetNetworkCredential().Password
            )
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
                
                # Store the ADCS object if not already stored
                if (-not $script:AdcsObjectStore.ContainsKey($distinguishedName)) {
                    # Build store object with all properties
                    $adcsObj = [PSCustomObject]@{
                        distinguishedName = $distinguishedName
                        objectClass = if ($objectDirectoryEntry.objectClass) { @($objectDirectoryEntry.objectClass) } else { @() }
                        name = if ($objectDirectoryEntry.name) { $objectDirectoryEntry.name.Value } else { $null }
                        displayName = if ($objectDirectoryEntry.displayName) { $objectDirectoryEntry.displayName.Value } else { $null }
                        cn = if ($objectDirectoryEntry.cn) { $objectDirectoryEntry.cn.Value } else { $null }
                        
                        # Certificate Template specific properties
                        flags = if ($objectDirectoryEntry.Properties.Contains('flags')) { $objectDirectoryEntry.flags.Value } else { $null }
                        pKIDefaultKeySpec = if ($objectDirectoryEntry.Properties.Contains('pKIDefaultKeySpec')) { $objectDirectoryEntry.pKIDefaultKeySpec.Value } else { $null }
                        pKIMaxIssuingDepth = if ($objectDirectoryEntry.Properties.Contains('pKIMaxIssuingDepth')) { $objectDirectoryEntry.pKIMaxIssuingDepth.Value } else { $null }
                        pKICriticalExtensions = if ($objectDirectoryEntry.Properties.Contains('pKICriticalExtensions')) { @($objectDirectoryEntry.pKICriticalExtensions) } else { @() }
                        pKIExtendedKeyUsage = if ($objectDirectoryEntry.Properties.Contains('pKIExtendedKeyUsage')) { @($objectDirectoryEntry.pKIExtendedKeyUsage) } else { @() }
                        'msPKI-Certificate-Name-Flag' = if ($objectDirectoryEntry.Properties.Contains('msPKI-Certificate-Name-Flag')) { $objectDirectoryEntry.Properties['msPKI-Certificate-Name-Flag'][0] } else { $null }
                        'msPKI-Enrollment-Flag' = if ($objectDirectoryEntry.Properties.Contains('msPKI-Enrollment-Flag')) { $objectDirectoryEntry.Properties['msPKI-Enrollment-Flag'][0] } else { $null }
                        'msPKI-Private-Key-Flag' = if ($objectDirectoryEntry.Properties.Contains('msPKI-Private-Key-Flag')) { $objectDirectoryEntry.Properties['msPKI-Private-Key-Flag'][0] } else { $null }
                        'msPKI-RA-Signature' = if ($objectDirectoryEntry.Properties.Contains('msPKI-RA-Signature')) { $objectDirectoryEntry.Properties['msPKI-RA-Signature'][0] } else { $null }
                        'msPKI-Template-Schema-Version' = if ($objectDirectoryEntry.Properties.Contains('msPKI-Template-Schema-Version')) { $objectDirectoryEntry.Properties['msPKI-Template-Schema-Version'][0] } else { $null }
                        'msPKI-Template-Minor-Revision' = if ($objectDirectoryEntry.Properties.Contains('msPKI-Template-Minor-Revision')) { $objectDirectoryEntry.Properties['msPKI-Template-Minor-Revision'][0] } else { $null }
                        
                        # Security descriptor
                        ObjectSecurity = $objectDirectoryEntry.ObjectSecurity
                        
                        # Store the raw DirectoryEntry path for later retrieval if needed
                        Path = $objectDirectoryEntry.Path
                    }
                    
                    $script:AdcsObjectStore[$distinguishedName] = $adcsObj
                    $cachedCount++
                    Write-Verbose "Stored ADCS object: $distinguishedName"
                }
                
                $objectDirectoryEntry
                $objectCount++
            }
            Write-Verbose "Found $objectCount total objects in the Public Key Services container and its subtree"
            Write-Verbose "Stored $cachedCount new ADCS objects (Total store size: $($script:AdcsObjectStore.Count))"
            
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