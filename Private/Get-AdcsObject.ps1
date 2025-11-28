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
        # Initialize ADCS Object Cache if it doesn't exist
        if (-not $script:AdcsObjectCache) {
            $script:AdcsObjectCache = @{}
        }
    }

    process {
        try {
            # Build the LDAP search base for the Public Key Services container
            $searchBase = "CN=Public Key Services,CN=Services,$($script:RootDSE.configurationNamingContext)"
            
            Write-Verbose "Searching $searchBase for AD CS objects."
            Write-Verbose "ADCS Object Cache currently has $($script:AdcsObjectCache.Count) entries"
            
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
            
            # Convert paths into DirectoryEntry objects and cache them
            $objectCount = 0
            $cachedCount = 0
            $searchResults | ForEach-Object {
                $objectDirectoryEntry = $_.GetDirectoryEntry()
                $distinguishedName = $objectDirectoryEntry.distinguishedName.Value
                
                Write-Verbose "`nFound object: $distinguishedName`nClass: $($objectDirectoryEntry.objectClass -join ', ')"
                
                # Cache the ADCS object if not already cached
                if (-not $script:AdcsObjectCache.ContainsKey($distinguishedName)) {
                    # Build cache object with all properties
                    $adcsObj = [PSCustomObject]@{
                        DistinguishedName = $distinguishedName
                        ObjectClass = if ($objectDirectoryEntry.objectClass) { @($objectDirectoryEntry.objectClass) } else { @() }
                        Name = if ($objectDirectoryEntry.name) { $objectDirectoryEntry.name.Value } else { $null }
                        DisplayName = if ($objectDirectoryEntry.displayName) { $objectDirectoryEntry.displayName.Value } else { $null }
                        CN = if ($objectDirectoryEntry.cn) { $objectDirectoryEntry.cn.Value } else { $null }
                        
                        # Certificate Template specific properties
                        Flags = if ($objectDirectoryEntry.Properties.Contains('flags')) { $objectDirectoryEntry.flags.Value } else { $null }
                        PKIDefaultKeySpec = if ($objectDirectoryEntry.Properties.Contains('pKIDefaultKeySpec')) { $objectDirectoryEntry.pKIDefaultKeySpec.Value } else { $null }
                        PKIMaxIssuingDepth = if ($objectDirectoryEntry.Properties.Contains('pKIMaxIssuingDepth')) { $objectDirectoryEntry.pKIMaxIssuingDepth.Value } else { $null }
                        PKICriticalExtensions = if ($objectDirectoryEntry.Properties.Contains('pKICriticalExtensions')) { @($objectDirectoryEntry.pKICriticalExtensions) } else { @() }
                        PKIExtendedKeyUsage = if ($objectDirectoryEntry.Properties.Contains('pKIExtendedKeyUsage')) { @($objectDirectoryEntry.pKIExtendedKeyUsage) } else { @() }
                        MSPKICertificateNameFlag = if ($objectDirectoryEntry.Properties.Contains('msPKI-Certificate-Name-Flag')) { $objectDirectoryEntry.Properties['msPKI-Certificate-Name-Flag'][0] } else { $null }
                        MSPKIEnrollmentFlag = if ($objectDirectoryEntry.Properties.Contains('msPKI-Enrollment-Flag')) { $objectDirectoryEntry.Properties['msPKI-Enrollment-Flag'][0] } else { $null }
                        MSPKIPrivateKeyFlag = if ($objectDirectoryEntry.Properties.Contains('msPKI-Private-Key-Flag')) { $objectDirectoryEntry.Properties['msPKI-Private-Key-Flag'][0] } else { $null }
                        MSPKIRASignature = if ($objectDirectoryEntry.Properties.Contains('msPKI-RA-Signature')) { $objectDirectoryEntry.Properties['msPKI-RA-Signature'][0] } else { $null }
                        MSPKITemplateSchemaVersion = if ($objectDirectoryEntry.Properties.Contains('msPKI-Template-Schema-Version')) { $objectDirectoryEntry.Properties['msPKI-Template-Schema-Version'][0] } else { $null }
                        MSPKITemplateMinorRevision = if ($objectDirectoryEntry.Properties.Contains('msPKI-Template-Minor-Revision')) { $objectDirectoryEntry.Properties['msPKI-Template-Minor-Revision'][0] } else { $null }
                        
                        # Security descriptor
                        ObjectSecurity = $objectDirectoryEntry.ObjectSecurity
                        
                        # Store the raw DirectoryEntry path for later retrieval if needed
                        Path = $objectDirectoryEntry.Path
                    }
                    
                    $script:AdcsObjectCache[$distinguishedName] = $adcsObj
                    $cachedCount++
                    Write-Verbose "Cached ADCS object: $distinguishedName"
                }
                
                $objectDirectoryEntry
                $objectCount++
            }
            Write-Verbose "Found $objectCount total objects in the Public Key Services container and its subtree"
            Write-Verbose "Cached $cachedCount new ADCS objects (Total cache size: $($script:AdcsObjectCache.Count))"
            
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