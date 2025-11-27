function Convert-IdentityReferenceToDirectoryEntry {
    <#
        .SYNOPSIS
        Converts an IdentityReference (NTAccount or SecurityIdentifier) to a DirectoryEntry.

        .DESCRIPTION
        Takes a System.Security.Principal.IdentityReference object (either NTAccount or SecurityIdentifier) 
        and performs an LDAP query to return the corresponding DirectoryEntry object.
        
        On domain-joined computers, uses the built-in Translate() method. On non-domain joined computers,
        performs an LDAP query using provided credentials to resolve the SID to an NTAccount.
        
        Supports forest-wide searches using Global Catalog when RootDSE is provided, enabling resolution
        of principals from child domains and trusted domains within the forest.

        .PARAMETER IdentityReference
        The IdentityReference object to convert. Can be either NTAccount or SecurityIdentifier.

        .PARAMETER Credential
        PSCredential for authenticating to Active Directory. Required for LDAP queries.

        .PARAMETER RootDSE
        A DirectoryEntry object for the RootDSE. Used to determine the domain context for LDAP queries.
        If not specified, attempts to query without specific domain context.

        .INPUTS
        System.Security.Principal.IdentityReference
        Accepts IdentityReference objects (NTAccount or SecurityIdentifier) via the pipeline.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry
        Returns the DirectoryEntry object for the principal with the specified SID.

        .EXAMPLE
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-...')
        $sid | Convert-IdentityReferenceToDirectoryEntry -Credential $cred -RootDSE $rootDSE
        Converts a SID to DirectoryEntry using credentials and RootDSE.

        .EXAMPLE
        $ntAccount = [System.Security.Principal.NTAccount]::new('DOMAIN\User')
        $ntAccount | Convert-IdentityReferenceToDirectoryEntry -Credential $cred -RootDSE $rootDSE
        Converts an NTAccount to DirectoryEntry.

        .EXAMPLE
        $ace.IdentityReference | Convert-IdentityReferenceToDirectoryEntry -Credential $cred -RootDSE $rootDSE
        Converts IdentityReferences from an ACL to DirectoryEntry objects.

        .NOTES
        Requires Credential and RootDSE parameters for LDAP queries.
        Uses Global Catalog for forest-wide searches to support child domain resolution.
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Security.Principal.IdentityReference]
        $IdentityReference,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]
        $RootDSE
    )

    begin {
        # Cache NetBIOS name lookups to avoid repeated queries
        $script:netBiosCache = @{}
        
        # Pre-load all NetBIOS names if we have credentials
        if ($Credential -and $RootDSE) {
            try {
                $configNC = $RootDSE.configurationNamingContext.Value
                if ($RootDSE.Path -match 'LDAP://([^/]+)') {
                    $server = $Matches[1]
                    $partitionsPath = "LDAP://$server/CN=Partitions,$configNC"
                    
                    $partitionsEntry = New-Object System.DirectoryServices.DirectoryEntry(
                        $partitionsPath,
                        $Credential.UserName,
                        $Credential.GetNetworkCredential().Password
                    )
                    
                    $partitionsSearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $partitionsSearcher.SearchRoot = $partitionsEntry
                    $partitionsSearcher.Filter = "(objectClass=crossRef)"
                    $partitionsSearcher.PropertiesToLoad.AddRange(@('nCName', 'nETBIOSName')) | Out-Null
                    $partitionsSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
                    
                    $allPartitions = $partitionsSearcher.FindAll()
                    foreach ($partition in $allPartitions) {
                        if ($partition.Properties['nCName'].Count -gt 0 -and $partition.Properties['nETBIOSName'].Count -gt 0) {
                            $domainDN = $partition.Properties['nCName'][0]
                            $netBiosName = $partition.Properties['nETBIOSName'][0]
                            $script:netBiosCache[$domainDN] = $netBiosName
                            Write-Verbose "Pre-cached NetBIOS name '$netBiosName' for '$domainDN'"
                        }
                    }
                    
                    $allPartitions.Dispose()
                    $partitionsSearcher.Dispose()
                    $partitionsEntry.Dispose()
                }
            } catch {
                Write-Verbose "Could not pre-load NetBIOS names: $_"
            }
        }
    }

    process {
        # Convert NTAccount to SecurityIdentifier if needed
        if ($IdentityReference -is [System.Security.Principal.NTAccount]) {
            Write-Verbose "Converting NTAccount '$IdentityReference' to SID"
            try {
                $sid = $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
            } catch {
                Write-Verbose "Built-in Translate() failed, attempting LDAP lookup for NTAccount"
                
                # Parse the NTAccount string
                $accountString = $IdentityReference.Value
                if ($accountString -match '^(.+?)\\(.+)$') {
                    $domain = $Matches[1]
                    $samAccountName = $Matches[2]
                } elseif ($accountString -match '@') {
                    # UPN format
                    $samAccountName = $accountString.Split('@')[0]
                    $domain = $null
                } else {
                    $samAccountName = $accountString
                    $domain = $null
                }
                
                # Extract server from RootDSE
                if ($RootDSE.Path -match 'LDAP://([^/]+)') {
                    $server = $Matches[1]
                } else {
                    Write-Warning "Could not extract server from RootDSE path."
                    return $null
                }
                
                $rootDomainDN = $RootDSE.rootDomainNamingContext.Value
                
                # Try Global Catalog search for the account
                Write-Verbose "Attempting Global Catalog search for NTAccount '$samAccountName'"
                $gcSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $gcPath = "GC://$server/$rootDomainDN"
                
                $gcEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    $gcPath,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
                
                $gcSearcher.SearchRoot = $gcEntry
                $gcSearcher.Filter = "(sAMAccountName=$samAccountName)"
                $gcSearcher.PropertiesToLoad.AddRange(@('distinguishedName')) | Out-Null
                $gcSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $gcSearcher.PageSize = 1000
                
                try {
                    $gcResult = $gcSearcher.FindOne()
                    
                    if ($gcResult) {
                        $distinguishedName = $gcResult.Properties['distinguishedName'][0]
                        Write-Verbose "Found NTAccount in GC at: $distinguishedName"
                        
                        # Return DirectoryEntry for the found object
                        $objectPath = "LDAP://$server/$distinguishedName"
                        $objectEntry = New-Object System.DirectoryServices.DirectoryEntry(
                            $objectPath,
                            $Credential.UserName,
                            $Credential.GetNetworkCredential().Password
                        )
                        
                        Write-Verbose "Resolved NTAccount '$accountString' to '$distinguishedName' via Global Catalog"
                        return $objectEntry
                    } else {
                        Write-Warning "Could not find NTAccount '$accountString' in Active Directory."
                        return $null
                    }
                } finally {
                    if ($gcSearcher) { $gcSearcher.Dispose() }
                    if ($gcEntry) { $gcEntry.Dispose() }
                }
            }
        } else {
            $sid = $IdentityReference
        }

        try {
            # Get the SID string
            $sidString = $sid.Value

            # Extract server from RootDSE
            if ($RootDSE) {
                $rootDomainDN = $RootDSE.rootDomainNamingContext.Value
                if ($RootDSE.Path -match 'LDAP://([^/]+)') {
                    $server = $Matches[1]
                } else {
                    Write-Warning "Could not extract server from RootDSE path."
                    return $null
                }
            } else {
                Write-Warning "RootDSE parameter required for SID resolution."
                return $null
            }

            # First try Global Catalog search for forest-wide lookup
            if ($rootDomainDN) {
                Write-Verbose "Attempting Global Catalog search for SID '$sidString'"
                $gcSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $gcPath = "GC://$server/$rootDomainDN"
                
                $gcEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    $gcPath,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
                
                $gcSearcher.SearchRoot = $gcEntry
                $gcSearcher.Filter = "(objectSid=$sidString)"
                $gcSearcher.PropertiesToLoad.AddRange(@('distinguishedName')) | Out-Null
                $gcSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $gcSearcher.PageSize = 1000

                try {
                    $gcResult = $gcSearcher.FindOne()
                    
                    if ($gcResult) {
                        $distinguishedName = $gcResult.Properties['distinguishedName'][0]
                        Write-Verbose "Found SID in GC at: $distinguishedName"
                        
                        # Return DirectoryEntry for the found object
                        $objectPath = "LDAP://$server/$distinguishedName"
                        $objectEntry = New-Object System.DirectoryServices.DirectoryEntry(
                            $objectPath,
                            $Credential.UserName,
                            $Credential.GetNetworkCredential().Password
                        )
                        
                        Write-Verbose "Resolved SID '$sidString' to '$distinguishedName' via Global Catalog"
                        return $objectEntry
                    }
                } catch {
                    Write-Verbose "Global Catalog search failed, falling back to domain search: $_"
                } finally {
                    if ($gcSearcher) { $gcSearcher.Dispose() }
                    if ($gcEntry) { $gcEntry.Dispose() }
                }
            }

            # Fallback to direct LDAP search in default domain
            Write-Verbose "Attempting direct LDAP search for SID '$sidString'"
            $domainDN = if ($RootDSE) { $RootDSE.defaultNamingContext.Value } else { $null }
            
            if (-not $domainDN) {
                Write-Warning "Could not determine domain DN for SID resolution."
                return $null
            }
            
            # Create LDAP searcher with credentials
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $ldapPath = "LDAP://$server/$domainDN"
            
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath,
                $Credential.UserName,
                $Credential.GetNetworkCredential().Password
            )
            
            $searcher.SearchRoot = $directoryEntry
            $searcher.Filter = "(objectSid=$sidString)"
            $searcher.PropertiesToLoad.AddRange(@('distinguishedName')) | Out-Null
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.PageSize = 1000

            $result = $searcher.FindOne()

            if ($result) {
                $distinguishedName = $result.Properties['distinguishedName'][0]
                
                # Return DirectoryEntry for the found object
                $objectPath = "LDAP://$server/$distinguishedName"
                $objectEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    $objectPath,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
                
                Write-Verbose "Resolved SID '$sidString' to '$distinguishedName' via LDAP"
                return $objectEntry
            } else {
                Write-Warning "Could not find SID '$sidString' in Active Directory via LDAP query."
                return $null
            }
        } catch {
            Write-Warning "LDAP query failed for SID '$sidString': $_"
            return $null
        } finally {
            if ($searcher) { $searcher.Dispose() }
            if ($directoryEntry) { $directoryEntry.Dispose() }
        }
    }
}
