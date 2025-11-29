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
        $IdentityReference
    )

    begin {
        # Initialize Principal Store if it doesn't exist
        # Store for IdentityReference → Full principal object with all properties
        if (-not $script:PrincipalStore) {
            $script:PrincipalStore = @{}
        }
        
        # Initialize Domain Store if it doesn't exist
        # Store for Domain DN → Full domain object with all properties
        if (-not $script:DomainStore) {
            $script:DomainStore = @{}
        }
        
        # Pre-load all domains into Domain Store if we have credentials
        if ($script:Credential -and $script:RootDSE) {
            try {
                $configNC = $script:RootDSE.configurationNamingContext.Value
                if ($script:RootDSE.Path -match 'LDAP://([^/]+)') {
                    $server = $Matches[1]
                    $partitionsPath = "LDAP://$server/CN=Partitions,$configNC"
                    
                    $partitionsEntry = New-Object System.DirectoryServices.DirectoryEntry(
                        $partitionsPath,
                        $script:Credential.UserName,
                        $script:Credential.GetNetworkCredential().Password
                    )
                    
                    $partitionsSearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $partitionsSearcher.SearchRoot = $partitionsEntry
                    $partitionsSearcher.Filter = "(objectClass=crossRef)"
                    $partitionsSearcher.PropertiesToLoad.AddRange(@('nCName', 'nETBIOSName', 'dnsRoot')) | Out-Null
                    $partitionsSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
                    
                    $allPartitions = $partitionsSearcher.FindAll()
                    foreach ($partition in $allPartitions) {
                        if ($partition.Properties['nCName'].Count -gt 0) {
                            $domainDN = $partition.Properties['nCName'][0]
                            
                            # Create domain store entry with all properties
                            if (-not $script:DomainStore.ContainsKey($domainDN)) {
                                $domainObject = [PSCustomObject]@{
                                    distinguishedName = $domainDN
                                    nETBIOSName = if ($partition.Properties['nETBIOSName'].Count -gt 0) { $partition.Properties['nETBIOSName'][0] } else { $null }
                                    dnsRoot = if ($partition.Properties['dnsRoot'].Count -gt 0) { $partition.Properties['dnsRoot'][0] } else { $null }
                                }
                                
                                $script:DomainStore[$domainDN] = $domainObject
                                Write-Verbose "Stored domain: $domainDN (NetBIOS: $($domainObject.nETBIOSName))"
                            }
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
        # Check store first - use IdentityReference.Value as store key
        $storeKey = $IdentityReference.Value
        if ($script:PrincipalStore.ContainsKey($storeKey)) {
            $storedPrincipal = $script:PrincipalStore[$storeKey]
            Write-Verbose "Store HIT: Found stored principal for '$storeKey': $($storedPrincipal.distinguishedName)"
            
            # Extract server from RootDSE
            if ($script:RootDSE.Path -match 'LDAP://([^/]+)') {
                $server = $Matches[1]
            } else {
                Write-Warning "Could not extract server from RootDSE path."
                return $null
            }
            
            # Create fresh DirectoryEntry from stored DN
            $objectPath = "LDAP://$server/$($storedPrincipal.distinguishedName)"
            $objectEntry = New-Object System.DirectoryServices.DirectoryEntry(
                $objectPath,
                $script:Credential.UserName,
                $script:Credential.GetNetworkCredential().Password
            )
            
            return $objectEntry
        }
        
        Write-Verbose "Store MISS: No stored DN found for '$storeKey', performing LDAP lookup"
        
        # Convert NTAccount to SecurityIdentifier if needed
        if ($IdentityReference -is [System.Security.Principal.NTAccount]) {
            Write-Verbose "Converting NTAccount '$IdentityReference' to SID"
            try {
                $sid = $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
            } catch {
                Write-Verbose "Built-in Translate() failed, attempting LDAP lookup for NTAccount"
                
                # Parse the NTAccount string
                $accountString = $IdentityReference.Value
                # if ($accountString -match '^(.+?)\\(.+)$') {
                #     $domain = $Matches[1]
                #     $samAccountName = $Matches[2]
                # } elseif ($accountString -match '@') {
                #     # UPN format
                #     $samAccountName = $accountString.Split('@')[0]
                #     $domain = $null
                # } else {
                #     $samAccountName = $accountString
                #     $domain = $null
                # }
                
                # Extract server from RootDSE
                if ($script:RootDSE.Path -match 'LDAP://([^/]+)') {
                    $server = $Matches[1]
                } else {
                    Write-Warning "Could not extract server from RootDSE path."
                    return $null
                }
                
                $rootDomainDN = $script:RootDSE.rootDomainNamingContext.Value
                
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
                # Load all principal properties for complete store object
                $gcSearcher.PropertiesToLoad.AddRange(@('distinguishedName', 'objectSid', 'sAMAccountName', 'objectClass', 'displayName', 'memberOf', 'userPrincipalName')) | Out-Null
                $gcSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $gcSearcher.PageSize = 1000
                
                try {
                    $gcResult = $gcSearcher.FindOne()
                    
                    if ($gcResult) {
                        $distinguishedName = $gcResult.Properties['distinguishedName'][0]
                        Write-Verbose "Found NTAccount in GC at: $distinguishedName"
                        
                        # Build complete principal object for store
                        # Create DirectoryEntry to get ObjectSecurity
                        $objectPath = "LDAP://$server/$distinguishedName"
                        $tempEntry = New-Object System.DirectoryServices.DirectoryEntry(
                            $objectPath,
                            $script:Credential.UserName,
                            $script:Credential.GetNetworkCredential().Password
                        )
                        
                        $principalObject = [PSCustomObject]@{
                            DistinguishedName = $distinguishedName
                            ObjectSid = if ($gcResult.Properties['objectSid'].Count -gt 0) { 
                                (New-Object System.Security.Principal.SecurityIdentifier($gcResult.Properties['objectSid'][0], 0)).Value 
                            } else { $null }
                            SamAccountName = if ($gcResult.Properties['sAMAccountName'].Count -gt 0) { $gcResult.Properties['sAMAccountName'][0] } else { $null }
                            ObjectClass = if ($gcResult.Properties['objectClass'].Count -gt 0) { $gcResult.Properties['objectClass'][-1] } else { $null }
                            DisplayName = if ($gcResult.Properties['displayName'].Count -gt 0) { $gcResult.Properties['displayName'][0] } else { $null }
                            UserPrincipalName = if ($gcResult.Properties['userPrincipalName'].Count -gt 0) { $gcResult.Properties['userPrincipalName'][0] } else { $null }
                            MemberOf = if ($gcResult.Properties['memberOf'].Count -gt 0) { @($gcResult.Properties['memberOf']) } else { @() }
                            ObjectSecurity = $tempEntry.ObjectSecurity
                        }
                        
                        $tempEntry.Dispose()
                        
                        # Store the complete principal object
                        $script:PrincipalStore[$storeKey] = $principalObject
                        Write-Verbose "Stored principal object for '$storeKey': $distinguishedName (ObjectClass: $($principalObject.ObjectClass))"
                        
                        # Return DirectoryEntry for the found object
                        $objectPath = "LDAP://$server/$distinguishedName"
                        $objectEntry = New-Object System.DirectoryServices.DirectoryEntry(
                            $objectPath,
                            $script:Credential.UserName,
                            $script:Credential.GetNetworkCredential().Password
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
            if ($script:RootDSE) {
                $rootDomainDN = $script:RootDSE.rootDomainNamingContext.Value
                if ($script:RootDSE.Path -match 'LDAP://([^/]+)') {
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
                    $script:Credential.UserName,
                    $script:Credential.GetNetworkCredential().Password
                )
                
                $gcSearcher.SearchRoot = $gcEntry
                $gcSearcher.Filter = "(objectSid=$sidString)"
                # Load all principal properties for complete store object
                $gcSearcher.PropertiesToLoad.AddRange(@('distinguishedName', 'objectSid', 'sAMAccountName', 'objectClass', 'displayName', 'memberOf', 'userPrincipalName')) | Out-Null
                $gcSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $gcSearcher.PageSize = 1000

                try {
                    $gcResult = $gcSearcher.FindOne()
                    
                    if ($gcResult) {
                        $distinguishedName = $gcResult.Properties['distinguishedName'][0]
                        Write-Verbose "Found SID in GC at: $distinguishedName"
                        
                        # Build complete principal object for store
                        # Create DirectoryEntry to get ObjectSecurity
                        $objectPath = "LDAP://$server/$distinguishedName"
                        $tempEntry = New-Object System.DirectoryServices.DirectoryEntry(
                            $objectPath,
                            $script:Credential.UserName,
                            $script:Credential.GetNetworkCredential().Password
                        )
                        
                        $principalObject = [PSCustomObject]@{
                            DistinguishedName = $distinguishedName
                            ObjectSid = if ($gcResult.Properties['objectSid'].Count -gt 0) { 
                                (New-Object System.Security.Principal.SecurityIdentifier($gcResult.Properties['objectSid'][0], 0)).Value 
                            } else { $null }
                            SamAccountName = if ($gcResult.Properties['sAMAccountName'].Count -gt 0) { $gcResult.Properties['sAMAccountName'][0] } else { $null }
                            ObjectClass = if ($gcResult.Properties['objectClass'].Count -gt 0) { $gcResult.Properties['objectClass'][-1] } else { $null }
                            DisplayName = if ($gcResult.Properties['displayName'].Count -gt 0) { $gcResult.Properties['displayName'][0] } else { $null }
                            UserPrincipalName = if ($gcResult.Properties['userPrincipalName'].Count -gt 0) { $gcResult.Properties['userPrincipalName'][0] } else { $null }
                            MemberOf = if ($gcResult.Properties['memberOf'].Count -gt 0) { @($gcResult.Properties['memberOf']) } else { @() }
                            ObjectSecurity = $tempEntry.ObjectSecurity
                        }
                        
                        $tempEntry.Dispose()
                        
                        # Store the complete principal object
                        $script:PrincipalStore[$storeKey] = $principalObject
                        Write-Verbose "Stored principal object for '$storeKey': $distinguishedName (objectClass: $($principalObject.objectClass))"
                        
                        # Return DirectoryEntry for the found object
                        $objectPath = "LDAP://$server/$distinguishedName"
                        $objectEntry = New-Object System.DirectoryServices.DirectoryEntry(
                            $objectPath,
                            $script:Credential.UserName,
                            $script:Credential.GetNetworkCredential().Password
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
            $domainDN = if ($script:RootDSE) { $script:RootDSE.defaultNamingContext.Value } else { $null }
            
            if (-not $domainDN) {
                Write-Warning "Could not determine domain DN for SID resolution."
                return $null
            }
            
            # Create LDAP searcher with credentials
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $ldapPath = "LDAP://$server/$domainDN"
            
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath,
                $script:Credential.UserName,
                $script:Credential.GetNetworkCredential().Password
            )
            
            $searcher.SearchRoot = $directoryEntry
            $searcher.Filter = "(objectSid=$sidString)"
            # Load all principal properties for complete store object
            $searcher.PropertiesToLoad.AddRange(@('distinguishedName', 'objectSid', 'sAMAccountName', 'objectClass', 'displayName', 'memberOf', 'userPrincipalName')) | Out-Null
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.PageSize = 1000

            $result = $searcher.FindOne()

            if ($result) {
                $distinguishedName = $result.Properties['distinguishedName'][0]
                
                # Build complete principal object for store
                # Create DirectoryEntry to get ObjectSecurity
                $objectPath = "LDAP://$server/$distinguishedName"
                $tempEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    $objectPath,
                    $script:Credential.UserName,
                    $script:Credential.GetNetworkCredential().Password
                )
                
                $principalObject = [PSCustomObject]@{
                    distinguishedName = $distinguishedName
                    objectSid = if ($result.Properties['objectSid'].Count -gt 0) { 
                        (New-Object System.Security.Principal.SecurityIdentifier($result.Properties['objectSid'][0], 0)).Value 
                    } else { $null }
                    sAMAccountName = if ($result.Properties['sAMAccountName'].Count -gt 0) { $result.Properties['sAMAccountName'][0] } else { $null }
                    objectClass = if ($result.Properties['objectClass'].Count -gt 0) { $result.Properties['objectClass'][-1] } else { $null }
                    displayName = if ($result.Properties['displayName'].Count -gt 0) { $result.Properties['displayName'][0] } else { $null }
                    userPrincipalName = if ($result.Properties['userPrincipalName'].Count -gt 0) { $result.Properties['userPrincipalName'][0] } else { $null }
                    memberOf = if ($result.Properties['memberOf'].Count -gt 0) { @($result.Properties['memberOf']) } else { @() }
                    ObjectSecurity = $tempEntry.ObjectSecurity
                }
                
                $tempEntry.Dispose()
                
                # Store the complete principal object
                $script:PrincipalStore[$storeKey] = $principalObject
                Write-Verbose "Stored principal object for '$storeKey': $distinguishedName (objectClass: $($principalObject.objectClass))"
                
                # Return DirectoryEntry for the found object
                $objectPath = "LDAP://$server/$distinguishedName"
                $objectEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    $objectPath,
                    $script:Credential.UserName,
                    $script:Credential.GetNetworkCredential().Password
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
