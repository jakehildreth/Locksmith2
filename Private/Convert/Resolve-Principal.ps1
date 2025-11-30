function Resolve-Principal {
    <#
        .SYNOPSIS
        Resolves an IdentityReference to a complete principal object and caches it in the PrincipalStore.

        .DESCRIPTION
        Takes a System.Security.Principal.IdentityReference object (either NTAccount or SecurityIdentifier) 
        and resolves it to a complete principal object via LDAP query. The resolved principal is cached in the
        module-level PrincipalStore for fast subsequent lookups, and a DirectoryEntry is returned.
        
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
        $sid | Resolve-Principal -Credential $cred -RootDSE $rootDSE
        Resolves a SID to a DirectoryEntry and caches the principal.

        .EXAMPLE
        $ntAccount = [System.Security.Principal.NTAccount]::new('DOMAIN\User')
        $ntAccount | Resolve-Principal -Credential $cred -RootDSE $rootDSE
        Resolves an NTAccount to a DirectoryEntry and caches the principal.

        .EXAMPLE
        $ace.IdentityReference | Resolve-Principal -Credential $cred -RootDSE $rootDSE
        Resolves IdentityReferences from an ACL to DirectoryEntry objects and caches them.

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
    }

    process {
        # Convert IdentityReference to SID for store key
        $sidKey = $IdentityReference | Convert-IdentityReferenceToSid
        if (-not $sidKey) {
            Write-Warning "Could not convert IdentityReference to SID: $($IdentityReference.Value)"
            return $null
        }
        
        $sidString = $sidKey.Value
        
        # Try to get NTAccount name for the SID (for well-known principals)
        $ntAccountName = if ($IdentityReference -is [System.Security.Principal.NTAccount]) {
            # Already have the friendly name
            $IdentityReference.Value
        } elseif ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
            # Try to translate SID to NTAccount to get friendly name
            try {
                $ntAccount = $IdentityReference.Translate([System.Security.Principal.NTAccount])
                $ntAccount.Value
            } catch {
                Write-Verbose "Could not translate SID '$sidString' to NTAccount. $_"
                $null
            }
        } else {
            $null
        }
        
        # Check store first - use SID as store key
        if ($script:PrincipalStore.ContainsKey($sidString)) {
            $storedPrincipal = $script:PrincipalStore[$sidString]
            Write-Verbose "Store HIT: Found stored principal for SID '$sidString': $($storedPrincipal.distinguishedName)"
            
            # Extract server from RootDSE
            if ($script:RootDSE.Path -match 'LDAP://([^/]+)') {
                $server = $Matches[1]
            } else {
                Write-Warning "Could not extract server from RootDSE path."
                return $null
            }
            
            # Create fresh DirectoryEntry from stored DN
            $objectPath = "LDAP://$server/$($storedPrincipal.distinguishedName)"
            $objectEntry = New-AuthenticatedDirectoryEntry -Path $objectPath
            
            return $objectEntry
        }
        
        Write-Verbose "Store MISS: No stored DN found for SID '$sidString', performing LDAP lookup"
        
        try {
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
            if ($rootDomainDN -and $script:GCDirectoryEntry) {
                Write-Verbose "Attempting Global Catalog search for SID '$sidString'"
                $gcSearcher = New-Object System.DirectoryServices.DirectorySearcher
                
                $gcSearcher.SearchRoot = $script:GCDirectoryEntry
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
                        $principalObject = [LS2Principal]::new($gcResult, $server, $sidKey, $ntAccountName)
                        
                        # Store the complete principal object using SID as key
                        $script:PrincipalStore[$sidString] = $principalObject
                        Write-Verbose "Stored principal object for SID '$sidString': $distinguishedName (objectClass: $($principalObject.objectClass))"
                        
                        # Return DirectoryEntry for the found object
                        $objectPath = "LDAP://$server/$distinguishedName"
                        $objectEntry = New-AuthenticatedDirectoryEntry -Path $objectPath
                        
                        Write-Verbose "Resolved SID '$sidString' to '$distinguishedName' via Global Catalog"
                        return $objectEntry
                    }
                } catch {
                    Write-Verbose "Global Catalog search failed, falling back to domain search: $_"
                } finally {
                    if ($gcSearcher) { $gcSearcher.Dispose() }
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
            
            if ($script:LDAPDirectoryEntry -and $domainDN -eq $script:RootDSE.defaultNamingContext.Value) {
                $searcher.SearchRoot = $script:LDAPDirectoryEntry
            } else {
                $ldapPath = "LDAP://$server/$domainDN"
                $searcher.SearchRoot = New-AuthenticatedDirectoryEntry -Path $ldapPath
            }
            $searcher.Filter = "(objectSid=$sidString)"
            # Load all principal properties for complete store object
            $searcher.PropertiesToLoad.AddRange(@('distinguishedName', 'objectSid', 'sAMAccountName', 'objectClass', 'displayName', 'memberOf', 'userPrincipalName')) | Out-Null
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.PageSize = 1000

            $result = $searcher.FindOne()

            if ($result) {
                $distinguishedName = $result.Properties['distinguishedName'][0]
                
                # Build complete principal object for store
                $principalObject = [LS2Principal]::new($result, $server, $sidKey, $ntAccountName)
                
                # Store the complete principal object using SID as key
                $script:PrincipalStore[$sidString] = $principalObject
                Write-Verbose "Stored principal object for SID '$sidString': $distinguishedName (objectClass: $($principalObject.objectClass))"
                
                # Return DirectoryEntry for the found object
                $objectPath = "LDAP://$server/$distinguishedName"
                $objectEntry = New-AuthenticatedDirectoryEntry -Path $objectPath
                
                Write-Verbose "Resolved SID '$sidString' to '$distinguishedName' via LDAP"
                return $objectEntry
            } else {
                Write-Warning "Could not find SID '$sidString' in Active Directory via LDAP query."
                
                # For well-known SIDs that don't exist in AD, create a minimal store entry
                # This includes BUILTIN groups and other system principals
                if ($ntAccountName) {
                    Write-Verbose "Creating store entry for well-known SID '$sidString' with name '$ntAccountName'"
                    
                    $principalObject = [LS2Principal]::new($sidString, $ntAccountName)
                    
                    # Store the principal object
                    $script:PrincipalStore[$sidString] = $principalObject
                    Write-Verbose "Stored well-known principal for SID '$sidString': $ntAccountName"
                }
                
                return $null
            }
        } catch {
            Write-Warning "LDAP query failed for SID '$sidString': $_"
            return $null
        } finally {
            if ($searcher) { $searcher.Dispose() }
        }
    }
}
