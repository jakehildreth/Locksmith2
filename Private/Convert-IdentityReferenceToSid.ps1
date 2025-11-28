function Convert-IdentityReferenceToSid {
    <#
        .SYNOPSIS
        Converts an IdentityReference (NTAccount) to a SecurityIdentifier (SID).

        .DESCRIPTION
        Takes a System.Security.Principal.IdentityReference object and converts NTAccount objects
        to SecurityIdentifier (SID) objects. If the input is already a SID, it is returned unchanged.
        
        On domain-joined computers, uses the built-in Translate() method. On non-domain joined computers,
        performs an LDAP query using provided credentials to resolve the NTAccount to a SID.
        
        Supports forest-wide searches using Global Catalog when RootDSE is provided, enabling resolution
        of principals from child domains and trusted domains within the forest.

        .PARAMETER Principal
        The IdentityReference object to convert. Typically from ACL IdentityReference properties.

        .PARAMETER Credential
        PSCredential for authenticating to Active Directory. Required when running from non-domain joined computers.

        .PARAMETER RootDSE
        A DirectoryEntry object for the RootDSE. Used to determine the domain context for LDAP queries.
        If not specified, attempts to derive the domain from the NTAccount name.

        .INPUTS
        System.Security.Principal.IdentityReference
        Accepts IdentityReference objects via the pipeline.

        .OUTPUTS
        System.Security.Principal.SecurityIdentifier
        Returns the SID representation of the principal, or the original object if already a SID.

        .EXAMPLE
        $ace.IdentityReference | Convert-IdentityReferenceToSid
        Converts an ACE's IdentityReference to a SID (domain-joined computer).

        .EXAMPLE
        $ace.IdentityReference | Convert-IdentityReferenceToSid -Credential $cred -RootDSE $rootDSE
        Converts an ACE's IdentityReference to a SID using credentials and RootDSE (non-domain joined computer).

        .EXAMPLE
        $SubCA.ObjectSecurity.Access.IdentityReference | Convert-IdentityReferenceToSid -Credential $cred -RootDSE $rootDSE
        Converts all IdentityReferences from an object's ACL to SIDs.

        .NOTES
        Automatically detects domain membership and uses appropriate method.
        For non-domain joined scenarios, Credential and RootDSE parameters are recommended.
        Uses Global Catalog for forest-wide searches to support child domain resolution.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Principal.SecurityIdentifier])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Security.Principal.IdentityReference]
        $IdentityReference
    )

    begin {
        # Cache for performance (currently unused but kept for consistency with Convert-SidToIdentityReference)
        $script:searchCache = @{}
    }

    process {
        # If already a SID, return it
        if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
            return $IdentityReference
        }

        # Try the built-in Translate method first (works on domain-joined computers)
        try {
            return $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
        } catch {
            Write-Verbose "Translate() failed, attempting LDAP lookup: $_"
        }

        # Fallback to LDAP query for non-domain joined scenarios
        if (-not $script:Credential) {
            Write-Warning "Could not translate principal '$IdentityReference' to SID. Not domain-joined and no credential provided."
            return $IdentityReference
        }

        try {
            # Parse the NTAccount name
            $ntAccountString = $IdentityReference.Value
            if ($ntAccountString -match '^(.+?)\\(.+)$') {
                $domain = $Matches[1]
                $samAccountName = $Matches[2]
            } else {
                $samAccountName = $ntAccountString
                $domain = $null
            }

            # Get the default naming context from RootDSE
            if ($script:RootDSE) {
                $rootDomainDN = $script:RootDSE.rootDomainNamingContext.Value
                # Extract server from RootDSE path if available
                if ($script:RootDSE.Path -match 'LDAP://([^/]+)') {
                    $server = $Matches[1]
                } else {
                    $server = $domain
                }
            } else {
                $server = $domain
                $rootDomainDN = $null
            }

            if (-not $server) {
                Write-Warning "Could not determine server to query for principal '$IdentityReference'."
                return $IdentityReference
            }

            # First try Global Catalog search for forest-wide lookup
            if ($rootDomainDN) {
                Write-Verbose "Attempting Global Catalog search for '$IdentityReference'"
                $gcSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $gcPath = "GC://$server/$rootDomainDN"
                
                $gcEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    $gcPath,
                    $script:Credential.UserName,
                    $script:Credential.GetNetworkCredential().Password
                )
                
                $gcSearcher.SearchRoot = $gcEntry
                $gcSearcher.Filter = "(sAMAccountName=$samAccountName)"
                $gcSearcher.PropertiesToLoad.AddRange(@('distinguishedName', 'objectSid')) | Out-Null
                $gcSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $gcSearcher.PageSize = 1000

                try {
                    $gcResult = $gcSearcher.FindOne()
                    
                    if ($gcResult -and $gcResult.Properties['objectSid'].Count -gt 0) {
                        $distinguishedName = $gcResult.Properties['distinguishedName'][0]
                        $sidBytes = $gcResult.Properties['objectSid'][0]
                        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                        Write-Verbose "Found principal in GC at: $distinguishedName"
                        Write-Verbose "Resolved '$IdentityReference' to SID '$($sid.Value)' via Global Catalog"
                        
                        return $sid
                    }
                } catch {
                    Write-Verbose "Global Catalog search failed, falling back to domain search: $_"
                } finally {
                    if ($gcSearcher) { $gcSearcher.Dispose() }
                    if ($gcEntry) { $gcEntry.Dispose() }
                }
            }

            # Fallback to direct LDAP search in default domain
            Write-Verbose "Attempting direct LDAP search for '$IdentityReference'"
            $domainDN = if ($script:RootDSE) { $script:RootDSE.defaultNamingContext.Value } else { $null }
            
            # Create LDAP searcher with credentials
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $ldapPath = if ($domainDN) { "LDAP://$server/$domainDN" } else { "LDAP://$server" }
            
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath,
                $script:Credential.UserName,
                $script:Credential.GetNetworkCredential().Password
            )
            
            $searcher.SearchRoot = $directoryEntry
            $searcher.Filter = "(sAMAccountName=$samAccountName)"
            $searcher.PropertiesToLoad.Add('objectSid') | Out-Null
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.PageSize = 1000

            $result = $searcher.FindOne()

            if ($result -and $result.Properties['objectSid'].Count -gt 0) {
                $sidBytes = $result.Properties['objectSid'][0]
                $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                Write-Verbose "Resolved '$IdentityReference' to SID '$($sid.Value)' via LDAP"
                return $sid
            } else {
                Write-Warning "Could not find principal '$IdentityReference' in Active Directory via LDAP query."
                return $IdentityReference
            }
        } catch {
            Write-Warning "LDAP query failed for principal '$IdentityReference': $_"
            return $IdentityReference
        } finally {
            if ($searcher) { $searcher.Dispose() }
            if ($directoryEntry) { $directoryEntry.Dispose() }
        }
    }
}
