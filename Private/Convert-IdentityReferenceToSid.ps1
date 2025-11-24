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
        $Principal,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]
        $RootDSE
    )

    process {
        # If already a SID, return it
        if ($Principal -is [System.Security.Principal.SecurityIdentifier]) {
            return $Principal
        }

        # Try the built-in Translate method first (works on domain-joined computers)
        try {
            return $Principal.Translate([System.Security.Principal.SecurityIdentifier])
        } catch {
            Write-Verbose "Translate() failed, attempting LDAP lookup: $_"
        }

        # Fallback to LDAP query for non-domain joined scenarios
        if (-not $Credential) {
            Write-Warning "Could not translate principal '$Principal' to SID. Not domain-joined and no credential provided."
            return $Principal
        }

        try {
            # Parse the NTAccount name
            $ntAccountString = $Principal.Value
            if ($ntAccountString -match '^(.+?)\\(.+)$') {
                $domain = $Matches[1]
                $samAccountName = $Matches[2]
            } else {
                $samAccountName = $ntAccountString
                $domain = $null
            }

            # Get the default naming context from RootDSE
            if ($RootDSE) {
                $rootDomainDN = $RootDSE.rootDomainNamingContext.Value
                # Extract server from RootDSE path if available
                if ($RootDSE.Path -match 'LDAP://([^/]+)') {
                    $server = $Matches[1]
                } else {
                    $server = $domain
                }
            } else {
                $server = $domain
                $rootDomainDN = $null
            }

            if (-not $server) {
                Write-Warning "Could not determine server to query for principal '$Principal'."
                return $Principal
            }

            # First try Global Catalog search for forest-wide lookup
            if ($rootDomainDN) {
                Write-Verbose "Attempting Global Catalog search for '$Principal'"
                $gcSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $gcPath = "GC://$server/$rootDomainDN"
                
                $gcEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    $gcPath,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
                
                $gcSearcher.SearchRoot = $gcEntry
                $gcSearcher.Filter = "(sAMAccountName=$samAccountName)"
                $gcSearcher.PropertiesToLoad.Add('distinguishedName') | Out-Null
                $gcSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree

                try {
                    $gcResult = $gcSearcher.FindOne()
                    
                    if ($gcResult) {
                        # Found in GC, now get full object from specific domain
                        $distinguishedName = $gcResult.Properties['distinguishedName'][0]
                        Write-Verbose "Found principal in GC at: $distinguishedName"
                        
                        # Query the specific domain partition for full objectSid
                        $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher
                        $domainPath = "LDAP://$server/$distinguishedName"
                        
                        $domainEntry = New-Object System.DirectoryServices.DirectoryEntry(
                            $domainPath,
                            $Credential.UserName,
                            $Credential.GetNetworkCredential().Password
                        )
                        
                        $domainSearcher.SearchRoot = $domainEntry
                        $domainSearcher.Filter = "(objectClass=*)"
                        $domainSearcher.PropertiesToLoad.Add('objectSid') | Out-Null
                        $domainSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                        
                        $domainResult = $domainSearcher.FindOne()
                        
                        if ($domainResult -and $domainResult.Properties['objectSid'].Count -gt 0) {
                            $sidBytes = $domainResult.Properties['objectSid'][0]
                            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                            Write-Verbose "Resolved '$Principal' to SID '$($sid.Value)' via Global Catalog"
                            
                            if ($domainSearcher) { $domainSearcher.Dispose() }
                            if ($domainEntry) { $domainEntry.Dispose() }
                            if ($gcSearcher) { $gcSearcher.Dispose() }
                            if ($gcEntry) { $gcEntry.Dispose() }
                            
                            return $sid
                        }
                        
                        if ($domainSearcher) { $domainSearcher.Dispose() }
                        if ($domainEntry) { $domainEntry.Dispose() }
                    }
                } catch {
                    Write-Verbose "Global Catalog search failed, falling back to domain search: $_"
                } finally {
                    if ($gcSearcher) { $gcSearcher.Dispose() }
                    if ($gcEntry) { $gcEntry.Dispose() }
                }
            }

            # Fallback to direct LDAP search in default domain
            Write-Verbose "Attempting direct LDAP search for '$Principal'"
            $domainDN = if ($RootDSE) { $RootDSE.defaultNamingContext.Value } else { $null }
            
            # Create LDAP searcher with credentials
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $ldapPath = if ($domainDN) { "LDAP://$server/$domainDN" } else { "LDAP://$server" }
            
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
                $ldapPath,
                $Credential.UserName,
                $Credential.GetNetworkCredential().Password
            )
            
            $searcher.SearchRoot = $directoryEntry
            $searcher.Filter = "(sAMAccountName=$samAccountName)"
            $searcher.PropertiesToLoad.Add('objectSid') | Out-Null
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree

            $result = $searcher.FindOne()

            if ($result -and $result.Properties['objectSid'].Count -gt 0) {
                $sidBytes = $result.Properties['objectSid'][0]
                $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                Write-Verbose "Resolved '$Principal' to SID '$($sid.Value)' via LDAP"
                return $sid
            } else {
                Write-Warning "Could not find principal '$Principal' in Active Directory via LDAP query."
                return $Principal
            }
        } catch {
            Write-Warning "LDAP query failed for principal '$Principal': $_"
            return $Principal
        } finally {
            if ($searcher) { $searcher.Dispose() }
            if ($directoryEntry) { $directoryEntry.Dispose() }
        }
    }
}
