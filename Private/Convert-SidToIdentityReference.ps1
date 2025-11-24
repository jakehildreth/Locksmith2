function Convert-SidToIdentityReference {
    <#
        .SYNOPSIS
        Converts a SecurityIdentifier (SID) to an IdentityReference (NTAccount).

        .DESCRIPTION
        Takes a System.Security.Principal.SecurityIdentifier object and converts it to an 
        NTAccount object. If the input is already an NTAccount, it is returned unchanged.
        
        On domain-joined computers, uses the built-in Translate() method. On non-domain joined computers,
        performs an LDAP query using provided credentials to resolve the SID to an NTAccount.
        
        Supports forest-wide searches using Global Catalog when RootDSE is provided, enabling resolution
        of principals from child domains and trusted domains within the forest.

        .PARAMETER SecurityIdentifier
        The SecurityIdentifier object to convert. Typically from SID strings or ACL entries.

        .PARAMETER Credential
        PSCredential for authenticating to Active Directory. Required when running from non-domain joined computers.

        .PARAMETER RootDSE
        A DirectoryEntry object for the RootDSE. Used to determine the domain context for LDAP queries.
        If not specified, attempts to query without specific domain context.

        .INPUTS
        System.Security.Principal.SecurityIdentifier
        Accepts SecurityIdentifier objects via the pipeline.

        .OUTPUTS
        System.Security.Principal.NTAccount
        Returns the NTAccount representation of the SID, or the original object if already an NTAccount.

        .EXAMPLE
        $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-...')
        $sid | Convert-SidToIdentityReference
        Converts a SID to NTAccount (domain-joined computer).

        .EXAMPLE
        $sid | Convert-SidToIdentityReference -Credential $cred -RootDSE $rootDSE
        Converts a SID to NTAccount using credentials and RootDSE (non-domain joined computer).

        .EXAMPLE
        $ace.IdentityReference | Convert-SidToIdentityReference -Credential $cred -RootDSE $rootDSE
        Converts SID IdentityReferences from an ACL to NTAccount objects.

        .NOTES
        Automatically detects domain membership and uses appropriate method.
        For non-domain joined scenarios, Credential and RootDSE parameters are recommended.
        Uses Global Catalog for forest-wide searches to support child domain resolution.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Principal.NTAccount])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Security.Principal.IdentityReference]
        $SecurityIdentifier,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
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
        # If already an NTAccount, return it
        if ($SecurityIdentifier -is [System.Security.Principal.NTAccount]) {
            return $SecurityIdentifier
        }

        # Try the built-in Translate method first (works on domain-joined computers)
        try {
            return $SecurityIdentifier.Translate([System.Security.Principal.NTAccount])
        } catch {
            Write-Verbose "Translate() failed, attempting LDAP lookup: $_"
        }

        # Fallback to LDAP query for non-domain joined scenarios
        if (-not $Credential) {
            Write-Warning "Could not translate SID '$SecurityIdentifier' to NTAccount. Not domain-joined and no credential provided."
            return $SecurityIdentifier
        }

        try {
            # Get the SID string
            $sidString = $SecurityIdentifier.Value

            # Extract server from RootDSE
            if ($RootDSE) {
                $rootDomainDN = $RootDSE.rootDomainNamingContext.Value
                if ($RootDSE.Path -match 'LDAP://([^/]+)') {
                    $server = $Matches[1]
                } else {
                    Write-Warning "Could not extract server from RootDSE path."
                    return $SecurityIdentifier
                }
            } else {
                Write-Warning "RootDSE parameter required for non-domain joined SID resolution."
                return $SecurityIdentifier
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
                $gcSearcher.PropertiesToLoad.AddRange(@('distinguishedName', 'sAMAccountName')) | Out-Null
                $gcSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $gcSearcher.PageSize = 1000

                try {
                    $gcResult = $gcSearcher.FindOne()
                    
                    if ($gcResult -and $gcResult.Properties['sAMAccountName'].Count -gt 0) {
                        $distinguishedName = $gcResult.Properties['distinguishedName'][0]
                        $samAccountName = $gcResult.Properties['sAMAccountName'][0]
                        Write-Verbose "Found SID in GC at: $distinguishedName"
                        
                        # Get NetBIOS domain name (with caching)
                        $domainDN = $distinguishedName -replace '^.*?,(?=DC=)', ''
                        
                        if ($script:netBiosCache.ContainsKey($domainDN)) {
                            $domainNetBiosName = $script:netBiosCache[$domainDN]
                        } else {
                            # Fallback: extract first DC component from DN
                            if ($domainDN -match 'DC=([^,]+)') {
                                $domainNetBiosName = $Matches[1].ToUpper()
                                Write-Verbose "Using fallback NetBIOS name from DN: $domainNetBiosName"
                            } else {
                                $domainNetBiosName = 'UNKNOWN'
                            }
                            $script:netBiosCache[$domainDN] = $domainNetBiosName
                        }
                        
                        $ntAccountString = "$domainNetBiosName\$samAccountName"
                        $ntAccount = New-Object System.Security.Principal.NTAccount($ntAccountString)
                        Write-Verbose "Resolved SID '$sidString' to '$ntAccountString' via Global Catalog"
                        
                        return $ntAccount
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
                return $SecurityIdentifier
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
            $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'distinguishedName')) | Out-Null
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.PageSize = 1000

            $result = $searcher.FindOne()

            if ($result -and $result.Properties['sAMAccountName'].Count -gt 0) {
                $samAccountName = $result.Properties['sAMAccountName'][0]
                $distinguishedName = $result.Properties['distinguishedName'][0]
                
                # Get NetBIOS domain name (with caching)
                $domainDN = $distinguishedName -replace '^.*?,(?=DC=)', ''
                
                if ($script:netBiosCache.ContainsKey($domainDN)) {
                    $domainNetBiosName = $script:netBiosCache[$domainDN]
                } else {
                    # Fallback: extract first DC component from DN
                    if ($domainDN -match 'DC=([^,]+)') {
                        $domainNetBiosName = $Matches[1].ToUpper()
                        Write-Verbose "Using fallback NetBIOS name from DN: $domainNetBiosName"
                    } else {
                        $domainNetBiosName = 'UNKNOWN'
                    }
                    $script:netBiosCache[$domainDN] = $domainNetBiosName
                }
                
                $ntAccountString = "$domainNetBiosName\$samAccountName"
                $ntAccount = New-Object System.Security.Principal.NTAccount($ntAccountString)
                Write-Verbose "Resolved SID '$sidString' to '$ntAccountString' via LDAP"
                return $ntAccount
            } else {
                Write-Warning "Could not find SID '$sidString' in Active Directory via LDAP query."
                return $SecurityIdentifier
            }
        } catch {
            Write-Warning "LDAP query failed for SID '$sidString': $_"
            return $SecurityIdentifier
        } finally {
            if ($searcher) { $searcher.Dispose() }
            if ($directoryEntry) { $directoryEntry.Dispose() }
        }
    }
}
