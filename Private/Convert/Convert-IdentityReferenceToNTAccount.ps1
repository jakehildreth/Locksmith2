function Convert-IdentityReferenceToNTAccount {
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
        $sid | Convert-IdentityReferenceToNTAccount
        Converts a SID to NTAccount (domain-joined computer).

        .EXAMPLE
        $sid | Convert-IdentityReferenceToNTAccount -Credential $cred -RootDSE $rootDSE
        Converts a SID to NTAccount using credentials and RootDSE (non-domain joined computer).

        .EXAMPLE
        $ace.IdentityReference | Convert-IdentityReferenceToNTAccount -Credential $cred -RootDSE $rootDSE
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

    process {
        # If already an NTAccount, return it
        if ($SecurityIdentifier -is [System.Security.Principal.NTAccount]) {
            return $SecurityIdentifier
        }

        # Check PrincipalStore first (if it exists) - it has the NTAccount name already
        $sidString = $SecurityIdentifier.Value
        if ($script:PrincipalStore -and $script:PrincipalStore.ContainsKey($sidString)) {
            $storedPrincipal = $script:PrincipalStore[$sidString]
            if ($storedPrincipal.ntAccountName) {
                Write-Verbose "PrincipalStore HIT for SID '$sidString' → NTAccount: $($storedPrincipal.ntAccountName)"
                return [System.Security.Principal.NTAccount]::new($storedPrincipal.ntAccountName)
            }
        }

        # Try the built-in Translate method first (works on domain-joined computers)
        try {
            $ntAccount = $SecurityIdentifier.Translate([System.Security.Principal.NTAccount])
            return $ntAccount
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

            # Get root domain DN for GC searches
            $rootDomainDN = if ($RootDSE) { $RootDSE.rootDomainNamingContext.Value } else { $null }

            # First try Global Catalog search for forest-wide lookup
            if ($rootDomainDN) {
                Write-Verbose "Attempting Global Catalog search for SID '$sidString'"
                $gcSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $gcPath = "GC://$script:Server/$rootDomainDN"
                
                $gcSearcher.SearchRoot = New-AuthenticatedDirectoryEntry -Path $gcPath
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
                        
                        # Get NetBIOS domain name from DomainStore
                        $domainDN = $distinguishedName -replace '^.*?,(?=DC=)', ''
                        
                        if ($script:DomainStore -and $script:DomainStore.ContainsKey($domainDN)) {
                            $domainNetBiosName = $script:DomainStore[$domainDN].nETBIOSName.ToUpper()
                        } else {
                            # Fallback: extract first DC component from DN
                            if ($domainDN -match 'DC=([^,]+)') {
                                $domainNetBiosName = $Matches[1].ToUpper()
                                Write-Verbose "Using fallback NetBIOS name from DN: $domainNetBiosName"
                            } else {
                                $domainNetBiosName = 'UNKNOWN'
                            }
                        }
                        
                        $ntAccountString = "$($domainNetBiosName.ToUpper())\$samAccountName"
                        $ntAccount = New-Object System.Security.Principal.NTAccount($ntAccountString)
                        Write-Verbose "Resolved SID '$sidString' to '$ntAccountString' via Global Catalog"
                        
                        return $ntAccount
                    }
                } catch {
                    Write-Verbose "Global Catalog search failed, falling back to domain search: $_"
                } finally {
                    if ($gcSearcher) { $gcSearcher.Dispose() }
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
            $ldapPath = "LDAP://$script:Server/$domainDN"
            
            $searcher.SearchRoot = New-AuthenticatedDirectoryEntry -Path $ldapPath
            $searcher.Filter = "(objectSid=$sidString)"
            $searcher.PropertiesToLoad.AddRange(@('sAMAccountName', 'distinguishedName')) | Out-Null
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.PageSize = 1000

            $result = $searcher.FindOne()

            if ($result -and $result.Properties['sAMAccountName'].Count -gt 0) {
                $samAccountName = $result.Properties['sAMAccountName'][0]
                $distinguishedName = $result.Properties['distinguishedName'][0]
                
                # Get NetBIOS domain name from DomainStore
                $domainDN = $distinguishedName -replace '^.*?,(?=DC=)', ''
                
                if ($script:DomainStore -and $script:DomainStore.ContainsKey($domainDN)) {
                    $domainNetBiosName = $script:DomainStore[$domainDN].nETBIOSName.ToUpper()
                } else {
                    # Fallback: extract first DC component from DN
                    if ($domainDN -match 'DC=([^,]+)') {
                        $domainNetBiosName = $Matches[1].ToUpper()
                        Write-Verbose "Using fallback NetBIOS name from DN: $domainNetBiosName"
                    } else {
                        $domainNetBiosName = 'UNKNOWN'
                    }
                }
                
                $ntAccountString = "$($domainNetBiosName.ToUpper())\$samAccountName"
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
        }
    }
}
