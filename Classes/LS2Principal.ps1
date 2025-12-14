class LS2Principal {
    [string]$distinguishedName
    [string]$objectSid
    [string]$sAMAccountName
    [string]$objectClass
    [string]$displayName
    [string]$NTAccountName
    [string]$userPrincipalName
    [string[]]$memberOf
    [System.DirectoryServices.ActiveDirectorySecurity]$ObjectSecurity

    # Constructor from SearchResult
    LS2Principal(
        [System.DirectoryServices.SearchResult]$SearchResult,
        [string]$Server,
        [System.Security.Principal.SecurityIdentifier]$SidKey,
        [string]$NTAccountName
    ) {
        $this.distinguishedName = $SearchResult.Properties['distinguishedName'][0]
        
        # Create DirectoryEntry to get ObjectSecurity
        if (-not $Server) {
            throw "Server parameter is null or empty"
        }
        
        $objectPath = "LDAP://$Server/$($this.distinguishedName)"
        Write-Verbose "LS2Principal: Creating DirectoryEntry for $objectPath"
        $tempEntry = New-AuthenticatedDirectoryEntry -Path $objectPath
        
        # Handle case where DirectoryEntry creation fails
        if (-not $tempEntry) {
            throw "Failed to create DirectoryEntry for path: $objectPath"
        }
        
        # Set objectSid
        if ($SearchResult.Properties['objectSid'].Count -gt 0) {
            $this.objectSid = (New-Object System.Security.Principal.SecurityIdentifier($SearchResult.Properties['objectSid'][0], 0)).Value
        }
        
        # Set sAMAccountName
        if ($SearchResult.Properties['sAMAccountName'].Count -gt 0) {
            $this.sAMAccountName = $SearchResult.Properties['sAMAccountName'][0]
        }
        
        # Set objectClass (get the most specific class)
        if ($SearchResult.Properties['objectClass'].Count -gt 0) {
            $classes = @($SearchResult.Properties['objectClass'])
            $this.objectClass = $classes[$classes.Count - 1]
        }
        
        # Set displayName
        if ($SearchResult.Properties['displayName'].Count -gt 0) {
            $this.displayName = $SearchResult.Properties['displayName'][0]
        }
        
        # Set NTAccountName - use provided or build from sAMAccountName + domain
        if ($NTAccountName) {
            $this.NTAccountName = $NTAccountName
        } elseif ($this.sAMAccountName) {
            # Build NTAccount name from sAMAccountName and domain NetBIOS name
            $domainDN = $this.distinguishedName -replace '^.*?,(?=DC=)', ''
            
            if ($script:DomainStore -and $script:DomainStore.ContainsKey($domainDN)) {
                $domainNetBiosName = $script:DomainStore[$domainDN].nETBIOSName.ToUpper()
                $this.NTAccountName = "$domainNetBiosName\$($this.sAMAccountName)"
            } else {
                # Fallback: extract first DC component from DN
                if ($domainDN -match 'DC=([^,]+)') {
                    $domainNetBiosName = $Matches[1].ToUpper()
                    $this.NTAccountName = "$domainNetBiosName\$($this.sAMAccountName)"
                }
            }
        }
        
        # Set userPrincipalName
        if ($SearchResult.Properties['userPrincipalName'].Count -gt 0) {
            $this.userPrincipalName = $SearchResult.Properties['userPrincipalName'][0]
        }
        
        # Set memberOf
        if ($SearchResult.Properties['memberOf'].Count -gt 0) {
            $this.memberOf = @($SearchResult.Properties['memberOf'])
        } else {
            $this.memberOf = @()
        }
        
        # Set ObjectSecurity (may fail for some objects in PS5.1)
        try {
            $this.ObjectSecurity = $tempEntry.ObjectSecurity
        } catch {
            Write-Verbose "Could not retrieve ObjectSecurity for '$($this.distinguishedName)': $_"
            $this.ObjectSecurity = $null
        }
        
        # Dispose only if not null
        if ($tempEntry) {
            $tempEntry.Dispose()
        }
        
        # Add nTSecurityDescriptor as an alias for ObjectSecurity
        $this | Add-Member -MemberType ScriptProperty -Name nTSecurityDescriptor -Value {
            return $this.ObjectSecurity
        }
    }
    
    # Constructor for well-known principals that don't exist in AD
    # Used for BUILTIN groups (S-1-5-32-*) and other machine-local SIDs
    # Note: Some well-known SIDs like S-1-5-11 exist as foreignSecurityPrincipal objects
    # and will use the main constructor instead
    LS2Principal(
        [string]$ObjectSid,
        [string]$NTAccountName
    ) {
        $this.distinguishedName = $null
        $this.objectSid = $ObjectSid
        $this.sAMAccountName = $null
        $this.objectClass = 'wellKnownPrincipal'
        $this.displayName = $null
        $this.NTAccountName = $NTAccountName
        $this.userPrincipalName = $null
        $this.memberOf = @()
        $this.ObjectSecurity = $null
    }
}
