function Expand-GroupMembership {
    <#
        .SYNOPSIS
        Expands group memberships to return direct member SIDs.

        .DESCRIPTION
        Takes an array of SIDs and expands any that are groups to include their direct members.
        Non-group principals are returned as-is. This function performs non-recursive expansion,
        returning only direct members of groups.
        
        The function uses the PrincipalStore to determine if a principal is a group, then
        queries the 'member' attribute via LDAP to retrieve direct member DNs. Each member
        DN is then resolved to its SID and added to the result set.
        
        IMPORTANT: Returns both the original group SID AND its member SIDs. To get only members
        without the group itself, filter the output: $result | Where-Object { $_ -ne $groupSid }
        
        Results are cached to avoid redundant LDAP queries for the same groups.

        .PARAMETER SidList
        Array of SID strings to process. Groups will be expanded to their direct members,
        non-groups will be returned unchanged.

        .INPUTS
        System.String[]
        Accepts an array of SID strings via the pipeline.

        .OUTPUTS
        System.String[]
        Returns an array of SID strings including both original non-group principals and
        all direct members of any groups in the input.

        .EXAMPLE
        $sids = @('S-1-5-21-...-513', 'S-1-5-21-...-1104')
        $expanded = Expand-GroupMembership -SidList $sids
        Expands Domain Users group and custom group to include their direct members.

        .EXAMPLE
        $template.LowPrivilegeEnrollee | Expand-GroupMembership
        Expands any groups in the LowPrivilegeEnrollee array to show all direct members.

        .NOTES
        This function performs non-recursive expansion. Nested groups are returned as group
        objects, not expanded further. For recursive expansion, call this function multiple
        times or implement recursive logic.
        
        Requires that principals have already been resolved via Resolve-Principal so they
        exist in the PrincipalStore with objectClass information.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('SID', 'SecurityIdentifier')]
        [string[]]$SidList
    )

    begin {
        # Initialize expanded group cache if it doesn't exist
        if (-not $script:ExpandedGroupCache) {
            $script:ExpandedGroupCache = @{}
        }
        
        $allMembers = [System.Collections.Generic.List[string]]::new()
        Write-Verbose "Starting group membership expansion for $($SidList.Count) principal(s)"
    }

    process {
        foreach ($sid in $SidList) {
            Write-Verbose "Processing SID: $sid"
            
            # Check if principal exists in PrincipalStore
            if (-not $script:PrincipalStore -or -not $script:PrincipalStore.ContainsKey($sid)) {
                Write-Verbose "SID '$sid' not in PrincipalStore, returning as-is"
                $allMembers.Add($sid)
                continue
            }
            
            $principal = $script:PrincipalStore[$sid]
            
            # Check if it's a group
            if ($principal.objectClass -notmatch '^group$') {
                Write-Verbose "SID '$sid' is not a group (objectClass: $($principal.objectClass)), returning as-is"
                $allMembers.Add($sid)
                continue
            }
            
            # It's a group - check cache first
            if ($script:ExpandedGroupCache.ContainsKey($sid)) {
                $cachedMembers = $script:ExpandedGroupCache[$sid]
                Write-Verbose "Cache HIT: Group '$sid' has $($cachedMembers.Count) cached member(s)"
                
                # Always add the group itself first
                $allMembers.Add($sid)
                
                # Then add all cached members (if any)
                foreach ($member in $cachedMembers) {
                    $allMembers.Add($member)
                }
                continue
            }
            
            # Not in cache - query LDAP for group members
            Write-Verbose "Cache MISS: Querying LDAP for members of group '$sid' ($($principal.ntAccountName))"
            
            try {
                # Get the group's DN
                $groupDN = $principal.distinguishedName
                
                if (-not $groupDN) {
                    Write-Warning "Group SID '$sid' has no distinguishedName, cannot expand"
                    $allMembers.Add($sid)
                    continue
                }
                
                # Query the group object for its member attribute
                $groupPath = "LDAP://$script:Server/$groupDN"
                $groupEntry = New-AuthenticatedDirectoryEntry -Path $groupPath
                
                if (-not $groupEntry) {
                    Write-Warning "Could not create DirectoryEntry for group '$groupDN'"
                    $allMembers.Add($sid)
                    continue
                }
                
                # Get member attribute (contains DNs of direct members)
                $memberDNs = @($groupEntry.Properties['member'])
                
                if ($memberDNs.Count -eq 0) {
                    Write-Verbose "Group '$($principal.ntAccountName)' has no members - keeping group itself in list"
                    # Cache empty result (but keep the group in the output)
                    $script:ExpandedGroupCache[$sid] = @()
                    $allMembers.Add($sid)
                    $groupEntry.Dispose()
                    continue
                }
                
                Write-Verbose "Group '$($principal.ntAccountName)' has $($memberDNs.Count) direct member(s)"
                
                # Convert each member DN to SID
                $memberSids = [System.Collections.Generic.List[string]]::new()
                
                foreach ($memberDN in $memberDNs) {
                    try {
                        # Query for the member's objectSid
                        $memberPath = "LDAP://$script:Server/$memberDN"
                        $memberEntry = New-AuthenticatedDirectoryEntry -Path $memberPath
                        
                        if ($memberEntry -and $memberEntry.Properties['objectSid'].Count -gt 0) {
                            $memberSid = (New-Object System.Security.Principal.SecurityIdentifier($memberEntry.Properties['objectSid'][0], 0)).Value
                            $memberSids.Add($memberSid)
                            Write-Verbose "  Member: $memberDN -> $memberSid"
                            
                            # Ensure member is in PrincipalStore (triggers resolution if needed)
                            $sidRef = [System.Security.Principal.SecurityIdentifier]::new($memberSid)
                            $null = $sidRef | Resolve-Principal
                        } else {
                            Write-Warning "Could not retrieve objectSid for member '$memberDN'"
                        }
                        
                        if ($memberEntry) {
                            $memberEntry.Dispose()
                        }
                    } catch {
                        Write-Warning "Failed to process member '$memberDN': $_"
                    }
                }
                
                # Cache the expanded membership
                $script:ExpandedGroupCache[$sid] = $memberSids.ToArray()
                Write-Verbose "Cached $($memberSids.Count) member(s) for group '$sid'"
                
                # Add the group itself first
                $allMembers.Add($sid)
                
                # Then add all members
                foreach ($memberSid in $memberSids) {
                    $allMembers.Add($memberSid)
                }
                
                $groupEntry.Dispose()
                
            } catch {
                Write-Warning "Failed to expand group '$sid': $_"
                # Return the group itself on error
                $allMembers.Add($sid)
            }
        }
    }

    end {
        # Return unique list
        $uniqueMembers = $allMembers | Sort-Object -Unique
        Write-Verbose "Group expansion complete: $($SidList.Count) input(s) -> $($uniqueMembers.Count) unique member(s)"
        return $uniqueMembers
    }
}
