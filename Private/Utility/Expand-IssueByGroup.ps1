function Expand-IssueByGroup {
    <#
        .SYNOPSIS
        Expands issues for group principals into individual issues for each group member.

        .DESCRIPTION
        Takes an LS2Issue object and checks if the IdentityReferenceSID belongs to a group.
        If it is a group, creates individual LS2Issue objects for each direct member of the group.
        If not a group, returns the original issue unchanged.
        
        This allows security findings to be attributed to individual users rather than just
        showing a group has dangerous permissions.

        .PARAMETER Issue
        The LS2Issue object to potentially expand.

        .PARAMETER IncludeGroup
        If specified, includes the original group issue in the output along with member issues.
        By default, only member issues are returned for groups.

        .OUTPUTS
        LS2Issue[]
        Returns an array of LS2Issue objects. For non-groups, returns a single-item array
        with the original issue. For groups, returns one issue per member (and optionally
        the group issue itself if -IncludeGroup is specified).

        .EXAMPLE
        $issue | Expand-IssueByGroup
        Expands group issues into per-member issues, omitting the group issue.

        .EXAMPLE
        $issue | Expand-IssueByGroup -IncludeGroup
        Expands group issues but also includes the original group issue in output.

        .EXAMPLE
        $allIssues = $issues | ForEach-Object { Expand-IssueByGroup $_ }
        Processes an array of issues, expanding any that reference groups.

        .NOTES
        Requires PrincipalStore to be populated with resolved principals including objectClass.
        Uses Expand-GroupMembership to get direct members of groups.
        The MemberCount property is set on group issues to indicate expansion occurred.
    #>
    [CmdletBinding()]
    [OutputType([LS2Issue[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [LS2Issue]$Issue,
        
        [Parameter()]
        [switch]$IncludeGroup
    )

    #requires -Version 5.1

    process {
        # If no IdentityReferenceSID, this isn't a permission-based issue, return as-is
        if ([string]::IsNullOrEmpty($Issue.IdentityReferenceSID)) {
            Write-Verbose "Issue has no IdentityReferenceSID - returning unchanged"
            return @($Issue)
        }

        # Check if principal is a group
        $principal = $script:PrincipalStore[$Issue.IdentityReferenceSID]
        if (-not $principal) {
            Write-Verbose "Principal $($Issue.IdentityReferenceSID) not found in PrincipalStore - returning unchanged"
            return @($Issue)
        }

        $isGroup = $principal.objectClass -eq 'group'
        
        if (-not $isGroup) {
            Write-Verbose "Principal $($Issue.IdentityReference) is not a group - returning unchanged"
            return @($Issue)
        }

        Write-Verbose "Expanding group $($Issue.IdentityReference) into member issues"

        # Expand group membership
        $members = Expand-GroupMembership -SidList @($Issue.IdentityReferenceSID)
        
        # Filter out the group itself from members
        $memberSids = $members | Where-Object { $_ -ne $Issue.IdentityReferenceSID }
        
        if (-not $memberSids -or $memberSids.Count -eq 0) {
            Write-Verbose "Group $($Issue.IdentityReference) has no members - returning original issue"
            # Update MemberCount to 0
            $Issue.MemberCount = 0
            return @($Issue)
        }

        Write-Verbose "Found $($memberSids.Count) member(s) in group $($Issue.IdentityReference)"

        # Create array to hold results
        $expandedIssues = @()

        # Optionally include the original group issue
        if ($IncludeGroup) {
            # Update MemberCount on the group issue
            $Issue.MemberCount = $memberSids.Count
            $expandedIssues += $Issue
        }

        # Create an issue for each member
        foreach ($memberSid in $memberSids) {
            # Get member principal from store
            $memberPrincipal = $script:PrincipalStore[$memberSid]
            
            if (-not $memberPrincipal) {
                Write-Verbose "Member SID $memberSid not found in PrincipalStore - skipping"
                continue
            }

            $memberNTAccount = $memberPrincipal.NTAccountName
            
            Write-Verbose "  Creating issue for member: $memberNTAccount"

            # Create issue description explaining group membership path
            $memberIssueText = "$memberNTAccount ($memberSid) is able to abuse this configuration via membership in the group $($Issue.IdentityReference) ($($Issue.IdentityReferenceSID))."
            
            # Create remediation reference pointing back to the original group issue
            $remediationReference = "For full remediation details, refer to $($Issue.GetIdentifier())"
            $fixText = "$memberNTAccount ($memberSid) is able to abuse this configuration via membership in the group $($Issue.IdentityReference) ($($Issue.IdentityReferenceSID)). $remediationReference"
            $revertText = $fixText

            # Clone the issue with new principal information
            $memberIssue = [LS2Issue]@{
                Technique             = $Issue.Technique
                Forest                = $Issue.Forest
                Name                  = $Issue.Name
                DistinguishedName     = $Issue.DistinguishedName
                IdentityReference     = $memberNTAccount
                IdentityReferenceSID  = $memberSid
                ActiveDirectoryRights = $Issue.ActiveDirectoryRights
                Enabled               = $Issue.Enabled
                EnabledOn             = $Issue.EnabledOn
                CAFullName            = $Issue.CAFullName
                Owner                 = $Issue.Owner
                HasNonStandardOwner   = $Issue.HasNonStandardOwner
                Issue                 = $memberIssueText
                Fix                   = $fixText
                Revert                = $revertText
            }

            $expandedIssues += $memberIssue
        }

        Write-Verbose "Expanded group $($Issue.IdentityReference) into $($expandedIssues.Count) issue(s)"
        
        return $expandedIssues
    }
}
