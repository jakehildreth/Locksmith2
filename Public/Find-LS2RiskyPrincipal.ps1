function Find-LS2RiskyPrincipal {
    <#
        .SYNOPSIS
        Analyzes principal-centric risk by aggregating vulnerabilities each principal can exploit.

        .DESCRIPTION
        Find-LS2RiskyPrincipal pivots from configuration-centric to principal-centric risk analysis.
        It expands group memberships and aggregates issues by individual principal, showing which
        users/service accounts have the highest exposure to AD CS vulnerabilities.
        
        This enables risk prioritization: remediate principals with the most exploitable paths first.
        
        The function automatically expands group issues into per-member issues, then aggregates by
        principal to show total exposure across all techniques and configurations.

        .PARAMETER Technique
        Filter results to only include a specific ESC technique (e.g., 'ESC1', 'ESC7a').
        If not specified, includes all techniques.

        .PARAMETER MinimumIssueCount
        Only return principals with at least this many exploitable issues.
        Default: 1 (show all principals with any exposure)

        .PARAMETER Top
        Return only the top N principals with highest risk exposure.
        If not specified, returns all principals matching criteria.

        .PARAMETER Rescan
        Forces a fresh vulnerability scan even if IssueStore is already populated.
        Clears the IssueStore and rescans all AD CS configurations.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        PSCustomObject
        Returns objects with the following properties:
        - Principal: NTAccount name of the principal
        - IssueCount: Total number of exploitable configurations
        - Techniques: Array of unique ESC techniques the principal can abuse
        - VulnerableObjects: Array of unique vulnerable objects (templates, CAs, etc.)
        - Issues: Hashtable of LS2Issue objects keyed by GetIdentifier() for detailed analysis

        .EXAMPLE
        Find-LS2RiskyPrincipal -Top 10
        Shows the 10 principals with the highest number of exploitable vulnerabilities.

        .EXAMPLE
        Find-LS2RiskyPrincipal -Technique ESC1 -MinimumIssueCount 5
        Shows principals who can abuse at least 5 ESC1 (SAN abuse) configurations.

        .EXAMPLE
        Find-LS2RiskyPrincipal | Where-Object Principal -like '*admin*'
        Shows risk exposure for all principals with 'admin' in their name.

        .EXAMPLE
        $topRisk = Find-LS2RiskyPrincipal -Top 20
        $topRisk | Format-Table Principal, IssueCount, Techniques
        Gets top 20 riskiest principals and displays summary information.

        .EXAMPLE
        Find-LS2RiskyPrincipal -Top 5 | ForEach-Object {
            "$($_.Principal): $($_.IssueCount) issues"
            $_.Issues.Values | Format-Table Technique, Name
        }
        Shows detailed breakdown of issues for top 5 riskiest principals.

        .NOTES
        Author: Jake Hildreth (@jakehildreth)
        Requires: PowerShell 5.1+
        
        If IssueStore is not already populated, this function will automatically run a full
        vulnerability scan (all techniques) to populate it. For better performance, run
        Invoke-Locksmith2 first if you plan to query multiple times.
        
        This function performs group expansion, which requires LDAP queries. For large environments
        with many group memberships, this may take time to complete.

        .LINK
        Invoke-Locksmith2

        .LINK
        Expand-IssueByGroup

        .LINK
        Get-FlattenedIssues
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateSet('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC4a', 'ESC4o', 'ESC5a', 'ESC5o', 'ESC6', 'ESC7a', 'ESC7m', 'ESC9', 'ESC11', 'ESC16')]
        [string]$Technique,
        
        [Parameter()]
        [int]$MinimumIssueCount = 1,
        
        [Parameter()]
        [int]$Top,
        
        [Parameter()]
        [switch]$Rescan
    )

    #requires -Version 5.1

    begin {
        # Ensure stores are initialized and populated
        $initParams = @{}
        if ($Rescan) { $initParams['Rescan'] = $true }
        
        if (-not (Initialize-LS2Scan @initParams)) {
            return
        }
        
        Write-Verbose "Retrieving all issues from IssueStore..."
    }

    process {
        # Get all flattened issues
        $allIssues = Get-FlattenedIssues
        
        if (-not $allIssues -or $allIssues.Count -eq 0) {
            Write-Warning "No issues found in IssueStore."
            return
        }
        
        Write-Verbose "Found $($allIssues.Count) total issue(s)"
        
        # Expand group memberships
        Write-Verbose "Expanding group memberships to individual principals..."
        $expandedIssues = $allIssues | ForEach-Object { Expand-IssueByGroup $_ }
        Write-Verbose "Expanded to $($expandedIssues.Count) issue(s) after group expansion"
        
        # Filter by technique if specified
        if ($Technique) {
            Write-Verbose "Filtering to technique: $Technique"
            $expandedIssues = $expandedIssues | Where-Object Technique -eq $Technique
            Write-Verbose "Filtered to $($expandedIssues.Count) issue(s) for $Technique"
        }
        
        # Filter to only permission-based issues (those with IdentityReference)
        $principalIssues = $expandedIssues | Where-Object { -not [string]::IsNullOrEmpty($_.IdentityReference) }
        Write-Verbose "Aggregating $($principalIssues.Count) permission-based issue(s) by principal..."
        
        # Group by principal and create risk report
        $riskReport = $principalIssues |
            Group-Object IdentityReference |
            ForEach-Object {
                $principalName = $_.Name
                $issues = $_.Group
                $issueCount = $issues.Count
                
                # Create hashtable of issues keyed by GetIdentifier()
                $issueHashtable = @{}
                foreach ($issue in $issues) {
                    $identifier = $issue.GetIdentifier()
                    if (-not $issueHashtable.ContainsKey($identifier)) {
                        $issueHashtable[$identifier] = $issue
                    }
                }
                
                [PSCustomObject]@{
                    Principal         = $principalName
                    IssueCount        = $issueCount
                    Techniques        = @($issues.Technique | Select-Object -Unique | Sort-Object)
                    VulnerableObjects = @($issues.Name | Select-Object -Unique | Sort-Object)
                    Issues            = $issueHashtable
                }
            } |
            Where-Object IssueCount -ge $MinimumIssueCount |
            Sort-Object IssueCount -Descending
        
        Write-Verbose "Risk report generated for $($riskReport.Count) principal(s)"
        
        # Return top N if specified
        if ($Top) {
            Write-Verbose "Returning top $Top principal(s)"
            $riskReport | Select-Object -First $Top
        } else {
            $riskReport
        }
    }
}
