function Get-FlattenedIssues {
    <#
        .SYNOPSIS
        Flattens the IssueStore hashtable into individual LS2Issue objects.

        .DESCRIPTION
        Converts the nested IssueStore structure (DN -> Technique -> Issues array) into
        a flat list of LS2Issue objects containing complete vulnerability information.
        
        Each returned LS2Issue object contains all properties defined in the LS2Issue class:
        - Core identification: Technique, Forest, Name, DistinguishedName
        - Principal information: IdentityReference, IdentityReferenceSID, ActiveDirectoryRights
        - Template properties: Enabled, EnabledOn
        - CA properties: CAFullName
        - Ownership properties: Owner, HasNonStandardOwner
        - Remediation: Issue, Fix, Revert

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        LS2Issue
        Returns LS2Issue objects with complete vulnerability information.

        .EXAMPLE
        Get-FlattenedIssues
        Returns a flattened list of all LS2Issue objects from the IssueStore.

        .EXAMPLE
        Get-FlattenedIssues | Where-Object Technique -eq 'ESC1'
        Returns only ESC1 issues.

        .EXAMPLE
        Get-FlattenedIssues | Group-Object {$_.IsTemplateIssue()}
        Groups issues by whether they are template-related.

        .NOTES
        Requires $script:IssueStore to be populated by Invoke-Locksmith2 
        or related Find-LS2Vulnerable* functions.
    #>
    [CmdletBinding()]
    [OutputType([LS2Issue])]
    param()

    #requires -Version 5.1

    begin {
        Write-Verbose "Flattening IssueStore into individual issue entries..."
        
        # Get stores from module scope
        $stores = Get-LS2Stores
        
        if (-not $stores.IssueStore -or $stores.IssueStore.Count -eq 0) {
            Write-Warning "IssueStore is empty or not initialized. Run Invoke-Locksmith2 first."
            return
        }
    }

    process {
        $issueCount = 0

        # Iterate through each DN in the IssueStore
        foreach ($dn in $stores.IssueStore.Keys) {
            # Iterate through each technique for this DN
            foreach ($technique in $stores.IssueStore[$dn].Keys) {
                # Get all issues for this DN + technique combination
                $issues = $stores.IssueStore[$dn][$technique]

                # Output each LS2Issue object directly
                foreach ($issue in $issues) {
                    $issueCount++
                    $issue
                }
            }
        }

        Write-Verbose "Flattened $issueCount issue(s) from IssueStore"
    }
}
