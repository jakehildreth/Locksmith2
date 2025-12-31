function Test-IssueExists {
    <#
        .SYNOPSIS
        Checks if an issue already exists in the IssueStore.

        .DESCRIPTION
        Searches the IssueStore for an existing issue that matches the provided issue.
        Uses the LS2Issue.Matches() method to determine if issues are identical.

        .PARAMETER Issue
        The LS2Issue object to check for existence in the IssueStore.

        .PARAMETER DistinguishedName
        The distinguished name of the object the issue is associated with.

        .PARAMETER Technique
        The technique/ESC identifier for the issue.

        .OUTPUTS
        System.Boolean
        Returns $true if an identical issue already exists, $false otherwise.

        .EXAMPLE
        if (-not (Test-IssueExists -Issue $newIssue -DistinguishedName $dn -Technique 'ESC1')) {
            # Add the issue
        }

        .NOTES
        Used internally to prevent duplicate issues from being added to the IssueStore.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [LS2Issue]$Issue,
        
        [Parameter(Mandatory)]
        [string]$DistinguishedName,
        
        [Parameter(Mandatory)]
        [string]$Technique
    )

    #requires -Version 5.1

    # Check if DN exists in store
    if (-not $script:IssueStore.ContainsKey($DistinguishedName)) {
        return $false
    }

    # Check if technique exists for this DN
    if (-not $script:IssueStore[$DistinguishedName].ContainsKey($Technique)) {
        return $false
    }

    # Check if any existing issue matches this one
    foreach ($existingIssue in $script:IssueStore[$DistinguishedName][$Technique]) {
        if ($Issue.Matches($existingIssue)) {
            Write-Verbose "Duplicate issue detected: $($Issue.GetIdentifier())"
            return $true
        }
    }

    return $false
}
