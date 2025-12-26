function Get-IssueCount {
    <#
    .SYNOPSIS
        Counts issues for a specific ESC technique from the IssueStore.

    .DESCRIPTION
        Iterates through the IssueStore and counts all issues for a given ESC technique.
        This eliminates the need to repeat the counting logic for each technique.

    .PARAMETER Technique
        The ESC technique name to count issues for (e.g., 'ESC1', 'ESC6', 'ESC4o').

    .EXAMPLE
        Get-IssueCount -Technique 'ESC1'
        Returns the number of ESC1 issues found.

    .OUTPUTS
        [int] The total count of issues for the specified technique.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$Technique
    )

    $count = 0
    foreach ($dn in $script:IssueStore.Keys) {
        if ($script:IssueStore[$dn].ContainsKey($Technique)) {
            $count += $script:IssueStore[$dn][$Technique].Count
        }
    }
    return $count
}
