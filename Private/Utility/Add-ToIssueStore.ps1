function Add-ToIssueStore {
    <#
    .SYNOPSIS
        Adds an issue to the IssueStore with automatic structure initialization.

    .DESCRIPTION
        Handles the common pattern of initializing the IssueStore nested hashtable
        structure and adding an issue. Ensures the DN key exists, the technique
        key exists, and appends the issue to the array.

    .PARAMETER DistinguishedName
        The Distinguished Name of the object this issue relates to.

    .PARAMETER Technique
        The ESC technique name (e.g., 'ESC1', 'ESC6', 'ESC4o').

    .PARAMETER Issue
        The LS2Issue object to add to the store.

    .EXAMPLE
        Add-ToIssueStore -DistinguishedName $template.distinguishedName -Technique 'ESC1' -Issue $issue
        Adds an ESC1 issue to the IssueStore for the specified template.

    .OUTPUTS
        None. Modifies $script:IssueStore directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName,

        [Parameter(Mandatory)]
        [string]$Technique,

        [Parameter(Mandatory)]
        [object]$Issue
    )

    # Initialize DN key if needed
    if (-not $script:IssueStore.ContainsKey($DistinguishedName)) {
        $script:IssueStore[$DistinguishedName] = @{}
    }

    # Initialize technique key if needed
    if (-not $script:IssueStore[$DistinguishedName].ContainsKey($Technique)) {
        $script:IssueStore[$DistinguishedName][$Technique] = @()
    }

    # Add the issue
    $script:IssueStore[$DistinguishedName][$Technique] += $Issue
}
