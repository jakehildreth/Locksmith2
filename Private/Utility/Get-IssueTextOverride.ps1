function Get-IssueTextOverride {
    <#
        .SYNOPSIS
        Selects issue text overrides for an AD CS object based on technique Overrides.

        .DESCRIPTION
        Technique definitions in ESCDefinitions.ps1 may carry an Overrides array. Each
        override specifies a single When condition (property equality) and alternate
        IssueTemplate/FixTemplate/RevertTemplate text.

        This function returns the first override whose When condition matches the
        object, or the base config when no override matches. Callers use the returned
        hashtable's IssueTemplate/FixTemplate/RevertTemplate in place of the base
        config's text.

        Example override shape:
            Overrides = @(
                @{
                    When           = @{ Property = 'IsCATemplate'; Value = $true }
                    IssueTemplate  = '...'
                    FixTemplate    = '...'
                    RevertTemplate = '...'
                }
            )

        .PARAMETER Config
        A technique definition hashtable from $script:ESCDefinitions.

        .PARAMETER AdcsObject
        The LS2AdcsObject being evaluated.

        .OUTPUTS
        Hashtable — the matching override merged into the issue-text role, or Config unchanged.

        .EXAMPLE
        $textConfig = Get-IssueTextOverride -Config $config -AdcsObject $template

        .NOTES
        Overrides only carry text. Placeholder expansion remains the caller's job.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Config,

        [Parameter(Mandatory)]
        [LS2AdcsObject]$AdcsObject
    )

    foreach ($override in @($Config.Overrides)) {
        if ($null -eq $override.When) { continue }
        if ($AdcsObject.($override.When.Property) -eq $override.When.Value) {
            Write-Verbose "Override matched on $($override.When.Property) = $($override.When.Value)"
            return $override
        }
    }

    return $Config
}
