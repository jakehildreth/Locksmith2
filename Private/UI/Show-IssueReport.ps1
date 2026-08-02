function Show-IssueReport {
    <#
        .SYNOPSIS
        Displays discovered AD CS issues in console based on specified mode.

        .DESCRIPTION
        Formats and displays LS2Issue objects in the console using different output modes.
        Issues are grouped by technique with styled headers matching the original Locksmith format.

        Mode 0: Summary table per technique with banners
        Mode 1: Detailed per-technique list views
        Mode 5: Full list view including Fix and Revert scripts

        .PARAMETER Issues
        Array of LS2Issue objects to display.

        .PARAMETER Mode
        Output mode for displaying issues:
        - 0: Summary table per technique with banners
        - 1: Detailed per-technique list views
        - 5: Full list view with fix/revert scripts

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        None. Outputs directly to console using Write-Host and Format-* cmdlets.

        .EXAMPLE
        $issues = Get-FlattenedIssues
        Show-IssueReport -Issues $issues -Mode 0

        Displays issues in summary table format.

        .EXAMPLE
        Show-IssueReport -Issues $issues -Mode 1

        Displays issues using per-technique detailed list views.

        .EXAMPLE
        Show-IssueReport -Issues $issues -Mode 5

        Displays issues in full list format with fix and revert scripts.

        .NOTES
        Author: Jake Hildreth (@jakehildreth)
        Module: Locksmith2
        Requires: PowerShell 5.1+
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [LS2Issue[]]$Issues,

        [Parameter(Mandatory)]
        [ValidateSet(0, 1, 5)]
        [int]$Mode
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Preparing issue report (Mode $Mode)..."

        $writeTechniqueHeader = {
            param([string]$Title)
            Write-Host ""
            Write-Host "$('-' * ($Title.Length + 10))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
            Write-Host "     " -BackgroundColor Magenta -NoNewline
            Write-Host $Title -BackgroundColor Magenta -ForegroundColor Black -NoNewline
            Write-Host "     " -BackgroundColor Magenta -NoNewline; Write-Host
            Write-Host "$('-' * ($Title.Length + 10))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
            Write-Host ""
        }
    }

    process {
        # Sort and group issues by technique
        $sortedIssues = $Issues | Sort-Object Technique, @{ Expression = 'RiskValue'; Descending = $true }, Name, Issue
        $issuesByTechnique = $sortedIssues | Group-Object -Property Technique | Sort-Object Name

        Write-Host "`n[i] Locksmith discovered the following AD CS issues:`n" -ForegroundColor Cyan

        switch ($Mode) {
            0 {
                # Mode 0: Summary table per technique with banners
                foreach ($group in $issuesByTechnique) {
                    & $writeTechniqueHeader "$($group.Name) Issues"
                    $group.Group | Format-Table -View Summary
                }
            }
            1 {
                # Mode 1: Per-technique detailed list views
                foreach ($group in $issuesByTechnique) {
                    & $writeTechniqueHeader "$($group.Name) Issues"
                    $viewName = "$($group.Name)Detailed"
                    $group.Group | Format-List -View $viewName
                }
            }
            5 {
                # Mode 5: Full list view with fix/revert scripts
                foreach ($group in $issuesByTechnique) {
                    & $writeTechniqueHeader "$($group.Name) Issues"
                    $group.Group | Format-List -View Full
                }
            }
        }
    }
}
