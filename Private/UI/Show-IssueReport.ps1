function Show-IssueReport {
    <#
        .SYNOPSIS
        Displays discovered AD CS issues in console based on specified mode.

        .DESCRIPTION
        Formats and displays LS2Issue objects in the console using different output modes.
        Issues are grouped by technique with styled headers matching the original Locksmith format.
        
        Mode 0: Table format showing Name and Issue columns
        Mode 1: List format showing Name, Issue, Fix, and Revert properties

        .PARAMETER Issues
        Array of LS2Issue objects to display.

        .PARAMETER Mode
        Output mode for displaying issues:
        - 0: Table format (issues only)
        - 1: List format (issues with fix scripts)

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        None. Outputs directly to console using Write-Host and Format-* cmdlets.

        .EXAMPLE
        $issues = Get-FlattenedIssues
        Show-IssueReport -Issues $issues -Mode 0
        
        Displays issues in table format.

        .EXAMPLE
        Show-IssueReport -Issues $issues -Mode 1
        
        Displays issues in list format with fix scripts.

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
        [ValidateSet(0, 1)]
        [int]$Mode
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Preparing issue report in Mode $Mode format..."
    }

    process {
        # Sort and group issues by technique
        $sortedIssues = $Issues | Sort-Object Technique, Name, Issue
        $issuesByTechnique = $sortedIssues | Group-Object -Property Technique | Sort-Object Name

        # Display based on mode
        switch ($Mode) {
            0 {
                # Mode 0: Table format (issues only) grouped by technique
                Write-Host "`n[i] Locksmith discovered the following AD CS issues:`n" -ForegroundColor Cyan
                
                foreach ($group in $issuesByTechnique) {
                    $title = "$($group.Name) Issues"
                    Write-Host ""
                    Write-Host "$('-' * ($title.Length + 10))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
                    Write-Host "     " -BackgroundColor Magenta -NoNewline
                    Write-Host $title -BackgroundColor Magenta -ForegroundColor Black -NoNewline
                    Write-Host "     " -BackgroundColor Magenta -NoNewline; Write-Host
                    Write-Host "$('-' * ($title.Length + 10))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
                    Write-Host ""
                    $group.Group | Format-Table -Property Name, Issue -Wrap
                }
            }
            1 {
                # Mode 1: List format (issues with fix scripts) grouped by technique
                Write-Host "`n[i] Locksmith discovered the following AD CS issues:`n" -ForegroundColor Cyan
                
                foreach ($group in $issuesByTechnique) {
                    $title = "$($group.Name) Issues"
                    Write-Host ""
                    Write-Host "$('-' * ($title.Length + 10))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
                    Write-Host "     " -BackgroundColor Magenta -NoNewline
                    Write-Host $title -BackgroundColor Magenta -ForegroundColor Black -NoNewline
                    Write-Host "     " -BackgroundColor Magenta -NoNewline; Write-Host
                    Write-Host "$('-' * ($title.Length + 10))" -ForegroundColor Black -BackgroundColor Magenta -NoNewline; Write-Host
                    Write-Host ""
                    
                    # Create display objects with properly formatted strings
                    $displayIssues = foreach ($issue in $group.Group) {
                        [PSCustomObject]@{
                            Name   = $issue.Name
                            Issue  = $issue.Issue
                            Fix    = if ($issue.Fix) { $ExecutionContext.InvokeCommand.ExpandString($issue.Fix) } else { $null }
                            Revert = if ($issue.Revert) { $ExecutionContext.InvokeCommand.ExpandString($issue.Revert) } else { $null }
                        }
                    }
                    
                    $displayIssues | Format-List -Property Name, Issue, Fix, Revert
                }
            }
        }
    }
}
