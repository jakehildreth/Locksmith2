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

        .PARAMETER DetailLevel
        Named detail level rendered via LS2Issue format views:
        - Summary: compact table (Technique, Forest, ObjectClass, Name, Issue)
        - Detailed: per-technique list views showing properties relevant to each technique
        - Full: list view with every property including Fix and Revert scripts

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

        .EXAMPLE
        Show-IssueReport -Issues $issues -DetailLevel Detailed
        
        Displays issues using per-technique detailed format views.

        .NOTES
        Author: Jake Hildreth (@jakehildreth)
        Module: Locksmith2
        Requires: PowerShell 5.1+
    #>
    [CmdletBinding(DefaultParameterSetName = 'Mode')]
    param(
        [Parameter(Mandatory)]
        [LS2Issue[]]$Issues,

        [Parameter(Mandatory, ParameterSetName = 'Mode')]
        [ValidateSet(0, 1)]
        [int]$Mode,

        [Parameter(Mandatory, ParameterSetName = 'DetailLevel')]
        [ValidateSet('Summary', 'Detailed', 'Full')]
        [string]$DetailLevel
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Preparing issue report ($($PSCmdlet.ParameterSetName))..."

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
        $sortedIssues = $Issues | Sort-Object Technique, Name, Issue
        $issuesByTechnique = $sortedIssues | Group-Object -Property Technique | Sort-Object Name

        if ($PSCmdlet.ParameterSetName -eq 'DetailLevel') {
            Write-Host "`n[i] Locksmith discovered the following AD CS issues:`n" -ForegroundColor Cyan

            # Per-technique Detailed views fall back to Full when no view is defined
            $availableViews = @((Get-FormatData -TypeName 'LS2Issue' -PowerShellVersion $PSVersionTable.PSVersion).FormatViewDefinition.Name)

            foreach ($group in $issuesByTechnique) {
                & $writeTechniqueHeader "$($group.Name) Issues"

                switch ($DetailLevel) {
                    'Summary' {
                        $group.Group | Format-Table -View 'Summary'
                    }
                    'Detailed' {
                        $viewName = "$($group.Name)Detailed"
                        if ($availableViews -notcontains $viewName) {
                            Write-Verbose "No '$viewName' view defined. Falling back to 'Full'."
                            $viewName = 'Full'
                        }
                        $group.Group | Format-List -View $viewName
                    }
                    'Full' {
                        $group.Group | Format-List -View 'Full'
                    }
                }
            }
            return
        }

        # Display based on mode
        switch ($Mode) {
            0 {
                # Mode 0: Table format (issues only) grouped by technique
                Write-Host "`n[i] Locksmith discovered the following AD CS issues:`n" -ForegroundColor Cyan
                
                foreach ($group in $issuesByTechnique) {
                    & $writeTechniqueHeader "$($group.Name) Issues"
                    $group.Group | Format-Table -Property Name, Issue -Wrap
                }
            }
            1 {
                # Mode 1: List format (issues with fix scripts) grouped by technique
                Write-Host "`n[i] Locksmith discovered the following AD CS issues:`n" -ForegroundColor Cyan
                
                foreach ($group in $issuesByTechnique) {
                    & $writeTechniqueHeader "$($group.Name) Issues"
                    
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
