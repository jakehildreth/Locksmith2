function New-LS2Dashboard {
    <#
    .SYNOPSIS
    Generates an interactive HTML dashboard for Locksmith2 scan results.
    
    .DESCRIPTION
    Creates a comprehensive HTML dashboard with left navigation menu showing:
    - All issues with expanded principals
    - Issues filtered by type (Template, CA, Object)
    - Risky principals analysis
    
    Supports light/dark mode toggle and interactive filtering/sorting.
    Requires PSWriteHTML module (Install-Module PSWriteHTML).
    
    .PARAMETER FilePath
    Path where the HTML dashboard will be saved.
    Default: $env:TEMP\Locksmith2-Dashboard.html
    
    .PARAMETER Show
    Opens the dashboard in default browser after generation.
    
    .PARAMETER ExpandGroups
    Expands group principals into individual member issues.
    
    .PARAMETER Online
    Uses online CDN resources instead of embedding CSS/JS.
    Results in smaller file size but requires internet connection to view.
    
    .INPUTS
    None. This function does not accept pipeline input.
    
    .OUTPUTS
    None. Generates an HTML file at the specified path.
    
    .EXAMPLE
    Invoke-Locksmith2
    New-LS2Dashboard -FilePath C:\Reports\locksmith-dashboard.html -Show
    
    Runs a scan and generates an interactive dashboard.
    
    .EXAMPLE
    New-LS2Dashboard -ExpandGroups -Show
    
    Generates dashboard with group memberships expanded to individual principals.
    
    .EXAMPLE
    New-LS2Dashboard -FilePath C:\Reports\report.html -Online
    
    Generates a smaller dashboard file using online CDN resources.
    
    .NOTES
    Author: Jake Hildreth (@jakehildreth)
    Requires: PSWriteHTML module (https://github.com/EvotecIT/PSWriteHTML)
    Requires: PowerShell 5.1 or later
    
    The dashboard reads from the current IssueStore. Run Invoke-Locksmith2 or
    Find-LS2Vulnerable* functions first to populate the store with scan data.
    
    .LINK
    Invoke-Locksmith2
    
    .LINK
    Find-LS2RiskyPrincipal
    
    .LINK
    Get-FlattenedIssues
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$FilePath = "$env:TEMP\Locksmith2-Dashboard.html",
        
        [Parameter()]
        [switch]$Show,
        
        [Parameter()]
        [switch]$ExpandGroups,
        
        [Parameter()]
        [switch]$Online
    )
    
    #requires -Version 5.1
    
    # Check for PSWriteHTML module
    if (-not (Get-Module -ListAvailable -Name PSWriteHTML)) {
        Write-Error "PSWriteHTML module is required. Install with: Install-Module PSWriteHTML"
        return
    }
    
    Import-Module PSWriteHTML -ErrorAction Stop
    
    # Check if IssueStore is populated
    if (-not $script:IssueStore -or $script:IssueStore.Count -eq 0) {
        Write-Warning "IssueStore is empty. Run Invoke-Locksmith2 or Find-LS2Vulnerable* functions first."
        Write-Warning "Generating empty dashboard..."
    }
    
    # Get all issues from IssueStore
    $allIssues = Get-FlattenedIssues
    
    # Expand groups if requested
    if ($ExpandGroups) {
        Write-Verbose "Expanding group memberships for dashboard..."
        $allIssues = $allIssues | ForEach-Object { Expand-IssueByGroup $_ }
    }
    
    # Filter issues by category
    $templateTechniques = @('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC4a', 'ESC4o', 'ESC9')
    $caTechniques = @('ESC6', 'ESC7a', 'ESC7m', 'ESC11', 'ESC16')
    $objectTechniques = @('ESC5a', 'ESC5o')
    $misconfigurationTechniques = @('ESC1', 'ESC2', 'ESC3c1', 'ESC3c1', 'ESC6', 'ESC9', 'ESC11', 'ESC16')
    $accessTechniques = @('ESC4a', 'ESC5a')
    $ownershipTechniques = @('ESC4o', 'ESC5o')
    
    $templateIssues = $allIssues | Where-Object { $_.Technique -in $templateTechniques }
    $caIssues = $allIssues | Where-Object { $_.Technique -in $caTechniques }
    $objectIssues = $allIssues | Where-Object { $_.Technique -in $objectTechniques }
    $misconfigurationIssues = $allIssues | Where-Object { $_.Technique -in $misconfigurationTechniques }
    $accessIssues = $allIssues | Where-Object { $_.Technique -in $accessTechniques }
    $ownershipIssues = $allIssues | Where-Object { $_.Technique -in $ownershipTechniques }
    
    # Get risky principals
    Write-Verbose "Calculating principal risk scores..."
    $riskyPrincipals = Find-LS2RiskyPrincipal
    
    # Prepare data for tables - ALL tabs show same columns, just filtered/sorted differently
    $standardColumns = @(
        'Technique'
        'Forest'
        'Name'
        'DistinguishedName'
        @{N = 'ObjectClass'; E = { if ($_.ObjectClass) { $_.ObjectClass } else { 'N/A' } } }
        @{N = 'IdentityReference'; E = { if ($_.IdentityReference) { $_.IdentityReference } else { 'N/A' } } }
        @{N = 'IdentityReferenceSID'; E = { if ($_.IdentityReferenceSID) { $_.IdentityReferenceSID } else { 'N/A' } } }
        @{N = 'IdentityReferenceClass'; E = { if ($_.IdentityReferenceClass) { $_.IdentityReferenceClass } else { 'N/A' } } }
        @{N = 'ActiveDirectoryRights'; E = { if ($_.ActiveDirectoryRights) { $_.ActiveDirectoryRights } else { 'N/A' } } }
        @{N = 'AceObjectTypeGUID'; E = { if ($_.AceObjectTypeGUID) { $_.AceObjectTypeGUID } else { 'N/A' } } }
        @{N = 'AceObjectTypeName'; E = { if ($_.AceObjectTypeName) { $_.AceObjectTypeName } else { 'N/A' } } }
        @{N = 'Enabled'; E = { if ($null -ne $_.Enabled) { $_.Enabled } else { 'N/A' } } }
        @{N = 'EnabledOn'; E = { if ($_.EnabledOn) { $_.EnabledOn -join ', ' } else { 'N/A' } } }
        @{N = 'CAFullName'; E = { if ($_.CAFullName) { $_.CAFullName } else { 'N/A' } } }
        @{N = 'Owner'; E = { if ($_.Owner) { $_.Owner } else { 'N/A' } } }
        @{N = 'HasNonStandardOwner'; E = { if ($null -ne $_.HasNonStandardOwner) { $_.HasNonStandardOwner } else { 'N/A' } } }
        @{N = 'Members'; E = { if ($_.MemberCount) { $_.MemberCount } else { 'N/A' } } }
        'Issue'
        'Fix'
        'Revert'
    )
    
    $allIssuesTable = $allIssues | Select-Object $standardColumns
    $templateIssuesTable = $templateIssues | Select-Object $standardColumns
    $caIssuesTable = $caIssues | Select-Object $standardColumns
    $objectIssuesTable = $objectIssues | Select-Object $standardColumns
    $misconfigurationIssuesTable = $misconfigurationIssues | Select-Object $standardColumns
    $accessIssuesTable = $accessIssues | Select-Object $standardColumns
    $ownershipIssuesTable = $ownershipIssues | Select-Object $standardColumns
    
    $principalsTable = $riskyPrincipals | Select-Object `
        Principal,
    IssueCount,
    @{N = 'Techniques'; E = { $_.Techniques -join ', ' } },
    @{N = 'VulnerableObjects'; E = { $_.VulnerableObjects.Count } }
    
    $forestName = if ($script:Forest) { $script:Forest } else { 'Unknown Forest' }
    
    # Define conditional formatting rules - applies consistently to all issue tables
    $issueFormatting = {
        # Template issues (red-purple range)
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC1' -BackgroundColor '#ffcdd2' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC2' -BackgroundColor '#f8bbd0' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC4a' -BackgroundColor '#e1bee7' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC4o' -BackgroundColor '#d1c4e9' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC9' -BackgroundColor '#ce93d8' -Color Black
        
        # CA issues (yellow-orange range)
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC6' -BackgroundColor '#fff59d' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC7a' -BackgroundColor '#ffcc80' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC7m' -BackgroundColor '#ffb74d' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC11' -BackgroundColor '#ff9800' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC16' -BackgroundColor '#ffa726' -Color Black
        
        # Object issues (green-blue range)
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC5a' -BackgroundColor '#a5d6a7' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC5o' -BackgroundColor '#80cbc4' -Color Black
        
        # Rights-based formatting (high severity)
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*GenericAll*' -BackgroundColor '#d32f2f' -Color White
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*WriteDacl*' -BackgroundColor '#ef5350' -Color White
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*WriteOwner*' -BackgroundColor '#ff9800' -Color White
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*WriteProperty*' -BackgroundColor '#ffa726' -Color Black
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*GenericWrite*' -BackgroundColor '#ffa726' -Color Black
        
        # Status-based formatting
        New-HTMLTableCondition -Name 'Enabled' -Value $true -BackgroundColor '#fff9c4' -Color Black
    }
    
    # Define conditional formatting for principals table (different schema)
    # Order matters: most severe conditions last so they override less severe ones
    $principalFormatting = {
        New-HTMLTableCondition -Name 'IssueCount' -ComparisonType number -Operator ge -Value 1 -BackgroundColor '#fdd835' -Color Black
        New-HTMLTableCondition -Name 'IssueCount' -ComparisonType number -Operator ge -Value 5 -BackgroundColor '#ff9800' -Color White
        New-HTMLTableCondition -Name 'IssueCount' -ComparisonType number -Operator gt -Value 10 -BackgroundColor '#ef5350' -Color White
    }
    
    # Generate HTML Dashboard
    New-HTML -TitleText "Locksmith2 Security Dashboard - $forestName" -Online:$Online -FilePath $FilePath -Show:$Show {
        
        # Use tabs for single-page navigation with content switching
        New-HTMLTabStyle -SlimTabs -Transition -SelectorColor Magenta
        
        New-HTMLTab -Name 'All Issues' -IconSolid exclamation-triangle -IconColor Red {
            New-HTMLSection -Invisible {
                New-HTMLPanel -Width 10% {
                    New-HTMLText -Text "All Issues - Expanded Principals ($($allIssues.Count) total)" -FontSize 20 -FontWeight bold
                    New-HTMLText -Text @"
This view shows all discovered AD CS vulnerabilities with group memberships expanded to individual principals.
Issues are marked with the ESC technique and show which principals can exploit each configuration.
"@ -Color '#888' -FontSize 14
                }
                New-HTMLPanel {
                    New-HTMLTable -DataTable $allIssuesTable `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5', 'searchBuilder', 'searchPanes') `
                        -Title 'All AD CS Security Issues' {& $issueFormatting}
                }
            }
        }
        
        New-HTMLTab -Name 'Templates' -IconSolid file-contract -IconColor Orange {
            New-HTMLSection -Invisible {
                New-HTMLPanel -Width 10% {
                    New-HTMLText -Text "Certificate Template Issues ($($templateIssues.Count) issues)" -FontSize 20 -FontWeight bold
                    New-HTMLText -Text @"
Certificate templates are the most common source of AD CS vulnerabilities. These issues allow principals to request
certificates with dangerous permissions, subject alternative names, or enrollment agent capabilities.
"@ -Color '#888' -FontSize 14
                }
                New-HTMLPanel {
                    New-HTMLTable -DataTable $templateIssuesTable `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5', 'searchBuilder', 'searchPanes') `
                        -Title 'Template Vulnerabilities' `
                        -DefaultSortColumn 'Technique' {& $issueFormatting}
                }
            }
        }
        
        New-HTMLTab -Name 'CAs' -IconSolid certificate -IconColor Yellow {
            New-HTMLSection -Invisible {
                New-HTMLPanel -Width 10% {
                    New-HTMLText -Text "Certification Authority Issues ($($caIssues.Count) issues)" -FontSize 20 -FontWeight bold
                    New-HTMLText -Text @"
CA-level issues involve dangerous role assignments (ESC7) or insecure CA configurations (ESC6, ESC11, ESC16).
These vulnerabilities grant principals excessive control over certificate issuance.
"@ -Color '#888' -FontSize 14
                }
                New-HTMLPanel {
                    New-HTMLTable -DataTable $caIssuesTable `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5', 'searchBuilder', 'searchPanes') `
                        -Title 'CA Configuration Issues' `
                        -DefaultSortColumn 'Name' {& $issueFormatting}
                }
            }
        }
        
        New-HTMLTab -Name 'Objects' -IconSolid folder -IconColor Blue {
            New-HTMLSection -Invisible {
                New-HTMLPanel -Width 10% {
                    New-HTMLText -Text "PKI Object Issues ($($objectIssues.Count) issues)" -FontSize 20 -FontWeight bold
                    New-HTMLText -Text @"
ESC5 vulnerabilities involve dangerous ownership or write permissions on PKI infrastructure objects.
These allow principals to modify templates, CAs, or other critical AD CS components.
"@ -Color '#888' -FontSize 14
                }
                New-HTMLPanel {
                    New-HTMLTable -DataTable $objectIssuesTable `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5', 'searchBuilder', 'searchPanes') `
                        -Title 'Infrastructure Object Issues' `
                        -DefaultSortColumn 'Name' {& $issueFormatting}
                }
            }
        }
        
        New-HTMLTab -Name 'Risky Principals' -IconSolid user-shield -IconColor Purple {
            New-HTMLSection -Invisible {
                New-HTMLPanel -Width 10% {
                    New-HTMLText -Text "Principal Risk Analysis ($($principalsTable.Count) principals)" -FontSize 20 -FontWeight bold
                    New-HTMLText -Text @"
This analysis shows which principals have access to the most AD CS vulnerabilities. Principals with high issue counts
represent concentrated risk and should be prioritized for remediation or monitoring.
"@ -Color '#888' -FontSize 14
                }
                New-HTMLPanel {
                    New-HTMLTable -DataTable $principalsTable `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5', 'searchBuilder', 'searchPanes') `
                        -Title 'Principals by Risk Score' `
                        -DefaultSortColumn 'IssueCount' `
                        -DefaultSortOrder Descending {& $principalFormatting}
                }
            }
        }
        
        New-HTMLTab -Name 'Misconfigurations' -IconSolid cog -IconColor Red {
            New-HTMLSection -Invisible {
                New-HTMLPanel -Width 10% {
                    New-HTMLText -Text "Misconfiguration Issues ($($misconfigurationIssues.Count) issues)" -FontSize 20 -FontWeight bold
                    New-HTMLText -Text @"
These vulnerabilities result from insecure template or CA configurations that allow certificate abuse.
Examples include weak enrollment restrictions (ESC1, ESC2), SubCA attacks (ESC6), or weak certificate mappings (ESC9).
"@ -Color '#888' -FontSize 14
                }
                New-HTMLPanel {
                    New-HTMLTable -DataTable $misconfigurationIssuesTable `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5', 'searchBuilder', 'searchPanes') `
                        -Title 'Configuration-Based Vulnerabilities' `
                        -DefaultSortColumn 'Technique' {& $issueFormatting}
                }
            }
        }
        
        New-HTMLTab -Name 'Access Control' -IconSolid key -IconColor Green {
            New-HTMLSection -Invisible {
                New-HTMLPanel -Width 10% {
                    New-HTMLText -Text "Dangerous Access Control Issues ($($accessIssues.Count) issues)" -FontSize 20 -FontWeight bold
                    New-HTMLText -Text @"
These vulnerabilities involve principals with excessive write or modify permissions on templates or PKI objects.
ESC4a and ESC5a allow principals to modify certificate templates or infrastructure to create exploitable configurations.
"@ -Color '#888' -FontSize 14
                }
                New-HTMLPanel {
                    New-HTMLTable -DataTable $accessIssuesTable `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5', 'searchBuilder', 'searchPanes') `
                        -Title 'Write/Modify Permission Issues' `
                        -DefaultSortColumn 'ActiveDirectoryRights' {& $issueFormatting}
                }
            }
        }
        
        New-HTMLTab -Name 'Ownership' -IconSolid crown -IconColor Gold {
            New-HTMLSection -Invisible {
                New-HTMLPanel -Width 10% {
                    New-HTMLText -Text "Non-Standard Ownership Issues ($($ownershipIssues.Count) issues)" -FontSize 20 -FontWeight bold
                    New-HTMLText -Text @"
These vulnerabilities involve templates or PKI objects owned by non-standard principals.
Owners have full control and can modify or delete objects. ESC4o and ESC5o identify dangerous ownership configurations.
"@ -Color '#888' -FontSize 14
                }
                New-HTMLPanel {
                    New-HTMLTable -DataTable $ownershipIssuesTable `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5', 'searchBuilder', 'searchPanes') `
                        -Title 'Dangerous Ownership Configurations' `
                        -DefaultSortColumn 'Owner' {& $issueFormatting}
                }
            }
        }
    }
    
    Write-Verbose "Dashboard generated: $FilePath"
    if (-not $Show) {
        Write-Host "Dashboard saved to: $FilePath"
    }
}
