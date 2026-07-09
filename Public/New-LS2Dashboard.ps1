function New-LS2Dashboard {
    <#
    .SYNOPSIS
    Generates an interactive HTML dashboard for Locksmith2 scan results.

    .DESCRIPTION
    Creates a comprehensive HTML dashboard with left navigation menu showing:
    - All issues with expanded principals
    - Issues filtered by type (Template, CA, Object)
    - Risky principals analysis.

    .PARAMETER FilePath
    Path where the HTML dashboard will be saved.
    Default: Locksmith2-Dashboard.html in the current working directory.

    .PARAMETER Show
    Opens the dashboard in the default browser after generation.
    Defaults to $true when no parameters are specified.

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
        [string]$FilePath,

        [Parameter()]
        [bool]$Show = $true,

        [Parameter()]
        [switch]$ExpandGroups,

        [Parameter()]
        [switch]$Online
    )

    #requires -Version 5.1

    if (-not $FilePath) {
        $fileStamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
        $FilePath = Join-Path (Get-Location) "Locksmith2-Dashboard-$fileStamp.html"
    }

    # Check for PSWriteHTML module (loaded as a NestedModule or installed separately)
    if (-not (Get-Command -Name 'New-HTML' -ErrorAction SilentlyContinue)) {
        Write-Error "PSWriteHTML module is required but was not loaded. Reinstall Locksmith2 or Install-Module PSWriteHTML."
        return
    }

    # Check if IssueStore is populated
    if (-not $script:IssueStore -or $script:IssueStore.Count -eq 0) {
        Write-Warning "IssueStore is empty. Run Invoke-Locksmith2 or Find-LS2Vulnerable* functions first."
        Write-Warning "Generating empty dashboard..."
    }

    $allIssues = Get-FlattenedIssues
    if ($ExpandGroups) {
        Write-Verbose "Expanding group memberships for dashboard..."
        $allIssues = $allIssues | ForEach-Object { Expand-IssueByGroup $_ }
    }

    $standardColumns = @(
        'Technique'
        @{N = 'RiskName';    E = { if ($_.RiskName)          { $_.RiskName }  else { 'Unrated' } } }
        @{N = 'RiskValue';   E = { if ($null -ne $_.RiskValue) { $_.RiskValue } else { 'N/A'    } } }
        'Forest'
        'Name'
        'DistinguishedName'
        @{N = 'ObjectClass';            E = { if ($_.ObjectClass)            { $_.ObjectClass }                    else { 'N/A' } } }
        @{N = 'IdentityReference';      E = { if ($_.IdentityReference)      { $_.IdentityReference }              else { 'N/A' } } }
        @{N = 'IdentityReferenceSID';   E = { if ($_.IdentityReferenceSID)   { $_.IdentityReferenceSID }           else { 'N/A' } } }
        @{N = 'IdentityReferenceClass'; E = { if ($_.IdentityReferenceClass) { $_.IdentityReferenceClass }         else { 'N/A' } } }
        @{N = 'ActiveDirectoryRights';  E = { if ($_.ActiveDirectoryRights)  { $_.ActiveDirectoryRights }          else { 'N/A' } } }
        @{N = 'AceObjectTypeGUID';      E = { if ($_.AceObjectTypeGUID)      { $_.AceObjectTypeGUID }              else { 'N/A' } } }
        @{N = 'AceObjectTypeName';      E = { if ($_.AceObjectTypeName)      { $_.AceObjectTypeName }              else { 'N/A' } } }
        @{N = 'Enabled';                E = { if ($null -ne $_.Enabled)      { $_.Enabled }                        else { 'N/A' } } }
        @{N = 'EnabledOn';              E = { if ($_.EnabledOn)              { $_.EnabledOn -join ', ' }           else { 'N/A' } } }
        @{N = 'CAFullName';             E = { if ($_.CAFullName)             { $_.CAFullName }                     else { 'N/A' } } }
        @{N = 'Owner';                  E = { if ($_.Owner)                  { $_.Owner }                          else { 'N/A' } } }
        @{N = 'HasNonStandardOwner';    E = { if ($null -ne $_.HasNonStandardOwner) { $_.HasNonStandardOwner }    else { 'N/A' } } }
        @{N = 'Members';                E = { if ($_.MemberCount)            { $_.MemberCount }                    else { 'N/A' } } }
        @{N = 'RiskScoring';            E = { if ($_.RiskScoring)            { $_.RiskScoring -join '; ' }         else { 'N/A' } } }
        @{N = 'Issue';                  E = { if ($_.Issue)                  { $_.Issue   -replace "`n", "`n`n" }  else { 'N/A' } } }
        @{N = 'Fix';                    E = { if ($_.Fix)                    { $_.Fix     -replace "`n", "`n`n" }  else { 'N/A' } } }
        @{N = 'Revert';                 E = { if ($_.Revert)                 { $_.Revert  -replace "`n", "`n`n" }  else { 'N/A' } } }
    )

    # Tab definitions — single source of truth for filter, chrome, and table config.
    # Techniques = $null  -> no filter (All Issues).
    # IsPrincipals = $true -> use the principals table and formatting instead of issue table.
    $tabDefs = [ordered]@{
        'All Issues'        = @{ Icon = 'exclamation-triangle'; IconColor = 'Red';    Techniques = $null;                                                          Subtitle = 'All discovered AD CS vulnerabilities with principals expanded';                                             Title = 'All AD CS Security Issues';           SortColumn = 'RiskValue'; SortOrder = 'Descending'; SummaryLabel = 'Issue' }
        'Templates'         = @{ Icon = 'file-contract';        IconColor = 'Orange'; Techniques = @('ESC1','ESC2','ESC3c1','ESC3c2','ESC4a','ESC4o','ESC9');      Subtitle = 'Misconfigured templates allowing SAN abuse, weak enrollment restrictions, or enrollment agent exploitation'; Title = 'Template Vulnerabilities';            SortColumn = 'RiskValue'; SortOrder = 'Descending'; SummaryLabel = 'Template Issue' }
        'CAs'               = @{ Icon = 'certificate';          IconColor = 'Yellow'; Techniques = @('ESC6','ESC7a','ESC7m','ESC8','ESC11','ESC16');               Subtitle = 'Insecure CA configurations and dangerous role assignments (ESC6, ESC7, ESC8, ESC11, ESC16)';             Title = 'CA Configuration Issues';             SortColumn = 'RiskValue'; SortOrder = 'Descending'; SummaryLabel = 'CA Issue' }
        'Objects'           = @{ Icon = 'folder';               IconColor = 'Blue';   Techniques = @('ESC5a','ESC5o');                                             Subtitle = 'Dangerous permissions on PKI infrastructure objects (ESC5)';                                               Title = 'Infrastructure Object Issues';        SortColumn = 'RiskValue'; SortOrder = 'Descending'; SummaryLabel = 'Object Issue' }
        'Risky Principals'  = @{ Icon = 'user-shield';          IconColor = 'Purple'; IsPrincipals = $true;                                                        Subtitle = 'Ranked by number of exploitable AD CS vulnerabilities';                                                                                                              SortColumn = 'IssueCount'; SortOrder = 'Descending' }
        'Dangerous Configurations' = @{ Icon = 'cog';                  IconColor = 'Red';    Techniques = @('ESC1','ESC2','ESC3c1','ESC3c2','ESC6','ESC8','ESC9','ESC11','ESC16'); Subtitle = 'Insecure template/CA configurations enabling certificate abuse (ESC1, ESC2, ESC6, ESC8, ESC9, ESC11, ESC16)'; Title = 'Configuration-Based Vulnerabilities'; SortColumn = 'RiskValue'; SortOrder = 'Descending'; SummaryLabel = 'Configuration Issue' }
        'Access Control'    = @{ Icon = 'key';                  IconColor = 'Green';  Techniques = @('ESC4a','ESC5a');                                             Subtitle = 'Excessive write/modify permissions on templates and PKI objects (ESC4a, ESC5a)';                            Title = 'Write/Modify Permission Issues';       SortColumn = 'RiskValue'; SortOrder = 'Descending'; SummaryLabel = 'Access Control Issue' }
        'Ownership'         = @{ Icon = 'crown';                IconColor = 'Gold';   Techniques = @('ESC4o','ESC5o');                                             Subtitle = 'Non-standard owners with full control over templates or PKI objects (ESC4o, ESC5o)';                      Title = 'Dangerous Ownership Configurations';   SortColumn = 'RiskValue'; SortOrder = 'Descending'; SummaryLabel = 'Ownership Issue' }
    }

    # Build filtered + projected table for each issue tab
    foreach ($tabName in $tabDefs.Keys) {
        $def = $tabDefs[$tabName]
        if ($def.IsPrincipals) { continue }
        $filtered     = if ($def.Techniques) { $allIssues | Where-Object { $_.Technique -in $def.Techniques } } else { $allIssues }
        $def.Issues   = @($filtered)
        $def.Table    = $filtered | Select-Object $standardColumns
    }

    # Principals table (separate schema)
    Write-Verbose "Calculating principal risk scores..."
    $riskyPrincipals = Find-LS2RiskyPrincipal
    $principalsTable = $riskyPrincipals | Select-Object `
        Principal,
        IssueCount,
        @{N = 'Techniques';       E = { $_.Techniques -join ', ' } },
        @{N = 'VulnerableObjects'; E = { $_.VulnerableObjects.Count } }

    $forestName   = if ($script:Forest) { $script:Forest } else { 'Unknown Forest' }
    $generatedAt  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $scanUser     = if ($script:Credential) { $script:Credential.UserName } else { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
    $scanComputer = "$env:USERDOMAIN\$env:COMPUTERNAME"

    # Resolve logo and encode as base64 data URI for self-contained HTML
    $logoSource = $null
    $moduleBase = (Get-Module -Name Locksmith2 -ErrorAction SilentlyContinue).ModuleBase
    if ($null -ne $moduleBase) {
        foreach ($candidate in @(
            (Join-Path $moduleBase 'Images\Locksmith2.png'),
            (Join-Path $moduleBase '..\..\..\Images\Locksmith2.png')
        )) {
            try {
                if (Test-Path -LiteralPath $candidate) {
                    $logoBytes  = [System.IO.File]::ReadAllBytes(
                        (Get-Item -LiteralPath $candidate -ErrorAction Stop).FullName
                    )
                    $logoBase64 = [System.Convert]::ToBase64String($logoBytes)
                    $logoSource = "data:image/png;base64,$logoBase64"
                    break
                }
            } catch {
                Write-Verbose "Logo load failed for '$candidate': $_"
            }
        }
    }

    # Conditional formatting shared by all issue tables
    $issueFormatting = {
        # Template issues (red-purple range)
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC1'  -BackgroundColor '#ffcdd2' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC2'  -BackgroundColor '#f8bbd0' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC4a' -BackgroundColor '#e1bee7' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC4o' -BackgroundColor '#d1c4e9' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC9'  -BackgroundColor '#ce93d8' -Color Black
        # CA issues (yellow-orange range)
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC6'  -BackgroundColor '#fff59d' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC7a' -BackgroundColor '#ffcc80' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC7m' -BackgroundColor '#ffb74d' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC8'  -BackgroundColor '#ffe082' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC11' -BackgroundColor '#ff9800' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC16' -BackgroundColor '#ffa726' -Color Black
        # Object issues (green-blue range)
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC5a' -BackgroundColor '#a5d6a7' -Color Black
        New-HTMLTableCondition -Name 'Technique' -Value 'ESC5o' -BackgroundColor '#80cbc4' -Color Black
        # Rights-based (high severity)
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*GenericAll*'    -BackgroundColor '#d32f2f' -Color White
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*WriteDacl*'     -BackgroundColor '#ef5350' -Color White
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*WriteOwner*'    -BackgroundColor '#ff9800' -Color White
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*WriteProperty*' -BackgroundColor '#ffa726' -Color Black
        New-HTMLTableCondition -Name 'ActiveDirectoryRights' -ComparisonType string -Operator like -Value '*GenericWrite*'  -BackgroundColor '#ffa726' -Color Black
        # Status
        New-HTMLTableCondition -Name 'Enabled' -Value $true -BackgroundColor '#fff9c4' -Color Black
        # Risk rating
        New-HTMLTableCondition -Name 'RiskName' -Value 'Critical'     -BackgroundColor '#b71c1c' -Color White
        New-HTMLTableCondition -Name 'RiskName' -Value 'High'         -BackgroundColor '#e53935' -Color White
        New-HTMLTableCondition -Name 'RiskName' -Value 'Medium'       -BackgroundColor '#ff9800' -Color Black
        New-HTMLTableCondition -Name 'RiskName' -Value 'Low'          -BackgroundColor '#fdd835' -Color Black
        New-HTMLTableCondition -Name 'RiskName' -Value 'Informational'-BackgroundColor '#e3f2fd' -Color Black
    }

    # Conditional formatting for principals (different schema; most severe last so they override)
    $principalFormatting = {
        New-HTMLTableCondition -Name 'IssueCount' -ComparisonType number -Operator ge -Value 1  -BackgroundColor '#fdd835' -Color Black
        New-HTMLTableCondition -Name 'IssueCount' -ComparisonType number -Operator ge -Value 5  -BackgroundColor '#ff9800' -Color White
        New-HTMLTableCondition -Name 'IssueCount' -ComparisonType number -Operator gt -Value 10 -BackgroundColor '#ef5350' -Color White
    }

    # Renders one summary card. Called inside New-HTMLSection.
    # Cards are clickable: they filter the tab's DataTable by RiskName. Clicking the
    # active card again clears the filter. Non-selected cards are faded via CSS class.
    $summaryCard = {
        param(
            [string]$Label,
            [string]$Value,
            [string]$Color,
            [string]$TableId,
            [string]$FilterValue,
            [string]$CardClass = 'summary-card'
        )
        New-HTMLTag -Tag 'div' -Attributes @{ class = "$CardClass summary-card-clickable"; 'data-filter' = $FilterValue; 'data-table-id' = $TableId } {
            New-HTMLPanel {
                New-HTMLText -Text $Label -FontSize 12 -Color '#888' -Alignment center
                New-HTMLText -Text $Value -FontSize 32 -FontWeight bold -Color $Color -Alignment center
            }
        }
    }

    $tableButtons = @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5', 'searchBuilder', 'searchPanes')

    New-HTML -TitleText "Locksmith 2 Dashboard - $forestName - $generatedAt" -Online:$Online -FilePath $FilePath -Show:$Show {

        # Persistent header — logo + collection context. New-HTMLHeader renders outside the tab
        # container and does not create a tab-content slot (unlike New-HTMLSection/Panel at this level).
        New-HTMLHeader {
            Add-HTMLStyle -Content @'
header { text-align: center; padding: 12px 0; }
header img { max-width: 50%; height: auto; display: inline-block; }
.summary-section { display: flex; flex-wrap: wrap; gap: 12px; width: 100%; }
.summary-card { display: flex; flex: 1 1 0; min-width: 140px; cursor: pointer; transition: opacity 0.2s ease-in-out, transform 0.1s ease-in-out; }
.summary-card > .flexPanel { width: 100%; }
.summary-card:hover { opacity: 1 !important; transform: translateY(-2px); }
.summary-card-active > .flexPanel { outline: 2px solid #333; }
.summary-section:has(.summary-card-active) .summary-card:not(.summary-card-active) { opacity: 0.45; }
'@
            if ($logoSource) {
                New-HTMLImage -Source $logoSource -Width '50%' -AlternativeText 'Locksmith 2'
            }
            New-HTMLText -Text "Forest: $forestName  |  User: $scanUser  |  Computer: $scanComputer  |  Generated: $generatedAt" -FontSize 12 -Color '#555' -Alignment center
        }

        # NOTE: No New-HTMLSection/Panel before the first New-HTMLTab — PSWriteHTML counts every
        # top-level content block as a tab-content slot, shifting click handlers off by one.
        New-HTMLTabStyle -SlimTabs -SelectorColor Magenta

        foreach ($tabName in $tabDefs.Keys) {
            $def = $tabDefs[$tabName]
            $tableId = if ($def.IsPrincipals) { $null } else { 'IssuesTable-' + ($tabName -replace '\s+', '-' -replace '[^A-Za-z0-9-]', '') }
            New-HTMLTab -Name $tabName -IconSolid $def.Icon -IconColor $def.IconColor {
                if ($def.IsPrincipals) {
                    New-HTMLTable -DataTable $principalsTable `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons $tableButtons `
                        -Title 'Principals by Risk Score' `
                        -DefaultSortColumn $def.SortColumn `
                        -DefaultSortOrder $def.SortOrder {& $principalFormatting}
                    New-HTMLHorizontalLine
                    New-HTMLText -Text "$(@($principalsTable).Count) principals  --  $($def.Subtitle)" -Color '#666' -FontSize 13 -FontStyle italic
                } else {
                    if ($def.Issues.Count -gt 0) {
                        $tabRiskNames = foreach ($issue in $def.Issues) {
                            if ($issue.RiskName) { $issue.RiskName } else { 'Unrated' }
                        }
                        $tabRiskGroups = $tabRiskNames | Group-Object -NoElement
                        $tabRiskCountMap = @{}
                        foreach ($group in $tabRiskGroups) {
                            $tabRiskCountMap[$group.Name] = $group.Count
                        }

                        $tabTotal      = $def.Issues.Count
                        $tabCritical   = if ($tabRiskCountMap.ContainsKey('Critical'))     { $tabRiskCountMap['Critical'] }     else { 0 }
                        $tabHigh       = if ($tabRiskCountMap.ContainsKey('High'))         { $tabRiskCountMap['High'] }         else { 0 }
                        $tabMedium     = if ($tabRiskCountMap.ContainsKey('Medium'))       { $tabRiskCountMap['Medium'] }       else { 0 }
                        $tabLow        = if ($tabRiskCountMap.ContainsKey('Low'))          { $tabRiskCountMap['Low'] }          else { 0 }
                        $tabInfo       = if ($tabRiskCountMap.ContainsKey('Informational')) { $tabRiskCountMap['Informational'] } else { 0 }

                        New-HTMLSection -HeaderText 'Scan Summary' -Content {
                            New-HTMLTag -Tag 'div' -Attributes @{ class = 'summary-section'; 'data-table-id' = $tableId } {
                                & $summaryCard -Label "Total $($def.SummaryLabel)s" -Value $tabTotal -Color '#333' -TableId $tableId -FilterValue ''
                                & $summaryCard -Label 'Critical' -Value $tabCritical -Color '#b71c1c' -TableId $tableId -FilterValue 'Critical'
                                & $summaryCard -Label 'High' -Value $tabHigh -Color '#e53935' -TableId $tableId -FilterValue 'High'
                                & $summaryCard -Label 'Medium' -Value $tabMedium -Color '#ff9800' -TableId $tableId -FilterValue 'Medium'
                                & $summaryCard -Label 'Low' -Value $tabLow -Color '#fdd835' -TableId $tableId -FilterValue 'Low'
                                & $summaryCard -Label 'Informational' -Value $tabInfo -Color '#1976d2' -TableId $tableId -FilterValue 'Informational'
                            }
                            Add-HTMLScript -Content "
document.addEventListener('DOMContentLoaded', function() {
    var section = document.querySelector('.summary-section[data-table-id=\'$tableId\']');
    if (!section) return;
    section.addEventListener('click', function(e) {
        var card = e.target.closest('.summary-card');
        if (!card) return;
        var tableId = section.getAttribute('data-table-id');
        var table = document.getElementById(tableId);
        if (!table) return;
        var dt = (window.jQuery && jQuery.fn.DataTable) ? jQuery(table).DataTable() : null;
        if (!dt) return;
        var filter = card.getAttribute('data-filter') || '';
        if (filter === '') {
            section.querySelectorAll('.summary-card').forEach(function(c) { c.classList.remove('summary-card-active'); });
            dt.column(1).search('').draw();
            return;
        }
        card.classList.toggle('summary-card-active');
        var activeFilters = [];
        section.querySelectorAll('.summary-card.summary-card-active').forEach(function(c) {
            var f = c.getAttribute('data-filter');
            if (f) { activeFilters.push(f); }
        });
        if (activeFilters.length === 0) {
            dt.column(1).search('').draw();
        } else {
            var pattern = activeFilters.map(function(f) { return '^' + f.replace(/[-[\]{}()*+?.,\\\\^$|#\s]/g, '\\\\$&') + '$'; }).join('|');
            dt.column(1).search(pattern, true, false).draw();
        }
    });
});
"
                        }
                        New-HTMLHorizontalLine
                    }

                    New-HTMLTable -DataTable $def.Table `
                        -DataTableID $tableId `
                        -Filtering `
                        -PagingLength 25 `
                        -Buttons $tableButtons `
                        -Title $def.Title `
                        -DefaultSortColumn $def.SortColumn `
                        -DefaultSortOrder $def.SortOrder {& $issueFormatting}
                    New-HTMLHorizontalLine
                    New-HTMLText -Text "$($def.Issues.Count) issues  --  $($def.Subtitle)" -Color '#666' -FontSize 13 -FontStyle italic
                }
            }
        }
    }

    Write-Verbose "Dashboard generated: $FilePath"
    if (-not $Show) {
        Write-Host "Dashboard saved to: $FilePath"
    }
}
