function Find-LS2VulnerableTemplate {
    <#
    .SYNOPSIS
        Identifies vulnerable AD CS templates based on ESC technique definitions.

    .DESCRIPTION
        Reads ESC technique definitions from ESCDefinitions.psd1, queries the AdcsObjectStore
        for matching templates, and generates issues for problematic enrollees.

    .PARAMETER Technique
        ESC technique name to scan for (e.g., 'ESC1', 'ESC2', 'ESC3c1', 'ESC3c2')

    .EXAMPLE
        Find-LS2VulnerableTemplate -Technique ESC1
        Scans for templates vulnerable to ESC1 (misconfigured certificate templates).

    .EXAMPLE
        Find-LS2VulnerableTemplate -Technique ESC2
        Scans for templates vulnerable to ESC2 (certificate SubCA abuse).

    .EXAMPLE
        $esc1Issues = Find-LS2VulnerableTemplate -Technique ESC1 -Verbose
        Scans for ESC1 issues with verbose output, stores issues in $esc1Issues variable.

    .EXAMPLE
        Find-LS2VulnerableTemplate -Technique ESC1 -ExpandGroups
        Scans for ESC1 issues and expands group principals into individual per-member issues.

    .OUTPUTS
        LS2Issue
        LS2Issue objects for each vulnerability found.

    .NOTES
        Author: Jake Hildreth (@jakehildreth)
        Module: Locksmith2
        Requires: PowerShell 5.1+
        
        Requires script-scope variables set by Invoke-Locksmith2:
        - $script:AdcsObjectStore: Cache of AD CS objects
        - $script:PrincipalStore: Cache of resolved principals
        
        Supported techniques:
        - ESC1: Certificate Request Agent abuse
        - ESC2: Misconfigured Certificate Templates
        - ESC3c1/ESC3c2: Enrollment Agent restrictions
        - ESC4a/ESC4o: Vulnerable ACLs on templates
        - ESC9: Weak Certificate Mappings

    .LINK
        Find-LS2VulnerableCA

    .LINK
        Find-LS2VulnerableObject

    .LINK
        Invoke-Locksmith2
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC9', 'ESC4a', 'ESC4o')]
        [string]$Technique,
        
        [Parameter()]
        [string]$Forest,
        
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [switch]$ExpandGroups,
        
        [Parameter()]
        [switch]$Rescan
    )

    # Ensure stores are initialized and populated
    $initParams = @{}
    if ($PSBoundParameters.ContainsKey('Forest')) { $initParams['Forest'] = $Forest }
    if ($PSBoundParameters.ContainsKey('Credential')) { $initParams['Credential'] = $Credential }
    if ($Rescan) { $initParams['Rescan'] = $true }
    
    if (-not (Initialize-LS2Scan @initParams)) {
        return
    }

    # If no technique specified, return all template issues
    if (-not $Technique) {
        Write-Verbose "No technique specified. Returning all template issues..."
        $allIssues = Get-FlattenedIssues
        $templateTechniques = @('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC9', 'ESC4a', 'ESC4o')
        $templateIssues = $allIssues | Where-Object { $_.Technique -in $templateTechniques }
        
        if ($ExpandGroups) {
            $templateIssues | ForEach-Object { Expand-IssueByGroup $_ }
        } else {
            $templateIssues
        }
        return
    }

    # Load all ESC definitions
    $definitionsPath = Join-Path $PSScriptRoot '..\Private\Data\ESCDefinitions.psd1'
    $allDefinitions = Import-PowerShellDataFile -Path $definitionsPath
    $config = $allDefinitions[$Technique]

    Write-Verbose "Scanning for $Technique using definitions from $definitionsPath"

    # Query AdcsObjectStore for templates, then filter by conditions
    $allTemplates = $script:AdcsObjectStore.Values | Where-Object { $_.IsCertificateTemplate() }
    
    $vulnerableTemplates = @(foreach ($template in $allTemplates) {
        $matchesAllConditions = $true
        
        foreach ($condition in $config.Conditions) {
            $propertyValue = $template.($condition.Property)
            if ($propertyValue -ne $condition.Value) {
                $matchesAllConditions = $false
                break
            }
        }
        
        if ($matchesAllConditions) {
            $template
        }
    })

    Write-Verbose "Found $($vulnerableTemplates.Count) template(s) with $technique-vulnerable configuration"

    $issueCount = 0

    # ESC4a: ACE-based template editor detection
    if ($Technique -eq 'ESC4a') {
        foreach ($template in $vulnerableTemplates) {
            Write-Verbose "  Checking editors on template: $($template.Name)"

            # Get problematic editors based on config
            $problematicEditors = @()
            foreach ($editorProperty in $config.EditorProperties) {
                $problematicEditors += @($template.$editorProperty)
            }
            $problematicEditors = @($problematicEditors | Select-Object -Unique)

            if ($problematicEditors.Count -eq 0) {
                Write-Verbose "    No problematic editors found"
                continue
            }

            Write-Verbose "    Found $($problematicEditors.Count) problematic editor(s)"

            # Check ObjectSecurity for ACE details
            if (-not $template.ObjectSecurity) {
                Write-Verbose "    No ObjectSecurity available for template: $($template.Name)"
                continue
            }

            # For each problematic editor, find their ACE and create an issue
            foreach ($editorSid in $problematicEditors) {
                # Find the ACE for this SID
                $ace = $template.ObjectSecurity.Access | Where-Object {
                    $aceSid = ($_.IdentityReference | Convert-IdentityReferenceToSid).Value
                    $aceSid -eq $editorSid
                } | Select-Object -First 1

                if (-not $ace) {
                    Write-Verbose "    Could not find ACE for SID: $editorSid"
                    continue
                }

                Write-Verbose "    VULNERABLE: $($ace.IdentityReference) ($editorSid) has write rights"

                # Get domain/forest name from DN
                $forestName = if ($template.distinguishedName -match 'DC=([^,]+)') {
                    $template.distinguishedName -replace '^.*?DC=(.*)$', '$1' -replace ',DC=', '.'
                } else {
                    'Unknown'
                }

                # Join templates if they're arrays, then expand variables
                $issueTemplate = if ($config.IssueTemplate -is [array]) {
                    $config.IssueTemplate -join ''
                } else {
                    $config.IssueTemplate
                }
                
                $fixTemplate = if ($config.FixTemplate -is [array]) {
                    $config.FixTemplate -join "`n"
                } else {
                    $config.FixTemplate
                }
                
                $revertTemplate = if ($config.RevertTemplate -is [array]) {
                    $config.RevertTemplate -join "`n"
                } else {
                    $config.RevertTemplate
                }

                # Expand template variables in Issue, Fix, and Revert strings
                $issueText = $issueTemplate `
                    -replace '\$\(IdentityReference\)', $ace.IdentityReference `
                    -replace '\$\(TemplateName\)', $template.Name `
                    -replace '\$\(ActiveDirectoryRights\)', $ace.ActiveDirectoryRights
                
                $fixScript = $fixTemplate `
                    -replace '\$\(DistinguishedName\)', $template.distinguishedName `
                    -replace '\$\(IdentityReference\)', $ace.IdentityReference
                
                $revertScript = $revertTemplate `
                    -replace '\$\(DistinguishedName\)', $template.distinguishedName

                # Create LS2Issue object
                $issue = [LS2Issue]@{
                    Technique             = $technique
                    Forest                = $forestName
                    Name                  = $template.Name
                    DistinguishedName     = $template.distinguishedName
                    IdentityReference     = $ace.IdentityReference
                    IdentityReferenceSID  = $editorSid
                    ActiveDirectoryRights = $ace.ActiveDirectoryRights
                    Enabled               = $template.Enabled
                    EnabledOn             = $template.EnabledOn
                    Issue                 = $issueText
                    Fix                   = $fixScript
                    Revert                = $revertScript
                }

                # Store in IssueStore
                $dn = $template.distinguishedName
                if (-not $script:IssueStore) {
                    $script:IssueStore = @{}
                }
                if (-not $script:IssueStore.ContainsKey($dn)) {
                    $script:IssueStore[$dn] = @{}
                }
                if (-not $script:IssueStore[$dn].ContainsKey($Technique)) {
                    $script:IssueStore[$dn][$Technique] = @()
                }
                
                # Only add to store if not a duplicate
                if (-not (Test-IssueExists -Issue $issue -DistinguishedName $dn -Technique $Technique)) {
                    $script:IssueStore[$dn][$Technique] += $issue
                    $issueCount++
                }

                # Always output to pipeline
                if ($ExpandGroups) {
                    Expand-IssueByGroup -Issue $issue
                } else {
                    $issue
                }
            }
        }
        Write-Verbose "$Technique scan complete. Found $issueCount issue(s)."
        return
    }

    # ESC4o: Ownership-based detection (no enrollee checking needed)
    if ($Technique -eq 'ESC4o') {
        foreach ($template in $vulnerableTemplates) {
            $templateName = if ($template.displayName) { $template.displayName } else { $template.Name }
            $owner = if ($template.Owner) { $template.Owner } else { 'Unknown' }

            Write-Verbose "  Checking template: $templateName"

            # Create issue using template expansion
            $issueText = ($config.IssueTemplate -join '') `
                -replace '\$\(TemplateName\)', $templateName `
                -replace '\$\(Owner\)', $owner

            $fixScript = ($config.FixTemplate -join "`n") `
                -replace '\$\(DistinguishedName\)', $template.distinguishedName

            $revertScript = ($config.RevertTemplate -join "`n") `
                -replace '\$\(DistinguishedName\)', $template.distinguishedName `
                -replace '\$\(OriginalOwner\)', $owner

            # Create issue object
            $issue = [LS2Issue]::new(@{
                Technique          = $Technique
                Forest             = $script:ForestContext.RootDomain
                Name               = $templateName
                DistinguishedName  = $template.distinguishedName
                Owner              = $owner
                HasNonStandardOwner = $true
                Enabled            = $template.Enabled
                EnabledOn          = $template.EnabledOn
                Issue              = $issueText
                Fix                = $fixScript
                Revert             = $revertScript
            })

            # Store in IssueStore
            $dn = $template.distinguishedName
            if (-not $script:IssueStore) {
                $script:IssueStore = @{}
            }
            if (-not $script:IssueStore.ContainsKey($dn)) {
                $script:IssueStore[$dn] = @{}
            }
            if (-not $script:IssueStore[$dn].ContainsKey($Technique)) {
                $script:IssueStore[$dn][$Technique] = @()
            }
            
            # Only add to store if not a duplicate
            if (-not (Test-IssueExists -Issue $issue -DistinguishedName $dn -Technique $Technique)) {
                $script:IssueStore[$dn][$Technique] += $issue
                $issueCount++
            }

            # Always output to pipeline
            if ($ExpandGroups) {
                Expand-IssueByGroup -Issue $issue
            } else {
                $issue
            }
        }
        Write-Verbose "$Technique scan complete. Found $issueCount issue(s)."
        return
    }

    # Standard enrollee-based detection for other ESC techniques
    foreach ($template in $vulnerableTemplates) {
        Write-Verbose "  Checking enrollees on template: $($template.Name)"

        # Get problematic enrollees based on config
        $problematicEnrollees = @()
        foreach ($enrolleeProperty in $config.EnrolleeProperties) {
            $problematicEnrollees += @($template.$enrolleeProperty)
        }
        $problematicEnrollees = @($problematicEnrollees | Select-Object -Unique)

        if ($problematicEnrollees.Count -eq 0) {
            Write-Verbose "    No problematic enrollees found"
            continue
        }

        Write-Verbose "    Found $($problematicEnrollees.Count) problematic enrollee(s)"

        # Check ObjectSecurity for ACE details
        if (-not $template.ObjectSecurity) {
            Write-Verbose "    No ObjectSecurity available for template: $($template.Name)"
            continue
        }

        # For each problematic enrollee, find their ACE and create an issue
        foreach ($enrolleeSid in $problematicEnrollees) {
            # Find the ACE for this SID
            $ace = $template.ObjectSecurity.Access | Where-Object {
                $aceSid = ($_.IdentityReference | Convert-IdentityReferenceToSid).Value
                $aceSid -eq $enrolleeSid
            } | Select-Object -First 1

            if (-not $ace) {
                Write-Verbose "    Could not find ACE for SID: $enrolleeSid"
                continue
            }

            Write-Verbose "    VULNERABLE: $($ace.IdentityReference) ($enrolleeSid) has enrollment rights"

            # Get domain/forest name from DN
            $forestName = if ($template.distinguishedName -match 'DC=([^,]+)') {
                $template.distinguishedName -replace '^.*?DC=(.*)$', '$1' -replace ',DC=', '.'
            } else {
                'Unknown'
            }

            # Join templates if they're arrays, then expand variables
            $issueTemplate = if ($config.IssueTemplate -is [array]) {
                $config.IssueTemplate -join ''
            } else {
                $config.IssueTemplate
            }
            
            $fixTemplate = if ($config.FixTemplate -is [array]) {
                $config.FixTemplate -join "`n"
            } else {
                $config.FixTemplate
            }
            
            $revertTemplate = if ($config.RevertTemplate -is [array]) {
                $config.RevertTemplate -join "`n"
            } else {
                $config.RevertTemplate
            }

            # Expand template variables in Issue, Fix, and Revert strings
            $issueText = $issueTemplate `
                -replace '\$\(IdentityReference\)', $ace.IdentityReference `
                -replace '\$\(TemplateName\)', $template.Name
            
            $fixScript = $fixTemplate `
                -replace '\$\(DistinguishedName\)', $template.distinguishedName
            
            $revertScript = $revertTemplate `
                -replace '\$\(DistinguishedName\)', $template.distinguishedName

            # Create LS2Issue object
            $issue = [LS2Issue]@{
                Technique             = $technique
                Forest                = $forestName
                Name                  = $template.Name
                DistinguishedName     = $template.distinguishedName
                IdentityReference     = $ace.IdentityReference
                IdentityReferenceSID  = $enrolleeSid
                ActiveDirectoryRights = $ace.ActiveDirectoryRights
                Enabled               = $template.Enabled
                EnabledOn             = $template.EnabledOn
                Issue                 = $issueText
                Fix                   = $fixScript
                Revert                = $revertScript
            }

            # Initialize IssueStore structure if needed
            $dn = $template.distinguishedName
            if (-not $script:IssueStore) {
                $script:IssueStore = @{}
            }
            if (-not $script:IssueStore.ContainsKey($dn)) {
                $script:IssueStore[$dn] = @{}
            }
            if (-not $script:IssueStore[$dn].ContainsKey($technique)) {
                $script:IssueStore[$dn][$technique] = @()
            }
            
            # Only add to store if not a duplicate
            if (-not (Test-IssueExists -Issue $issue -DistinguishedName $dn -Technique $technique)) {
                $script:IssueStore[$dn][$technique] += $issue
                $issueCount++
            }

            # Always output to pipeline
            if ($ExpandGroups) {
                Expand-IssueByGroup -Issue $issue
            } else {
                $issue
            }
        }
    }

    Write-Verbose "$technique scan complete. Found $issueCount issue(s)."
}
