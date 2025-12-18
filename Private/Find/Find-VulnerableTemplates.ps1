function Find-VulnerableTemplates {
    <#
    .SYNOPSIS
        Identifies vulnerable AD CS templates based on ESC technique definitions.

    .DESCRIPTION
        Reads ESC technique definitions from ESCDefinitions.psd1, queries the AdcsObjectStore
        for matching templates, and generates issues for problematic enrollees.

    .PARAMETER Technique
        ESC technique name to scan for (e.g., 'ESC1', 'ESC2', 'ESC3C1', 'ESC3C2')

    .EXAMPLE
        Find-VulnerableTemplates -Technique ESC1

    .OUTPUTS
        LS2Issue objects for each vulnerability found
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ESC1', 'ESC2', 'ESC3C1', 'ESC3C2', 'ESC9')]
        [string]$Technique
    )

    # Load all ESC definitions
    $definitionsPath = Join-Path $PSScriptRoot '..\Data\ESCDefinitions.psd1'
    $allDefinitions = Import-PowerShellDataFile -Path $definitionsPath
    $config = $allDefinitions[$Technique]

    Write-Verbose "Scanning for $Technique using definitions from $definitionsPath"

    # Query AdcsObjectStore for templates, then filter by conditions
    $allTemplates = $script:AdcsObjectStore.Values | Where-Object { $_.IsCertificateTemplate() }
    
    $vulnerableTemplates = foreach ($template in $allTemplates) {
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
    }

    Write-Verbose "Found $($vulnerableTemplates.Count) template(s) with $technique-vulnerable configuration"

    $issueCount = 0

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
            if (-not $script:IssueStore.ContainsKey($dn)) {
                $script:IssueStore[$dn] = @{}
            }
            if (-not $script:IssueStore[$dn].ContainsKey($technique)) {
                $script:IssueStore[$dn][$technique] = @()
            }
            
            # Store in IssueStore
            $script:IssueStore[$dn][$technique] += $issue
            $issueCount++

            # Output to pipeline
            $issue
        }
    }

    Write-Verbose "$technique scan complete. Found $issueCount issue(s)."
}
