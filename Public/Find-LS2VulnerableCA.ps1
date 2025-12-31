function Find-LS2VulnerableCA {
    <#
    .SYNOPSIS
        Identifies vulnerable AD CS Certification Authorities based on ESC technique definitions.

    .DESCRIPTION
        Reads ESC technique definitions from ESCDefinitions.psd1, queries the AdcsObjectStore
        for matching CAs, and generates issues for configuration problems or dangerous role assignments.
        
        ESC6: Detects CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
        ESC7a: Detects dangerous CA Administrator role assignments
        ESC7m: Detects dangerous Certificate Manager role assignments
        ESC11: Detects CAs that don't require RPC encryption
        ESC16: Detects CAs with disabled CRL/AIA extensions

    .PARAMETER Technique
        ESC technique name to scan for (e.g., 'ESC6', 'ESC7a', 'ESC7m', 'ESC11', 'ESC16')

    .EXAMPLE
        Find-LS2VulnerableCA -Technique ESC6
        Checks for CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.

    .EXAMPLE
        Find-LS2VulnerableCA -Technique ESC7a
        Checks for dangerous CA Administrator role assignments.

    .EXAMPLE
        Find-LS2VulnerableCA -Technique ESC7m
        Checks for dangerous Certificate Manager role assignments.

    .EXAMPLE
        Find-LS2VulnerableCA -Technique ESC7a -ExpandGroups
        Checks for CA Administrator roles and expands group assignments into per-member issues.

    .EXAMPLE
        Find-LS2VulnerableCA -Technique ESC11
        Checks for CAs that don't require RPC encryption.

    .EXAMPLE
        Find-LS2VulnerableCA -Technique ESC16
        Checks for CAs with disabled security extensions in CRL/AIA.

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
        - ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
        - ESC7a: Dangerous CA Administrator role assignments
        - ESC7m: Dangerous Certificate Manager role assignments
        - ESC11: Missing RPC encryption requirement
        - ESC16: Disabled CRL/AIA security extensions

    .LINK
        Find-LS2VulnerableTemplate

    .LINK
        Find-LS2VulnerableObject

    .LINK
        Invoke-Locksmith2
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('ESC6', 'ESC7a', 'ESC7m', 'ESC11', 'ESC16')]
        [string]$Technique,
        
        [Parameter()]
        [string]$Forest,
        
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [switch]$ExpandGroups
    )

    #requires -Version 5.1

    # Ensure stores are initialized and populated
    if (-not (Initialize-LS2Scan -Forest $Forest -Credential $Credential)) {
        return
    }

    # If no technique specified, return all CA issues
    if (-not $Technique) {
        Write-Verbose "No technique specified. Returning all CA issues..."
        $allIssues = Get-FlattenedIssues
        $caTechniques = @('ESC6', 'ESC7a', 'ESC7m', 'ESC11', 'ESC16')
        $caIssues = $allIssues | Where-Object { $_.Technique -in $caTechniques }
        
        if ($ExpandGroups) {
            $caIssues | ForEach-Object { Expand-IssueByGroup $_ }
        } else {
            $caIssues
        }
        return
    }
        return
    }

    # Load all ESC definitions
    $definitionsPath = Join-Path $PSScriptRoot '..\Private\Data\ESCDefinitions.psd1'
    $allDefinitions = Import-PowerShellDataFile -Path $definitionsPath
    $config = $allDefinitions[$Technique]

    Write-Verbose "Scanning for $Technique using definitions from $definitionsPath"

    # Query AdcsObjectStore for CAs
    $allCAs = $script:AdcsObjectStore.Values | Where-Object { $_.objectClass -contains 'pKIEnrollmentService' }
    
    Write-Verbose "Found $($allCAs.Count) Certification Authority object(s) to check"

    $issueCount = 0

    # ESC7a and ESC7m have a different structure (checks role assignments)
    if ($Technique -eq 'ESC7a' -or $Technique -eq 'ESC7m') {
        foreach ($ca in $allCAs) {
            $caName = if ($ca.cn) { $ca.cn } elseif ($ca.Properties -and $ca.Properties.Contains('cn')) { $ca.Properties['cn'][0] } else { 'Unknown CA' }
            Write-Verbose "  Checking CA: $caName"

            # Get CAFullName for certutil commands
            $caFullName = if ($ca.CAFullName) { $ca.CAFullName } else { $null }
            
            if (-not $caFullName) {
                Write-Verbose "    CA '$caName' has no CAFullName property - skipping"
                continue
            }

            # Get forest name from DN
            $forestName = if ($ca.distinguishedName -match 'DC=([^,]+)') {
                $ca.distinguishedName -replace '^.*?DC=(.*)$', '$1' -replace ',DC=', '.'
            } else {
                'Unknown'
            }

            # Check each admin property for problematic principals
            foreach ($adminProperty in $config.AdminProperties) {
                $problematicPrincipals = @($ca.$adminProperty)
                
                if (-not $problematicPrincipals -or $problematicPrincipals.Count -eq 0) {
                    continue
                }

                Write-Verbose "    Found $($problematicPrincipals.Count) problematic principal(s) in $adminProperty"

                # Determine role type
                $isAdministrator = $adminProperty -like '*CAAdministrator*'
                $roleType = if ($isAdministrator) { 'Administrators' } else { 'Officers' }
                
                # Use the IssueTemplate from config (no longer separate templates)
                $issueTemplate = $config.IssueTemplate

                # Create an issue for each problematic principal
                foreach ($principalSid in $problematicPrincipals) {
                    # Resolve principal name from PrincipalStore
                    $identityReference = if ($script:PrincipalStore -and $script:PrincipalStore.ContainsKey($principalSid)) {
                        $script:PrincipalStore[$principalSid].ntAccountName
                    } else {
                        $principalSid
                    }

                    Write-Verbose "      VULNERABLE: $identityReference ($principalSid) has $roleType role"

                    # Join templates if they're arrays
                    $issueTemplateText = if ($issueTemplate -is [array]) {
                        $issueTemplate -join ''
                    } else {
                        $issueTemplate
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

                    # Expand template variables
                    $issueText = $issueTemplateText `
                        -replace '\$\(IdentityReference\)', $identityReference `
                        -replace '\$\(CAName\)', $caName
                    
                    $fixScript = $fixTemplate `
                        -replace '\$\(CAFullName\)', $caFullName `
                        -replace '\$\(IdentityReference\)', $identityReference `
                        -replace '\$\(RoleType\)', $roleType
                    
                    $revertScript = $revertTemplate `
                        -replace '\$\(CAFullName\)', $caFullName `
                        -replace '\$\(IdentityReference\)', $identityReference `
                        -replace '\$\(RoleType\)', $roleType

                    # Create LS2Issue object
                    $issue = [LS2Issue]@{
                        Technique             = $Technique
                        Forest                = $forestName
                        Name                  = $caName
                        DistinguishedName     = $ca.distinguishedName
                        CAFullName            = $caFullName
                        IdentityReference     = $identityReference
                        IdentityReferenceSID  = $principalSid
                        ActiveDirectoryRights = $roleType
                        Issue                 = $issueText
                        Fix                   = $fixScript
                        Revert                = $revertScript
                    }

                    # Initialize IssueStore structure if needed
                    $dn = $ca.distinguishedName
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
        }
    }
    # ESC6, ESC11, and ESC16 are configuration-based (no enrollee/principal iteration)
    else {
        $vulnerableCAs = @(foreach ($ca in $allCAs) {
            $matchesAllConditions = $true
            
            foreach ($condition in $config.Conditions) {
                $propertyValue = $ca.($condition.Property)
                if ($propertyValue -ne $condition.Value) {
                    $matchesAllConditions = $false
                    break
                }
            }
            
            if ($matchesAllConditions) {
                $ca
            }
        })

        Write-Verbose "Found $($vulnerableCAs.Count) CA(s) with $Technique-vulnerable configuration"

        foreach ($ca in $vulnerableCAs) {
            $caName = if ($ca.cn) { $ca.cn } elseif ($ca.Properties -and $ca.Properties.Contains('cn')) { $ca.Properties['cn'][0] } else { 'Unknown CA' }
            Write-Verbose "  VULNERABLE CA: $caName"

            # Get CAFullName for certutil commands
            $caFullName = if ($ca.CAFullName) { $ca.CAFullName } else { $null }
            
            if (-not $caFullName) {
                Write-Verbose "    CA '$caName' has no CAFullName property - skipping issue creation"
                continue
            }

            # Get forest name from DN
            $forestName = if ($ca.distinguishedName -match 'DC=([^,]+)') {
                $ca.distinguishedName -replace '^.*?DC=(.*)$', '$1' -replace ',DC=', '.'
            } else {
                'Unknown'
            }

            # Join templates if they're arrays
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

            # Expand template variables
            $issueText = $issueTemplate `
                -replace '\$\(CAName\)', $caName `
                -replace '\$\(CAFullName\)', $caFullName
            
            $fixScript = $fixTemplate `
                -replace '\$\(CAFullName\)', $caFullName
            
            $revertScript = $revertTemplate `
                -replace '\$\(CAFullName\)', $caFullName

            # Create LS2Issue object
            $issue = [LS2Issue]@{
                Technique         = $Technique
                Forest            = $forestName
                Name              = $caName
                DistinguishedName = $ca.distinguishedName
                CAFullName        = $caFullName
                Issue             = $issueText
                Fix               = $fixScript
                Revert            = $revertScript
            }

            # Initialize IssueStore structure if needed
            $dn = $ca.distinguishedName
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
}
