function Find-LS2VulnerableCA {
    <#
    .SYNOPSIS
        Identifies vulnerable AD CS Certification Authorities based on ESC technique definitions.

    .DESCRIPTION
        Uses ESC technique definitions loaded at module initialization, queries the AdcsObjectStore
        for matching CAs, and generates issues for configuration problems or dangerous role assignments.
        
        ESC6: Detects CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
        ESC7a: Detects dangerous CA Administrator role assignments
        ESC7m: Detects dangerous Certificate Manager role assignments
        ESC8: Detects vulnerable web enrollment endpoints (HTTP always; HTTPS if NTLM offered or EPA not required)
        ESC11: Detects CAs that don't require RPC encryption
        ESC16: Detects CAs with disabled CRL/AIA extensions

    .PARAMETER Technique
        ESC technique name to scan for (e.g., 'ESC6', 'ESC7a', 'ESC7m', 'ESC8', 'ESC11', 'ESC16')

    .PARAMETER Forest
        Fully qualified domain name of the target AD forest. If not specified, uses the value already
        set in module scope or auto-detected by Resolve-LS2ConnectionContext.

    .PARAMETER Credential
        PSCredential for authenticating to Active Directory. If not specified, uses the credential
        already set in module scope or the current user's identity.

    .PARAMETER ExpandGroups
        When specified, expands group principals in discovered issues into individual per-member issues.

    .PARAMETER Rescan
        Forces a fresh vulnerability scan even if the IssueStore is already populated.

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
        - ESC8: Vulnerable web enrollment endpoints
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
        [ValidateSet('ESC6', 'ESC7a', 'ESC7m', 'ESC8', 'ESC11', 'ESC16', 'Auditing')]
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

    #requires -Version 5.1

    # Ensure stores are initialized and populated
    $initParams = @{}
    if ($PSBoundParameters.ContainsKey('Forest')) { $initParams['Forest'] = $Forest }
    if ($PSBoundParameters.ContainsKey('Credential')) { $initParams['Credential'] = $Credential }
    if ($Rescan) { $initParams['Rescan'] = $true }
    
    if (-not (Initialize-LS2Scan @initParams)) {
        return
    }

    # If no technique specified, return all CA issues
    if (-not $Technique) {
        Write-Verbose "No technique specified. Returning all CA issues..."
        $allIssues = Get-FlattenedIssues
        $caTechniques = @('ESC6', 'ESC7a', 'ESC7m', 'ESC8', 'ESC11', 'ESC16', 'Auditing')
        $caIssues = $allIssues | Where-Object { $_.Technique -in $caTechniques }
        
        if ($ExpandGroups) {
            $caIssues | ForEach-Object { Expand-IssueByGroup $_ }
        } else {
            $caIssues
        }
        return
    }

    if (-not $script:ESCDefinitions) {
        Write-Warning 'ESCDefinitions not initialized. Cannot scan for vulnerabilities.'
        return
    }
    $config = $script:ESCDefinitions[$Technique]

    Write-Verbose "Scanning for $Technique"

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

                    # Get principal objectClass from PrincipalStore
                    $principalObjectClass = if ($script:PrincipalStore -and $script:PrincipalStore.ContainsKey($principalSid)) {
                        $script:PrincipalStore[$principalSid].objectClass
                    } else {
                        $null
                    }
                    
                    # Create LS2Issue object
                    $issue = [LS2Issue]@{
                        Technique              = $Technique
                        Forest                 = $forestName
                        Name                   = $caName
                        DistinguishedName      = $ca.distinguishedName
                        ObjectClass            = 'pKIEnrollmentService'
                        CAFullName             = $caFullName
                        IdentityReference      = $identityReference
                        IdentityReferenceSID   = $principalSid
                        IdentityReferenceClass = $principalObjectClass
                        ActiveDirectoryRights  = $roleType
                        Issue                  = $issueText
                        Fix                    = $fixScript
                        Revert                 = $revertScript
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
    # ESC8: endpoint-based (one issue per vulnerable web enrollment endpoint)
    elseif ($Technique -eq 'ESC8') {
        $fixText = if ($config.FixTemplate -is [array]) { $config.FixTemplate -join "`n" } else { $config.FixTemplate }
        $revertText = if ($config.RevertTemplate -is [array]) { $config.RevertTemplate -join "`n" } else { $config.RevertTemplate }

        foreach ($ca in $allCAs) {
            $caName = if ($ca.cn) { $ca.cn } else { 'Unknown CA' }
            $caFullName = $ca.CAFullName
            if (-not $caFullName) {
                Write-Verbose "  CA '$caName' has no CAFullName - skipping ESC8 check"
                continue
            }

            $forestName = if ($ca.distinguishedName -match 'DC=([^,]+)') {
                $ca.distinguishedName -replace '^.*?DC=(.*)$', '$1' -replace ',DC=', '.'
            } else {
                'Unknown'
            }

            $endpoints = @($ca.WebEnrollmentEndpoints)
            if (-not $endpoints -or $endpoints.Count -eq 0) {
                Write-Verbose "  CA '$caName' has no web enrollment endpoints"
                continue
            }

            foreach ($endpoint in $endpoints) {
                $url = $endpoint.URL
                $isHttp = $url -match '^http://'

                # Determine if this endpoint is vulnerable
                $vulnerable = $false
                if ($isHttp) {
                    $vulnerable = $true
                } elseif ($endpoint.NtlmOffered -eq $true -or $endpoint.EpaNotRequired -eq $true) {
                    $vulnerable = $true
                }

                if (-not $vulnerable) {
                    Write-Verbose "  Endpoint $url is not vulnerable - skipping"
                    continue
                }

                # Build issue text describing the applicable attack vectors
                if ($isHttp) {
                    $issueText = "The web enrollment endpoint at $url uses plain HTTP and is vulnerable to NTLM relay attacks.`n`n" +
                        "Any attacker who can intercept network traffic can relay NTLM credentials to this endpoint " +
                        "and request a certificate on behalf of the victim.`n`nMore info:`n  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
                } else {
                    $vectors = @()
                    if ($endpoint.NtlmOffered -eq $true) { $vectors += 'NTLM relay (NTLM offered on HTTPS endpoint)' }
                    if ($endpoint.EpaNotRequired -eq $true) { $vectors += 'Kerberos relay (EPA not required)' }
                    $vectorList = $vectors -join ' and '
                    $issueText = "The web enrollment endpoint at $url is vulnerable to $vectorList.`n`n" +
                        "An attacker who can intercept network traffic can relay credentials to this endpoint " +
                        "and request a certificate on behalf of the victim.`n`nMore info:`n  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
                }

                $issue = [LS2Issue]@{
                    Technique         = 'ESC8'
                    Forest            = $forestName
                    Name              = $caName
                    DistinguishedName = $ca.distinguishedName
                    ObjectClass       = 'pKIEnrollmentService'
                    CAFullName        = $caFullName
                    Issue             = $issueText
                    Fix               = $fixText
                    Revert            = $revertText
                }

                $dn = $ca.distinguishedName
                $issueKey = "ESC8:$url"
                if (-not $script:IssueStore) { $script:IssueStore = @{} }
                if (-not $script:IssueStore.ContainsKey($dn)) { $script:IssueStore[$dn] = @{} }
                if (-not $script:IssueStore[$dn].ContainsKey($issueKey)) { $script:IssueStore[$dn][$issueKey] = @() }

                if (-not (Test-IssueExists -Issue $issue -DistinguishedName $dn -Technique $Technique)) {
                    $script:IssueStore[$dn][$issueKey] += $issue
                    $issueCount++
                }

                $issue
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
                -replace '\$\(CAFullName\)', $caFullName `
                -replace '\$\(AuditFilter\)', $ca.AuditFilter
            
            $fixScript = $fixTemplate `
                -replace '\$\(CAFullName\)', $caFullName
            
            $revertScript = $revertTemplate `
                -replace '\$\(CAFullName\)', $caFullName `
                -replace '\$\(AuditFilter\)', $ca.AuditFilter

            # Create LS2Issue object
            $issue = [LS2Issue]@{
                Technique         = $Technique
                Forest            = $forestName
                Name              = $caName
                DistinguishedName = $ca.distinguishedName
                ObjectClass       = 'pKIEnrollmentService'
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
