function Find-LS2VulnerableCA {
    <#
    .SYNOPSIS
        Identifies vulnerable AD CS Certification Authorities based on ESC technique definitions.

    .DESCRIPTION
        Reads ESC technique definitions from ESCDefinitions.psd1, queries the AdcsObjectStore
        for matching CAs, and generates issues for configuration problems or dangerous role assignments.
        
        ESC6: Detects CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled
        ESC7: Detects dangerous CA Administrator and Certificate Manager role assignments
        ESC11: Detects CAs that don't require RPC encryption
        ESC16: Detects CAs with disabled CRL/AIA extensions

    .PARAMETER Technique
        ESC technique name to scan for (e.g., 'ESC6', 'ESC7', 'ESC11', 'ESC16')

    .EXAMPLE
        Find-VulnerableCA -Technique ESC6
        Checks for CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.

    .EXAMPLE
        Find-VulnerableCA -Technique ESC7
        Checks for dangerous CA Administrator and Certificate Manager role assignments.

    .EXAMPLE
        Find-VulnerableCA -Technique ESC11
        Checks for CAs that don't require RPC encryption.

    .OUTPUTS
        LS2Issue objects for each vulnerability found
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ESC6', 'ESC7', 'ESC11', 'ESC16')]
        [string]$Technique
    )

    #requires -Version 5.1

    # Load all ESC definitions
    $definitionsPath = Join-Path $PSScriptRoot '..\Private\Data\ESCDefinitions.psd1'
    $allDefinitions = Import-PowerShellDataFile -Path $definitionsPath
    $config = $allDefinitions[$Technique]

    Write-Verbose "Scanning for $Technique using definitions from $definitionsPath"

    # Query AdcsObjectStore for CAs
    $allCAs = $script:AdcsObjectStore.Values | Where-Object { $_.objectClass -contains 'pKIEnrollmentService' }
    
    Write-Verbose "Found $($allCAs.Count) Certification Authority object(s) to check"

    $issueCount = 0

    # ESC7 has a different structure (checks role assignments)
    if ($Technique -eq 'ESC7') {
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

                # Determine role type and issue template
                $isAdministrator = $adminProperty -like '*CAAdministrator*'
                $issueTemplate = if ($isAdministrator) {
                    $config.IssueTemplateCAAdmin
                } else {
                    $config.IssueTemplateCertManager
                }
                $roleType = if ($isAdministrator) { 'Administrators' } else { 'Officers' }

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
                    if (-not $script:IssueStore.ContainsKey($dn)) {
                        $script:IssueStore[$dn] = @{}
                    }
                    if (-not $script:IssueStore[$dn].ContainsKey($Technique)) {
                        $script:IssueStore[$dn][$Technique] = @()
                    }
                    
                    # Store in IssueStore
                    $script:IssueStore[$dn][$Technique] += $issue
                    $issueCount++

                    # Output to pipeline
                    $issue
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
            if (-not $script:IssueStore.ContainsKey($dn)) {
                $script:IssueStore[$dn] = @{}
            }
            if (-not $script:IssueStore[$dn].ContainsKey($Technique)) {
                $script:IssueStore[$dn][$Technique] = @()
            }
            
            # Store in IssueStore
            $script:IssueStore[$dn][$Technique] += $issue
            $issueCount++

            # Output to pipeline
            $issue
        }
    }

    Write-Verbose "$Technique scan complete. Found $issueCount issue(s)."
}
