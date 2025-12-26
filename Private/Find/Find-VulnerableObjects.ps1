function Find-VulnerableObjects {
    <#
    .SYNOPSIS
        Identifies vulnerable AD CS infrastructure objects (containers, computer accounts).

    .DESCRIPTION
        Scans AD CS infrastructure objects for ESC5 vulnerabilities related to ownership.
        
        ESC5: Vulnerable PKI Object Access Control
        - Containers with non-standard owners (can be modified to create vulnerable templates/CAs)
        - Computer objects hosting CAs with non-standard owners
        - Other PKI infrastructure objects with non-standard owners
        
        This function complements Find-VulnerableTemplates (templates) and Find-VulnerableCA (CAs)
        by focusing on the supporting infrastructure objects.

    .PARAMETER Technique
        ESC technique name to scan for. Currently supports 'ESC5'.

    .EXAMPLE
        Find-VulnerableObjects -Technique ESC5
        Checks for AD CS infrastructure objects with non-standard owners.

    .OUTPUTS
        LS2Issue objects for each vulnerability found
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ESC5o')]
        [string]$Technique
    )

    #requires -Version 5.1

    # Load all ESC definitions
    $definitionsPath = Join-Path $PSScriptRoot '..\Data\ESCDefinitions.psd1'
    $allDefinitions = Import-PowerShellDataFile -Path $definitionsPath
    $config = $allDefinitions[$Technique]

    Write-Verbose "Scanning for $Technique using definitions from $definitionsPath"

    # Query AdcsObjectStore for infrastructure objects (exclude templates and CAs which are handled separately)
    $allObjects = $script:AdcsObjectStore.Values | Where-Object { 
        $_.objectClass -notcontains 'pKICertificateTemplate' -and 
        $_.objectClass -notcontains 'pKIEnrollmentService'
    }
    
    Write-Verbose "Found $($allObjects.Count) infrastructure object(s) to check"

    $issueCount = 0

    # ESC5: Check for non-standard owners
    foreach ($object in $allObjects) {
        $objectName = if ($object.displayName) { 
            $object.displayName 
        } elseif ($object.name) { 
            $object.name 
        } elseif ($object.cn) {
            $object.cn
        } else { 
            'Unknown Object' 
        }
        
        Write-Verbose "  Checking object: $objectName"

        # Skip objects without HasNonStandardOwner property set
        if ($null -eq $object.HasNonStandardOwner) {
            Write-Verbose "    HasNonStandardOwner not set - skipping"
            continue
        }

        # Check for non-standard owner
        if ($object.HasNonStandardOwner -eq $true) {
            $issueCount++
            
            # Get owner for issue description
            $owner = if ($object.Owner) { 
                $object.Owner 
            } else { 
                'Unknown' 
            }
            
            # Get object type for issue description
            $objectType = if ($object.objectClass -contains 'container') {
                'Container'
            } elseif ($object.objectClass -contains 'certificationAuthority') {
                'Certification Authority Container'
            } elseif ($object.objectClass -contains 'computer') {
                'Computer Account'
            } else {
                'PKI Object'
            }

            # Expand issue template with variables
            $issueText = ($config.IssueTemplate -join '') `
                -replace '\$\(ObjectName\)', $objectName `
                -replace '\$\(ObjectType\)', $objectType `
                -replace '\$\(Owner\)', $owner

            # Expand fix script template with variables
            $fixScript = ($config.FixTemplate -join "`n") `
                -replace '\$\(DistinguishedName\)', $object.distinguishedName

            # Expand revert script template with variables
            $revertScript = ($config.RevertTemplate -join "`n") `
                -replace '\$\(DistinguishedName\)', $object.distinguishedName `
                -replace '\$\(OriginalOwner\)', $owner

            # Create issue object
            $issue = [LS2Issue]::new(
                $Technique,
                $object.distinguishedName,
                $issueText,
                $fixScript,
                $revertScript
            )

            # Add issue to IssueStore
            if (-not $script:IssueStore.ContainsKey($object.distinguishedName)) {
                $script:IssueStore[$object.distinguishedName] = @{}
            }
            
            if (-not $script:IssueStore[$object.distinguishedName].ContainsKey($Technique)) {
                $script:IssueStore[$object.distinguishedName][$Technique] = @()
            }
            
            $script:IssueStore[$object.distinguishedName][$Technique] += $issue

            Write-Verbose "    VULNERABLE: $objectType '$objectName' owned by $owner"

            # Return the issue
            $issue
        }
    }

    Write-Verbose "$Technique scan complete. Found $issueCount issue(s)."
}
