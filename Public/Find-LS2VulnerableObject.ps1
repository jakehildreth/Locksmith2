function Find-LS2VulnerableObject {
    <#
    .SYNOPSIS
        Identifies vulnerable AD CS infrastructure objects (containers, computer accounts).

    .DESCRIPTION
        Scans AD CS infrastructure objects for ESC5 vulnerabilities related to ownership.
        
        ESC5: Vulnerable PKI Object Access Control
        - Containers with non-standard owners (can be modified to create vulnerable templates/CAs)
        - Computer objects hosting CAs with non-standard owners
        - Other PKI infrastructure objects with non-standard owners
        
        This function complements Find-LS2VulnerableTemplate (templates) and Find-LS2VulnerableCA (CAs)
        by focusing on the supporting infrastructure objects.

    .PARAMETER Technique
        ESC technique name to scan for. Currently supports 'ESC5'.

    .EXAMPLE
        Find-LS2VulnerableObject -Technique ESC5o
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

    # Query AdcsObjectStore for infrastructure objects and CAs (exclude templates only)
    $allObjects = $script:AdcsObjectStore.Values | Where-Object { 
        $_.objectClass -notcontains 'pKICertificateTemplate'
    }
    
    # Filter objects by conditions
    $vulnerableObjects = @(foreach ($object in $allObjects) {
        $matchesAllConditions = $true
        
        foreach ($condition in $config.Conditions) {
            $propertyValue = $object.($condition.Property)
            
            $matches = switch ($condition.Operator) {
                'eq' { $propertyValue -eq $condition.Value }
                'ne' { $propertyValue -ne $condition.Value }
                'gt' { $propertyValue -gt $condition.Value }
                'lt' { $propertyValue -lt $condition.Value }
                'contains' { $propertyValue -contains $condition.Value }
                default { $false }
            }
            
            if (-not $matches) {
                $matchesAllConditions = $false
                break
            }
        }
        
        if ($matchesAllConditions) {
            $object
        }
    })
    
    Write-Verbose "Found $($vulnerableObjects.Count) object(s) to check (CAs and infrastructure)"

    $issueCount = 0

    # Process vulnerable objects
    foreach ($object in $vulnerableObjects) {
        $objectName = if ($object.displayName) { 
            $object.displayName 
        } elseif ($object.name) { 
            $object.name 
        } elseif ($object.cn) {
            $object.cn
        } else { 
            'Unknown Object' 
        }
        
        $owner = if ($object.Owner) { $object.Owner } else { 'Unknown' }
        
        Write-Verbose "  Checking object: $objectName (owned by $owner)"
        
        $issueCount++
        
        # Get object type for issue description
        $objectType = if ($object.objectClass -contains 'container') {
            'Container'
        } elseif ($object.objectClass -contains 'certificationAuthority') {
            'Certification Authority Container'
        } elseif ($object.objectClass -contains 'pKIEnrollmentService') {
            'Certification Authority'
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
        $issue = [LS2Issue]::new(@{
            Technique          = $Technique
            Forest             = $script:ForestContext.RootDomain
            Name               = $objectName
            DistinguishedName  = $object.distinguishedName
            Owner              = $owner
            HasNonStandardOwner = $true
            Issue              = $issueText
            Fix                = $fixScript
            Revert             = $revertScript
        })

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

    Write-Verbose "$Technique scan complete. Found $issueCount issue(s)."
}
