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

    .EXAMPLE
        Find-LS2VulnerableObject -Technique ESC5a
        Checks for AD CS objects with dangerous editors (write permissions).

    .EXAMPLE
        $issues = Find-LS2VulnerableObject -Technique ESC5o -Verbose
        Stores ESC5o issues in $issues variable with verbose output.

    .EXAMPLE
        Find-LS2VulnerableObject -Technique ESC5a -ExpandGroups
        Checks for dangerous write permissions and expands group principals into per-member issues.

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
        - $script:StandardOwners: List of acceptable owner SIDs
        
        Supported techniques:
        - ESC5a: Dangerous editors with write access to PKI objects
        - ESC5o: Non-standard ownership of PKI infrastructure objects

    .LINK
        Find-LS2VulnerableCA

    .LINK
        Find-LS2VulnerableTemplate

    .LINK
        Invoke-Locksmith2
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('ESC5a', 'ESC5o')]
        [string]$Technique,
        
        [Parameter()]
        [string]$Forest,
        
        [Parameter()]
        [PSCredential]$Credential,
        
        [Parameter()]
        [switch]$ExpandGroups
    )

    #requires -Version 5.1

    # Check if AdcsObjectStore is populated
    if (-not $script:AdcsObjectStore -or $script:AdcsObjectStore.Count -eq 0) {
        Write-Verbose "AdcsObjectStore is empty. Setting up prerequisites..."
        
        # Set up required context only if not already set or parameter provided
        if ($PSBoundParameters.ContainsKey('Forest') -or -not $script:Forest) {
            Set-LS2Forest -Forest $Forest
        }
        
        if ($PSBoundParameters.ContainsKey('Credential') -or -not $script:Credential) {
            Set-LS2Credential -Credential $Credential
        }
        
        if (-not $script:RootDSE) {
            $script:RootDSE = Get-RootDSE
        }
        
        if (-not $script:Server) {
            $script:Server = $script:Forest
        }
        
        # Initialize stores
        Initialize-DomainStore
        Initialize-PrincipalDefinitions
        Initialize-AdcsObjectStore
        
        # Check again after initialization attempt
        if (-not $script:AdcsObjectStore -or $script:AdcsObjectStore.Count -eq 0) {
            Write-Warning "AdcsObjectStore could not be populated. Verify credentials and forest connectivity."
            return
        }
    }

    # If no technique specified, scan all infrastructure object techniques
    if (-not $Technique) {
        $allTechniques = @('ESC5a', 'ESC5o')
        Write-Verbose "No technique specified. Scanning all infrastructure object techniques: $($allTechniques -join ', ')"
        foreach ($tech in $allTechniques) {
            Find-LS2VulnerableObject -Technique $tech
        }
        return
    }

    # Load all ESC definitions
    $definitionsPath = Join-Path $PSScriptRoot '..\Private\Data\ESCDefinitions.psd1'
    $allDefinitions = Import-PowerShellDataFile -Path $definitionsPath
    $config = $allDefinitions[$Technique]

    Write-Verbose "Scanning for $Technique using definitions from $definitionsPath"

    # Query AdcsObjectStore for infrastructure objects and CAs (exclude templates only)
    $allObjects = $script:AdcsObjectStore.Values | Where-Object { 
        $_.objectClass -notcontains 'pKICertificateTemplate'
    }
    
    # Handle ESC5a special logic (check EditorProperties)
    if ($config.EditorProperties) {
        Write-Verbose "ESC5a: Checking EditorProperties for vulnerable objects"
        
        $issueCount = 0
        
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
            
            # Check each editor property
            foreach ($editorProperty in $config.EditorProperties) {
                $editors = $object.$editorProperty
                
                if (-not $editors -or $editors.Count -eq 0) {
                    continue
                }
                
                Write-Verbose "    Found $($editors.Count) editor(s) in $editorProperty"
                
                # Create an issue for each problematic editor
                foreach ($editor in $editors) {
                    $issueCount++
                    
                    # Get corresponding names property
                    $namesProperty = $editorProperty + 'Names'
                    $editorNames = $object.$namesProperty
                    $editorDisplayName = if ($editorNames) {
                        ($editorNames | Where-Object { $_ -like "*$editor*" })[0]
                    } else {
                        $editor
                    }
                    
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
                    
                    # Determine what rights were granted (simplified for now)
                    $activeDirectoryRights = 'Write/Modify'
                    
                    # Expand issue template with variables
                    $issueText = ($config.IssueTemplate -join '') `
                        -replace '\$\(ObjectName\)', $objectName `
                        -replace '\$\(ObjectType\)', $objectType `
                        -replace '\$\(IdentityReference\)', $editorDisplayName `
                        -replace '\$\(ActiveDirectoryRights\)', $activeDirectoryRights
                    
                    # Expand fix script template with variables
                    $fixScript = ($config.FixTemplate -join "`n") `
                        -replace '\$\(DistinguishedName\)', $object.distinguishedName `
                        -replace '\$\(IdentityReference\)', $editor
                    
                    # Expand revert script template with variables
                    $revertScript = ($config.RevertTemplate -join "`n") `
                        -replace '\$\(DistinguishedName\)', $object.distinguishedName
                    
                    # Create issue object
                    $issue = [LS2Issue]::new(@{
                        Technique          = $Technique
                        Forest             = $script:ForestContext.RootDomain
                        Name               = $objectName
                        DistinguishedName  = $object.distinguishedName
                        IdentityReference  = $editor
                        Issue              = $issueText
                        Fix                = $fixScript
                        Revert             = $revertScript
                    })
                    
                    # Add issue to IssueStore
                    if (-not $script:IssueStore) {
                        $script:IssueStore = @{}
                    }
                    if (-not $script:IssueStore.ContainsKey($object.distinguishedName)) {
                        $script:IssueStore[$object.distinguishedName] = @{}
                    }
                    
                    if (-not $script:IssueStore[$object.distinguishedName].ContainsKey($Technique)) {
                        $script:IssueStore[$object.distinguishedName][$Technique] = @()
                    }
                    
                    # Only add to store if not a duplicate
                    if (-not (Test-IssueExists -Issue $issue -DistinguishedName $object.distinguishedName -Technique $Technique)) {
                        $script:IssueStore[$object.distinguishedName][$Technique] += $issue
                        Write-Verbose "      VULNERABLE: $editorDisplayName has write access"
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
        
        Write-Verbose "$Technique scan complete. Found $issueCount issue(s)."
        return
    }
    
    # Filter objects by conditions (for non-ESC5a techniques like ESC5o)
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
        if (-not $script:IssueStore) {
            $script:IssueStore = @{}
        }
        if (-not $script:IssueStore.ContainsKey($object.distinguishedName)) {
            $script:IssueStore[$object.distinguishedName] = @{}
        }
        
        if (-not $script:IssueStore[$object.distinguishedName].ContainsKey($Technique)) {
            $script:IssueStore[$object.distinguishedName][$Technique] = @()
        }
        
        # Only add to store if not a duplicate
        if (-not (Test-IssueExists -Issue $issue -DistinguishedName $object.distinguishedName -Technique $Technique)) {
            $script:IssueStore[$object.distinguishedName][$Technique] += $issue
            Write-Verbose "    VULNERABLE: $objectType '$objectName' owned by $owner"
        }

        # Always output to pipeline
        if ($ExpandGroups) {
            Expand-IssueByGroup -Issue $issue
        } else {
            $issue
        }
    }

    Write-Verbose "$Technique scan complete. Found $issueCount issue(s)."
}
