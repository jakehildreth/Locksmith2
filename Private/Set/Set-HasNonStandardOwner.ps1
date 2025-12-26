function Set-HasNonStandardOwner {
    <#
        .SYNOPSIS
        Adds HasNonStandardOwner property to AD CS objects based on their owner.

        .DESCRIPTION
        Examines the ownership of Active Directory Certificate Services objects
        to identify whether they have non-standard owners.
        
        Standard owners are typically high-privilege administrative groups such as:
        - Enterprise Admins (SID ending in -519)
        - Domain Admins (SID ending in -512)
        - Administrators (SID ending in -544)
        - SYSTEM (S-1-5-18)
        - Enterprise Domain Controllers (SID ending in -516)
        - Schema Admins (SID ending in -518)
        
        Objects owned by other principals may represent misconfiguration or potential
        security risks, as they could allow unauthorized modification of critical
        PKI infrastructure.
        
        The function sets the HasNonStandardOwner property on each object:
        - $true if the owner is NOT in the standard owner list
        - $false if the owner IS in the standard owner list
        - $null if ownership cannot be determined

        .PARAMETER AdcsObject
        One or more LS2AdcsObject or DirectoryEntry objects representing AD CS objects.
        These objects must have Owner property populated.

        .INPUTS
        LS2AdcsObject[]
        System.DirectoryServices.DirectoryEntry[]
        You can pipe AD CS objects to this function.

        .OUTPUTS
        LS2AdcsObject[]
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with HasNonStandardOwner property set.

        .EXAMPLE
        $templates = Get-AdcsObject | Where-Object { $_.IsCertificateTemplate() }
        $templates | Set-HasNonStandardOwner
        Processes all certificate templates and sets the HasNonStandardOwner property.

        .EXAMPLE
        Get-AdcsObject | 
            Set-HasNonStandardOwner | 
            Where-Object { $_.HasNonStandardOwner -eq $true }
        Retrieves all AD CS objects, sets HasNonStandardOwner, and filters to 
        only those with non-standard owners.

        .EXAMPLE
        $template = Get-AdcsObject | Where-Object Name -eq 'WebServer'
        $template | Set-HasNonStandardOwner
        if ($template.HasNonStandardOwner) {
            Write-Host "Template has non-standard owner: $($template.Owner)"
        }
        Checks a specific template for non-standard ownership.

        .NOTES
        Standard owner SID patterns:
        - S-1-5-18: SYSTEM
        - S-1-5-32-544: BUILTIN\Administrators
        - SIDs ending in -512: Domain Admins
        - SIDs ending in -516: Domain Controllers
        - SIDs ending in -518: Schema Admins
        - SIDs ending in -519: Enterprise Admins
        - SIDs ending in -521: Read-Only Domain Controllers
        
        Templates and CAs with non-standard owners may be vulnerable to ESC4-style
        attacks where the owner can modify critical security settings.

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    [OutputType([LS2AdcsObject[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$AdcsObject
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Identifying objects with non-standard owners..."
        
        # Use script-level StandardOwners (populated by Initialize-PrincipalDefinitions)
        if (-not $script:StandardOwners -or $script:StandardOwners.Count -eq 0) {
            Write-Warning "StandardOwners not initialized. Cannot validate object ownership."
            return
        }
        
        Write-Verbose "Using $($script:StandardOwners.Count) standard owner patterns"
    }

    process {
        foreach ($object in $AdcsObject) {
            try {
                $objectName = if ($object.displayName) {
                    $object.displayName
                } elseif ($object.name) {
                    $object.name
                } elseif ($object.Properties -and $object.Properties.Contains('displayName')) {
                    $object.Properties.displayName[0]
                } elseif ($object.Properties -and $object.Properties.Contains('name')) {
                    $object.Properties.name[0]
                } elseif ($object.distinguishedName) {
                    $object.distinguishedName
                } elseif ($object.Properties -and $object.Properties.Contains('distinguishedName')) {
                    $object.Properties.distinguishedName[0]
                } else {
                    'Unknown'
                }
                
                Write-Verbose "Processing object: $objectName"
                
                # Get the owner
                $owner = $null
                if ($object.Owner) {
                    $owner = $object.Owner
                } elseif ($object.ObjectSecurity -and $object.ObjectSecurity.Owner) {
                    $owner = $object.ObjectSecurity.Owner
                } elseif ($object.nTSecurityDescriptor -and $object.nTSecurityDescriptor.Owner) {
                    $owner = $object.nTSecurityDescriptor.Owner
                }
                
                if (-not $owner) {
                    Write-Verbose "Could not determine owner for $objectName"
                    $hasNonStandardOwner = $null
                } else {
                    Write-Verbose "Owner: $owner"
                    
                    # Convert owner to SID if it's not already
                    $ownerSid = $null
                    if ($owner -match '^S-1-') {
                        $ownerSid = $owner
                    } else {
                        try {
                            $ownerPrincipal = New-Object System.Security.Principal.NTAccount($owner)
                            $ownerSid = $ownerPrincipal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            Write-Verbose "Translated owner to SID: $ownerSid"
                        } catch {
                            Write-Warning "Could not translate owner '$owner' to SID for $objectName : $_"
                            $hasNonStandardOwner = $null
                        }
                    }
                    
                    if ($ownerSid) {
                        # Check if owner SID matches any standard owner pattern
                        $isStandardOwner = $false
                        
                        foreach ($pattern in $script:StandardOwners) {
                            # Check for exact SID match
                            if ($pattern -eq $ownerSid) {
                                $isStandardOwner = $true
                                Write-Verbose "Owner $owner ($ownerSid) matches standard owner pattern (exact): $pattern"
                                break
                            }
                            # Check for regex pattern match (patterns ending in $)
                            elseif ($pattern -match '\$$' -and $ownerSid -match $pattern) {
                                $isStandardOwner = $true
                                Write-Verbose "Owner $owner ($ownerSid) matches standard owner pattern (regex): $pattern"
                                break
                            }
                        }
                        
                        if ($isStandardOwner) {
                            $hasNonStandardOwner = $false
                        } else {
                            $hasNonStandardOwner = $true
                            Write-Verbose "Owner $owner ($ownerSid) is NOT a standard owner"
                        }
                    }
                }
                
                # Set the HasNonStandardOwner property on the pipeline object
                if ($object.PSObject.Properties['HasNonStandardOwner']) {
                    $object.HasNonStandardOwner = $hasNonStandardOwner
                } else {
                    $object | Add-Member -NotePropertyName HasNonStandardOwner -NotePropertyValue $hasNonStandardOwner -Force
                }
                
                # Update the AdcsObjectStore with the HasNonStandardOwner property
                $dn = $null
                if ($object.distinguishedName) {
                    # Handle PropertyValueCollection from DirectoryEntry
                    if ($object.distinguishedName -is [System.DirectoryServices.PropertyValueCollection]) {
                        $dn = $object.distinguishedName.Value
                    } else {
                        $dn = $object.distinguishedName
                    }
                } elseif ($object.Properties -and $object.Properties.Contains('distinguishedName')) {
                    $dn = $object.Properties.distinguishedName[0]
                }
                
                if ($dn -and $script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].HasNonStandardOwner = $hasNonStandardOwner
                    Write-Verbose "Updated AD CS Object Store for $dn with HasNonStandardOwner = $hasNonStandardOwner"
                }
                
                # Return the modified object
                $object
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'HasNonStandardOwnerProcessingFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $object
                )
                $PSCmdlet.WriteError($errorRecord)
                
                # Still return the object even if processing failed
                $object
            }
        }
    }

    end {
        Write-Verbose "Done identifying objects with non-standard owners."
    }
}
