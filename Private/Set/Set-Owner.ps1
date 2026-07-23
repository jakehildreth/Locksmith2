function Set-Owner {
    <#
        .SYNOPSIS
        Normalizes and resolves owner identity references for AD CS objects.

        .DESCRIPTION
        Examines the Owner property of AD CS objects and ensures consistent SID resolution
        by calling Resolve-Principal to populate the PrincipalStore cache. This enables
        downstream vulnerability detection functions (ESC4o, ESC5o) to consistently resolve
        owner identities to human-readable names.
        
        The Owner property from ObjectSecurity.Owner can return inconsistent formats:
        - DOMAIN\User (resolved NTAccount)
        - S-1-5-21-... (raw SID string)
        - O:S-1-5-21-... (SDDL format)
        
        This function extracts the SID, calls Resolve-Principal to cache the principal,
        and normalizes the Owner property to a consistent SID string format that can be
        reliably resolved later via Convert-IdentityReferenceToNTAccount.
        
        This is a critical preprocessing step for ESC4o and ESC5o vulnerability detection,
        ensuring that owner identities can be consistently resolved regardless of the
        format returned by the .NET ObjectSecurity.Owner property.

        .PARAMETER AdcsObject
        One or more LS2AdcsObject instances representing AD CS objects.

        .INPUTS
        LS2AdcsObject[]
        You can pipe LS2AdcsObject instances to this function.

        .OUTPUTS
        LS2AdcsObject[]
        Returns the input objects with normalized Owner properties.

        .EXAMPLE
        $templates = $script:AdcsObjectStore.Values | 
            Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        $templates | Set-Owner
        Normalizes owner identities for all certificate templates.

        .EXAMPLE
        $script:AdcsObjectStore.Values | Set-Owner
        Normalizes owner identities for all AD CS objects in the store.

        .NOTES
        This function mirrors the ACE resolution pattern used in Set-DangerousEditor,
        Set-LowPrivilegeEnrollee, etc., by proactively calling Resolve-Principal to
        populate PrincipalStore before owner names are needed for display.
        
        Run this function in the Initialize-AdcsObjectStore pipeline after
        Initialize-PrincipalDefinitions has completed and PrincipalStore is ready.
    #>
    [CmdletBinding()]
    [OutputType([LS2AdcsObject[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [LS2AdcsObject[]]$AdcsObject
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Normalizing owner identities for AD CS objects..."
    }

    process {
        $AdcsObject | ForEach-Object {
            try {
                $objectName = if ($_.displayName) {
                    $_.displayName
                } elseif ($_.Name) {
                    $_.Name
                } else {
                    $_.DistinguishedName
                }
                Write-Verbose "Processing owner for: $objectName"
                
                $owner = $_.Owner
                
                if (-not $owner) {
                    Write-Verbose "No owner found for object: $objectName"
                    return $_
                }
                
                # Extract SID from owner string (handles raw SID, SDDL format, or NTAccount)
                $ownerSid = $null
                
                if ($owner -match '^(?:O:)?(S-1-[\d-]+)') {
                    # Owner is already a SID (with or without SDDL prefix)
                    try {
                        $ownerSid = [System.Security.Principal.SecurityIdentifier]::new($Matches[1])
                        Write-Verbose "Owner is SID format: $($ownerSid.Value)"
                    } catch {
                        Write-Warning "Invalid SID format for owner '$owner' on object '$objectName': $_"
                    }
                } else {
                    # Owner is in NTAccount format (DOMAIN\User) - convert to SID
                    try {
                        $ntAccount = [System.Security.Principal.NTAccount]::new($owner)
                        $ownerSid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                        Write-Verbose "Converted NTAccount '$owner' to SID: $($ownerSid.Value)"
                    } catch {
                        Write-Warning "Could not translate NTAccount '$owner' to SID for object '$objectName': $_"
                    }
                }
                
                # If we successfully extracted a SID, resolve it to populate PrincipalStore
                if ($ownerSid) {
                    Write-Verbose "Resolving owner SID to populate PrincipalStore: $($ownerSid.Value)"
                    $null = $ownerSid | Resolve-Principal
                    
                    # Normalize the Owner property to the SID string
                    # This ensures downstream code can reliably convert it via PrincipalStore
                    $_.Owner = $ownerSid.Value
                    
                    Write-Verbose "Normalized owner to SID: $($ownerSid.Value)"
                }
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'OwnerResolutionFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $_
                )
                $PSCmdlet.WriteError($errorRecord)
                
                # Still return the object even if processing failed
                $_
            }
        }
    }

    end {
        Write-Verbose "Owner normalization complete."
    }
}
