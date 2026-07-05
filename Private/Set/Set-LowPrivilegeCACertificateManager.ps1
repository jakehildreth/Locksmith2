function Set-LowPrivilegeCACertificateManager {
    <#
        .SYNOPSIS
        Adds LowPrivilegeCACertificateManager properties to CA objects based on Certificate Manager assignments.

        .DESCRIPTION
        Examines the Certificate Manager assignments on Certificate Authority objects to identify
        principals that are neither high-privilege administrators nor overly broad dangerous groups.
        
        This function identifies "middle ground" Certificate Managers - specific users or groups that have
        Certificate Manager permissions but aren't part of the standard administrative hierarchy or the
        dangerous principals that represent broad attack surfaces.
        
        The function excludes two categories of principals:
        1. Safe/Administrative principals: Domain Admins, Enterprise Admins, SYSTEM, etc.
        2. Dangerous principals: Everyone, Authenticated Users, Domain Users, etc.
        
        What remains are custom Certificate Managers that may represent specific service accounts, security
        groups, or users that have been granted Certificate Manager permissions outside the standard model.
        These should be reviewed to ensure they align with security policies and least privilege
        principles for ESC7 vulnerability assessment.
        
        The function adds two properties to each CA object:
        1. LowPrivilegeCACertificateManager: Array of SIDs for custom Certificate Managers
        2. LowPrivilegeCACertificateManagerNames: Array of human-readable names formatted as "DOMAIN\User (SID)"
           or "SID (could not resolve)" if the principal cannot be resolved.

        .PARAMETER AdcsObject
        One or more CA objects that have been processed by Set-CACertificateManager.
        These objects must contain the CertificateManagers property.

        .INPUTS
        PSCustomObject[]
        You can pipe CA objects to this function.

        .OUTPUTS
        PSCustomObject[]
        Returns the input objects with added properties:
        - LowPrivilegeCACertificateManager: Array of SIDs
        - LowPrivilegeCACertificateManagerNames: Array of human-readable names

        .EXAMPLE
        $CAs | Set-LowPrivilegeCACertificateManager
        Processes all CA objects and adds the LowPrivilegeCACertificateManager property to each.

        .EXAMPLE
        $CAs | 
            Set-CACertificateManager | 
            Set-LowPrivilegeCACertificateManager | 
            Where-Object { $_.LowPrivilegeCACertificateManager.Count -gt 0 }
        Retrieves Certificate Managers, identifies low-privilege ones, and filters to 
        only those CAs with custom Certificate Managers.

        .EXAMPLE
        $ca = $CAs | Where-Object Name -eq 'MyRootCA'
        $ca | Set-LowPrivilegeCACertificateManager
        if ($ca.LowPrivilegeCACertificateManager) {
            Write-Host "CA has custom Certificate Managers:"
            $ca.LowPrivilegeCACertificateManagerNames | ForEach-Object { Write-Host "  $_" }
        }
        Checks a specific CA for custom/low-privilege Certificate Managers and displays human-readable names.

        .NOTES
        Safe/Administrative principals excluded by default:
        - Domain Admins (-512), Enterprise Admins (-519), Builtin Administrators (-544)
        - SYSTEM (-18), Builtin Administrator (-500)
        - Cert Publishers (-517)
        - Domain Controllers (-516), Read-Only Domain Controllers (-521)
        - Enterprise Domain Controllers (-498), Enterprise Read-Only Domain Controllers (-9)
        - Key Admins (-526), Enterprise Key Admins (-527)
        - SELF (S-1-5-10)
        
        Dangerous principals excluded by default:
        - NULL SID, Everyone, Anonymous Logon, BUILTIN\Users
        - Authenticated Users, Domain Users, Domain Computers

        This function requires the CertificateManagers property to be populated by Set-CACertificateManager.

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    [OutputType([LS2AdcsObject[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [LS2AdcsObject[]]$AdcsObject
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Identifying CAs that have low-privilege Certificate Managers..."
    }

    process {
        $AdcsObject | ForEach-Object {
            try {
                $objectName = $_.GetFriendlyName()
                Write-Verbose "Processing CA: $objectName"
                
                $dn = $_.distinguishedName
                
                # Get the CertificateManagers property directly from the LS2AdcsObject
                $certificateManagers = $_.CertificateManagers

                [array]$lowPrivilegeIdentityReference = if ($certificateManagers) {
                    foreach ($manager in $certificateManagers) {
                        try {
                            # Convert the Certificate Manager name to an NTAccount
                            $ntAccount = New-Object System.Security.Principal.NTAccount($manager.CertificateManager)
                            
                            # Translate to SID
                            $sid = $ntAccount | Convert-IdentityReferenceToSid
                            
                            # Check if this is a low-privilege principal
                            $isLowPrivilege = $sid.Value | Test-IsLowPrivilegePrincipal
                            
                            if ($isLowPrivilege) {
                                Write-Verbose "  Low-privilege Certificate Manager: $($manager.CertificateManager) ($($sid.Value))"
                                # Ensure principal is in PrincipalStore
                                $null = $ntAccount | Resolve-Principal
                                $sid.Value
                            }
                        } catch {
                            Write-Verbose "  Failed to process Certificate Manager $($manager.CertificateManager): $($_.Exception.Message)"
                        }
                    }
                } else {
                    Write-Verbose "  No CertificateManagers property found"
                    @()
                }

                $lowPrivilegeIdentityReference = $lowPrivilegeIdentityReference | Sort-Object -Unique
                
                if ($lowPrivilegeIdentityReference) {
                    Write-Verbose "CA has $($lowPrivilegeIdentityReference.Count) low privilege Certificate Manager(s): $($lowPrivilegeIdentityReference -join ', ')"
                    
                    # Expand any groups to include their direct members
                    Write-Verbose "Expanding group memberships for low privilege Certificate Managers..."
                    $lowPrivilegeIdentityReference = Expand-GroupMembership -SidList $lowPrivilegeIdentityReference
                    Write-Verbose "After expansion: $($lowPrivilegeIdentityReference.Count) unique principal(s)"
                } else {
                    Write-Verbose "No low privilege Certificate Managers found"
                }

                # Build human-readable names array from PrincipalStore
                [array]$lowPrivilegeCACertificateManagerNames = $lowPrivilegeIdentityReference | ForEach-Object {
                    if ($script:PrincipalStore -and $script:PrincipalStore.ContainsKey($_)) {
                        $name = $script:PrincipalStore[$_].ntAccountName
                        if ($name) {
                            "$name ($_)"
                        } else {
                            "$_ (could not resolve)"
                        }
                    } else {
                        "$_ (could not resolve)"
                    }
                } | Sort-Object -Unique

                # Set properties directly on the LS2AdcsObject (same reference as store)
                Write-Verbose "  Setting LowPrivilegeCACertificateManager to: $($lowPrivilegeIdentityReference -join ', ')"
                Write-Verbose "  Setting LowPrivilegeCACertificateManagerNames to: $($lowPrivilegeCACertificateManagerNames -join ', ')"
                $_.LowPrivilegeCACertificateManager = $lowPrivilegeIdentityReference
                $_.LowPrivilegeCACertificateManagerNames = $lowPrivilegeCACertificateManagerNames
                Write-Verbose "  After assignment - LowPrivilegeCACertificateManager count: $($_.LowPrivilegeCACertificateManager.Count)"
                Write-Verbose "Updated $($_.distinguishedName) with LowPrivilegeCACertificateManager"
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'LowPrivilegeCACertificateManagerProcessingFailed',
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
        Write-Verbose "Done identifying CAs that have low-privilege Certificate Managers."
    }
}
