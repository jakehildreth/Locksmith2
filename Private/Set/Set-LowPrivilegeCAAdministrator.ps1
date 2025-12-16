function Set-LowPrivilegeCAAdministrator {
    <#
        .SYNOPSIS
        Adds LowPrivilegeCAAdministrator properties to CA objects based on CA Administrator assignments.

        .DESCRIPTION
        Examines the CA Administrator assignments on Certificate Authority objects to identify
        principals that are neither high-privilege administrators nor overly broad dangerous groups.
        
        This function identifies "middle ground" CA Administrators - specific users or groups that have
        CA Administrator permissions but aren't part of the standard administrative hierarchy or the
        dangerous principals that represent broad attack surfaces.
        
        The function excludes two categories of principals:
        1. Safe/Administrative principals: Domain Admins, Enterprise Admins, SYSTEM, etc.
        2. Dangerous principals: Everyone, Authenticated Users, Domain Users, etc.
        
        What remains are custom CA Administrators that may represent specific service accounts, security
        groups, or users that have been granted CA Administrator permissions outside the standard model.
        These should be reviewed to ensure they align with security policies and least privilege
        principles for ESC7 vulnerability assessment.
        
        The function adds two properties to each CA object:
        1. LowPrivilegeCAAdministrator: Array of SIDs for custom CA Administrators
        2. LowPrivilegeCAAdministratorNames: Array of human-readable names formatted as "DOMAIN\User (SID)"
           or "SID (could not resolve)" if the principal cannot be resolved.

        .PARAMETER AdcsObject
        One or more CA objects that have been processed by Set-CAAdministrator.
        These objects must contain the CAAdministrators property.

        .INPUTS
        PSCustomObject[]
        You can pipe CA objects to this function.

        .OUTPUTS
        PSCustomObject[]
        Returns the input objects with added properties:
        - LowPrivilegeCAAdministrator: Array of SIDs
        - LowPrivilegeCAAdministratorNames: Array of human-readable names

        .EXAMPLE
        $CAs | Set-LowPrivilegeCAAdministrator
        Processes all CA objects and adds the LowPrivilegeCAAdministrator property to each.

        .EXAMPLE
        $CAs | 
            Set-CAAdministrator | 
            Set-LowPrivilegeCAAdministrator | 
            Where-Object { $_.LowPrivilegeCAAdministrator.Count -gt 0 }
        Retrieves CA Administrators, identifies low-privilege ones, and filters to 
        only those CAs with custom CA Administrators.

        .EXAMPLE
        $ca = $CAs | Where-Object Name -eq 'MyRootCA'
        $ca | Set-LowPrivilegeCAAdministrator
        if ($ca.LowPrivilegeCAAdministrator) {
            Write-Host "CA has custom CA Administrators:"
            $ca.LowPrivilegeCAAdministratorNames | ForEach-Object { Write-Host "  $_" }
        }
        Checks a specific CA for custom/low-privilege CA Administrators and displays human-readable names.

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

        This function requires the CAAdministrators property to be populated by Set-CAAdministrator.

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$AdcsObject
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Identifying CAs that have low-privilege CA Administrators..."
    }

    process {
        $AdcsObject | ForEach-Object {
            try {
                $objectName = if ($_.Name) { $_.Name } else { $_.DistinguishedName }
                Write-Verbose "Processing CA: $objectName"
                
                # Get the distinguished name - handle both DirectoryEntry and LS2AdcsObject
                $dn = if ($_.Properties.distinguishedName) {
                    $_.Properties.distinguishedName[0]
                } else {
                    $_.DistinguishedName
                }
                
                # Get the CAAdministrators property from AdcsObjectStore
                $caAdministrators = if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].CAAdministrators
                } else {
                    $_.CAAdministrators
                }

                [array]$lowPrivilegeIdentityReference = if ($caAdministrators) {
                    foreach ($admin in $caAdministrators) {
                        try {
                            # Convert the CA Administrator name to an NTAccount
                            $ntAccount = New-Object System.Security.Principal.NTAccount($admin.CAAdministrator)
                            
                            # Translate to SID
                            $sid = $ntAccount | Convert-IdentityReferenceToSid
                            
                            # Check if this is a low-privilege principal
                            $isLowPrivilege = $sid.Value | Test-IsLowPrivilegePrincipal
                            
                            if ($isLowPrivilege) {
                                Write-Verbose "  Low-privilege CA Administrator: $($admin.CAAdministrator) ($($sid.Value))"
                                # Ensure principal is in PrincipalStore
                                $null = $ntAccount | Resolve-Principal
                                $sid.Value
                            }
                        } catch {
                            Write-Verbose "  Failed to process CA Administrator $($admin.CAAdministrator): $($_.Exception.Message)"
                        }
                    }
                } else {
                    Write-Verbose "  No CAAdministrators property found"
                    @()
                }

                $lowPrivilegeIdentityReference = $lowPrivilegeIdentityReference | Sort-Object -Unique
                
                if ($lowPrivilegeIdentityReference) {
                    Write-Verbose "CA has $($lowPrivilegeIdentityReference.Count) low privilege CA Administrator(s): $($lowPrivilegeIdentityReference -join ', ')"
                    
                    # Expand any groups to include their direct members
                    Write-Verbose "Expanding group memberships for low privilege CA Administrators..."
                    $lowPrivilegeIdentityReference = Expand-GroupMembership -SidList $lowPrivilegeIdentityReference
                    Write-Verbose "After expansion: $($lowPrivilegeIdentityReference.Count) unique principal(s)"
                } else {
                    Write-Verbose "No low privilege CA Administrators found"
                }

                # Build human-readable names array from PrincipalStore
                [array]$lowPrivilegeCAAdministratorNames = $lowPrivilegeIdentityReference | ForEach-Object {
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

                # Update the AD CS Object Store with the LowPrivilegeCAAdministrator property
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    Write-Verbose "  Setting LowPrivilegeCAAdministrator to: $($lowPrivilegeIdentityReference -join ', ')"
                    Write-Verbose "  Setting LowPrivilegeCAAdministratorNames to: $($lowPrivilegeCAAdministratorNames -join ', ')"
                    $script:AdcsObjectStore[$dn].LowPrivilegeCAAdministrator = $lowPrivilegeIdentityReference
                    $script:AdcsObjectStore[$dn].LowPrivilegeCAAdministratorNames = $lowPrivilegeCAAdministratorNames
                    Write-Verbose "  After assignment - LowPrivilegeCAAdministrator count: $($script:AdcsObjectStore[$dn].LowPrivilegeCAAdministrator.Count)"
                    Write-Verbose "Updated AD CS Object Store for $dn with LowPrivilegeCAAdministrator"
                }

                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName LowPrivilegeCAAdministrator -NotePropertyValue $lowPrivilegeIdentityReference -Force
                $_ | Add-Member -NotePropertyName LowPrivilegeCAAdministratorNames -NotePropertyValue $lowPrivilegeCAAdministratorNames -Force
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'LowPrivilegeCAAdministratorProcessingFailed',
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
        Write-Verbose "Done identifying CAs that have low-privilege CA Administrators."
    }
}
