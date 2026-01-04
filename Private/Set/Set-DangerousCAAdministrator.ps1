function Set-DangerousCAAdministrator {
    <#
        .SYNOPSIS
        Adds a DangerousCAAdministrator property to AD CS Certification Authority objects.

        .DESCRIPTION
        Examines the CA Administrator role assignments on Certification Authorities to identify
        overly permissive administrative permissions.
        
        The function checks for CA Administrator roles granted to well-known dangerous principals
        that represent overly broad groups. These should typically not have CA Administrator 
        permissions, as they can lead to privilege escalation vulnerabilities (ESC7).
        
        The function adds two properties to each CA object:
        1. DangerousCAAdministrator: Array of SIDs for dangerous principals
        2. DangerousCAAdministratorNames: Array of human-readable names formatted as "DOMAIN\User (SID)"
           or "SID (could not resolve)" if the principal cannot be resolved.

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS Certification Authorities.
        Must have the CAAdministrators property set (typically by Set-CAAdministrator).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe CA DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with added properties:
        - DangerousCAAdministrator: Array of SIDs
        - DangerousCAAdministratorNames: Array of human-readable names

        .EXAMPLE
        $cas | Set-DangerousCAAdministrator
        Processes all CAs and identifies dangerous CA Administrators.

        .EXAMPLE
        $cas | Set-CAAdministrator | Set-DangerousCAAdministrator
        Queries CA Administrators and then identifies dangerous ones.

        .NOTES
        Well-known dangerous principals checked by default:
        - S-1-0-0: NULL SID
        - S-1-1-0: Everyone (all users possibly including anonymous)
        - S-1-5-7: Anonymous Logon
        - S-1-5-32-545: BUILTIN\Users
        - S-1-5-11: Authenticated Users
        - SIDs ending in -513: Domain Users groups
        - SIDs ending in -515: Domain Computers groups
        
        CAs with these principals having administrative permissions are considered
        high-risk as they can approve malicious certificate requests.

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObject
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Identifying CAs with dangerous CA Administrators..."
    }

    process {
        $AdcsObject | Where-Object SchemaClassName -EQ pKIEnrollmentService | ForEach-Object {
            try {
                $caName = if ($_.Properties -and $_.Properties.Contains('cn')) {
                    $_.Properties['cn'][0]
                } elseif ($_.cn) {
                    $_.cn
                } else {
                    'Unknown CA'
                }
                
                Write-Verbose "Processing CA: $caName"
                
                # Get CAAdministrators from the AdcsObjectStore
                $dn = $_.Properties.distinguishedName[0]
                $caAdministrators = if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].CAAdministrators
                } else {
                    $null
                }
                
                if (-not $caAdministrators) {
                    Write-Verbose "  CA '$caName' has no CAAdministrators property - skipping dangerous check"
                    $_
                    return
                }
                
                [array]$dangerousSids = foreach ($admin in $caAdministrators) {
                    try {
                        # Convert the admin name to NTAccount and then to SID
                        $ntAccount = New-Object System.Security.Principal.NTAccount($admin.CAAdministrator)
                        $sid = $ntAccount | Convert-IdentityReferenceToSid
                        
                        $isDangerous = $sid | Test-IsDangerousPrincipal
                        if ($isDangerous) {
                            Write-Verbose "  Dangerous CA Administrator found: $($admin.CAAdministrator)"
                            # Ensure principal is in PrincipalStore
                            $null = $ntAccount | Resolve-Principal
                            $sid.Value
                        }
                    } catch {
                        Write-Verbose "  Failed to check if '$($admin.CAAdministrator)' is dangerous: $($_.Exception.Message)"
                    }
                }
                
                $dangerousSids = $dangerousSids | Sort-Object -Unique
                
                if ($dangerousSids) {
                    Write-Verbose "  CA has $($dangerousSids.Count) dangerous CA Administrator(s): $($dangerousSids -join ', ')"
                } else {
                    Write-Verbose "  No dangerous CA Administrators found"
                }
                
                # Build human-readable names array from PrincipalStore
                [array]$dangerousNames = $dangerousSids | ForEach-Object {
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
                
                # Update the AD CS Object Store with the DangerousCAAdministrator property
                $dn = $_.Properties.distinguishedName[0]
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].DangerousCAAdministrator = $dangerousSids
                    $script:AdcsObjectStore[$dn].DangerousCAAdministratorNames = $dangerousNames
                    Write-Verbose "  Updated AD CS Object Store for $dn with DangerousCAAdministrator"
                }
                
                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName DangerousCAAdministrator -NotePropertyValue $dangerousSids -Force
                $_ | Add-Member -NotePropertyName DangerousCAAdministratorNames -NotePropertyValue $dangerousNames -Force
                
                # Return the modified object
                $_
                
            } catch {
                Write-Warning "Error processing CA: $($_.Exception.Message)"
                $_
            }
        }
    }

    end {
        Write-Verbose "Dangerous CA Administrator check complete"
    }
}
