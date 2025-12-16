function Set-DangerousCACertificateManager {
    <#
        .SYNOPSIS
        Adds a DangerousCACertificateManager property to AD CS Certification Authority objects.

        .DESCRIPTION
        Examines the Certificate Manager role assignments on Certification Authorities to identify
        overly permissive administrative permissions.
        
        The function checks for Certificate Manager roles granted to well-known dangerous principals
        that represent overly broad groups. These should typically not have Certificate Manager 
        permissions, as they can lead to privilege escalation vulnerabilities (ESC7).
        
        The function adds two properties to each CA object:
        1. DangerousCACertificateManager: Array of SIDs for dangerous principals
        2. DangerousCACertificateManagerNames: Array of human-readable names formatted as "DOMAIN\User (SID)"
           or "SID (could not resolve)" if the principal cannot be resolved.

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS Certification Authorities.
        Must have the CertificateManagers property set (typically by Set-CACertificateManager).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe CA DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with added properties:
        - DangerousCACertificateManager: Array of SIDs
        - DangerousCACertificateManagerNames: Array of human-readable names

        .EXAMPLE
        $cas | Set-DangerousCACertificateManager
        Processes all CAs and identifies dangerous Certificate Managers.

        .EXAMPLE
        $cas | Set-CACertificateManager | Set-DangerousCACertificateManager
        Queries Certificate Managers and then identifies dangerous ones.

        .NOTES
        Well-known dangerous principals checked by default:
        - S-1-0-0: NULL SID
        - S-1-1-0: Everyone (all users possibly including anonymous)
        - S-1-5-7: Anonymous Logon
        - S-1-5-32-545: BUILTIN\Users
        - S-1-5-11: Authenticated Users
        - SIDs ending in -513: Domain Users groups
        - SIDs ending in -515: Domain Computers groups
        
        CAs with these principals having Certificate Manager permissions are considered
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
        Write-Verbose "Identifying CAs with dangerous Certificate Managers..."
    }

    process {
        $AdcsObject | Where-Object SchemaClassName -eq pKIEnrollmentService | ForEach-Object {
            try {
                $caName = if ($_.Properties -and $_.Properties.Contains('cn')) {
                    $_.Properties['cn'][0]
                } elseif ($_.cn) {
                    $_.cn
                } else {
                    'Unknown CA'
                }
                
                # Get the distinguished name - handle both DirectoryEntry and LS2AdcsObject
                $dn = if ($_.Properties.distinguishedName) {
                    $_.Properties.distinguishedName[0]
                } else {
                    $_.DistinguishedName
                }

                # Retrieve CertificateManagers from AdcsObjectStore
                $certificateManagers = if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].CertificateManagers
                } else {
                    $_.CertificateManagers
                }

                [array]$dangerousSids = if ($certificateManagers) {
                    foreach ($manager in $certificateManagers) {
                        try {
                            # Convert the Certificate Manager name to an NTAccount
                            $ntAccount = New-Object System.Security.Principal.NTAccount($manager.CertificateManager)
                            
                            # Translate to SID
                            $sid = $ntAccount | Convert-IdentityReferenceToSid
                            
                            # Check if this is a dangerous principal
                            $isDangerous = $sid.Value | Test-IsDangerousPrincipal
                            
                            if ($isDangerous) {
                                Write-Verbose "  Dangerous Certificate Manager found: $($manager.CertificateManager)"
                                # Ensure principal is in PrincipalStore
                                $null = $ntAccount | Resolve-Principal
                                $sid.Value
                            }
                        } catch {
                            Write-Verbose "  Failed to check if '$($manager.CertificateManager)' is dangerous: $($_.Exception.Message)"
                        }
                    }
                } else {
                    @()
                }

                $dangerousSids = $dangerousSids | Sort-Object -Unique

                if ($dangerousSids) {
                    Write-Verbose "  CA has $($dangerousSids.Count) dangerous Certificate Manager(s): $($dangerousSids -join ', ')"
                } else {
                    Write-Verbose "  No dangerous Certificate Managers found"
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

                # Update the AD CS Object Store with the DangerousCACertificateManager property
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].DangerousCACertificateManager = $dangerousSids
                    $script:AdcsObjectStore[$dn].DangerousCACertificateManagerNames = $dangerousNames
                    Write-Verbose "  Updated AD CS Object Store for $dn with DangerousCACertificateManager"
                }

                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName DangerousCACertificateManager -NotePropertyValue $dangerousSids -Force
                $_ | Add-Member -NotePropertyName DangerousCACertificateManagerNames -NotePropertyValue $dangerousNames -Force
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'DangerousCACertificateManagerProcessingFailed',
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
        Write-Verbose "Dangerous Certificate Manager check complete"
    }
}
