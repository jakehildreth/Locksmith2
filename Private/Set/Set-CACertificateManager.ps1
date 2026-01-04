function Set-CACertificateManager {
    <#
        .SYNOPSIS
        Adds Certificate Manager role configuration to AD CS Certification Authority objects.

        .DESCRIPTION
        For each pKIEnrollmentService (CA) object, queries the CA's Certificate Manager
        role assignments using PSCertutil's Get-PCCertificateManager cmdlet and stores the 
        results in the AdcsObjectStore.
        
        Certificate Managers can approve or deny certificate requests, revoke certificates,
        and perform other certificate lifecycle management tasks. Excessive or inappropriate
        Certificate Manager assignments can lead to ESC7 vulnerabilities.
        
        The function adds these properties to each CA object:
        - CertificateManagers: Array of all Certificate Manager objects returned by Get-PCCertificateManager

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS Certification Authorities.
        Must have the CAFullName property set (typically by Set-CAComputerPrincipal).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe CA DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with added CertificateManagers property.

        .EXAMPLE
        $cas | Set-CACertificateManager
        Queries Certificate Managers for all CAs and stores the results.

        .EXAMPLE
        $cas | Set-CAComputerPrincipal | Set-CACertificateManager
        Sets up CA identification and then queries Certificate Managers.

        .NOTES
        Requires the PSCertutil module to be installed and loaded.
        This function must be called after Set-CAComputerPrincipal has set the CAFullName property.
        
        The function silently skips CAs that:
        - Don't have a CAFullName property
        - Are unreachable or don't respond to certutil queries
        - Return errors from Get-PCCertificateManager

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
        Write-Verbose "Querying Certificate Managers for Certification Authorities..."
    }

    process {
        $AdcsObject | Where-Object SchemaClassName -EQ pKIEnrollmentService | ForEach-Object {
            try {
                # Extract CA name for logging
                $caName = if ($_.Properties -and $_.Properties.Contains('cn')) {
                    $_.Properties['cn'][0]
                } elseif ($_.cn) {
                    $_.cn
                } else {
                    'Unknown CA'
                }
                
                Write-Verbose "Processing CA: $caName"
                
                # Get CAFullName from the AdcsObjectStore (where LS2AdcsObject has CAFullName ScriptProperty)
                $dn = $_.Properties.distinguishedName[0]
                $caFullName = if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].CAFullName
                } else {
                    $null
                }
                
                if (-not $caFullName) {
                    Write-Verbose "  CA '$caName' has no CAFullName property - skipping Certificate Managers query"
                    $_
                    return
                }
                
                Write-Verbose "  Querying Certificate Managers for: $caFullName"
                
                try {
                    # Query Certificate Managers using PSCertutil
                    $certificateManagers = Get-PCCertificateManager -CAFullName $caFullName -ErrorAction Stop
                    
                    if ($certificateManagers) {
                        $managerCount = @($certificateManagers).Count
                        Write-Verbose "  Retrieved $managerCount Certificate Manager(s)"
                        
                        # Resolve and cache each manager in PrincipalStore
                        foreach ($manager in $certificateManagers) {
                            Write-Verbose "    Certificate Manager: $($manager.CertificateManager)"
                            
                            try {
                                # Convert the string to an NTAccount and resolve to cache in PrincipalStore
                                $ntAccount = New-Object System.Security.Principal.NTAccount($manager.CertificateManager)
                                $null = Resolve-Principal -IdentityReference $ntAccount
                                Write-Verbose "      Cached principal in PrincipalStore"
                            } catch {
                                Write-Verbose "      Failed to resolve principal: $($_.Exception.Message)"
                            }
                        }
                        
                        # Update the AD CS Object Store
                        $dn = $_.Properties.distinguishedName[0]
                        if ($script:AdcsObjectStore.ContainsKey($dn)) {
                            $script:AdcsObjectStore[$dn].CertificateManagers = $certificateManagers
                            Write-Verbose "  Updated AD CS Object Store for $dn with Certificate Manager data"
                        }
                        
                        # Also add to the pipeline object for backward compatibility
                        $_ | Add-Member -NotePropertyName CertificateManagers -NotePropertyValue $certificateManagers -Force
                        
                    } else {
                        Write-Verbose "  No Certificate Managers returned from Get-PCCertificateManager"
                    }
                    
                } catch {
                    Write-Verbose "  Failed to query Certificate Managers for '$caFullName': $($_.Exception.Message)"
                    # Continue processing other CAs
                }
                
                # Return the modified object
                $_
                
            } catch {
                Write-Warning "Error processing CA: $($_.Exception.Message)"
                $_
            }
        }
    }

    end {
        Write-Verbose "Certificate Manager query complete"
    }
}
