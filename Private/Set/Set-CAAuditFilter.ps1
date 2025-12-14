function Set-CAAuditFilter {
    <#
        .SYNOPSIS
        Adds AuditFilter configuration properties to AD CS Certification Authority objects.

        .DESCRIPTION
        For each pKIEnrollmentService (CA) object, queries the CA's AuditFilter registry
        configuration using PSCertutil's Get-PCAuditFilter cmdlet and stores the results
        in the AdcsObjectStore.
        
        This function tracks the AuditFilter registry value which controls what events
        are audited by the Certificate Authority. Insufficient auditing can make it
        difficult to detect and respond to attacks.
        
        The function adds this property to each CA object:
        - AuditFilter: Integer value representing the audit bitmask

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS Certification Authorities.
        Must have the CAFullName property set (typically by Set-CAComputerPrincipal).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe CA DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with added AuditFilter property.

        .EXAMPLE
        $cas | Set-CAAuditFilter
        Queries AuditFilter for all CAs and stores the results.

        .EXAMPLE
        $cas | Set-CAComputerPrincipal | Set-CAAuditFilter
        Sets up CA identification and then queries AuditFilter.

        .NOTES
        Requires the PSCertutil module to be installed and loaded.
        This function must be called after Set-CAComputerPrincipal has set the CAFullName property.
        
        The function silently skips CAs that:
        - Don't have a CAFullName property
        - Are unreachable or don't respond to certutil queries
        - Return errors from Get-PCAuditFilter

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
        Write-Verbose "Querying AuditFilter for Certification Authorities..."
    }

    process {
        $AdcsObject | Where-Object SchemaClassName -eq pKIEnrollmentService | ForEach-Object {
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
                    Write-Verbose "  CA '$caName' has no CAFullName property - skipping AuditFilter query"
                    $_
                    continue
                }
                
                Write-Verbose "  Querying AuditFilter for: $caFullName"
                
                try {
                    # Query AuditFilter using PSCertutil
                    $auditFilterResult = Get-PCAuditFilter -CAFullName $caFullName -ErrorAction Stop
                    
                    if ($auditFilterResult -and $null -ne $auditFilterResult.AuditFilter) {
                        $auditFilter = $auditFilterResult.AuditFilter
                        Write-Verbose "  Retrieved AuditFilter: $auditFilter"
                        
                        # Update the AD CS Object Store
                        if ($script:AdcsObjectStore.ContainsKey($dn)) {
                            $script:AdcsObjectStore[$dn].AuditFilter = $auditFilter
                            Write-Verbose "  Updated AD CS Object Store for $dn with AuditFilter data"
                        }
                        
                        # Also add to the pipeline object for backward compatibility
                        $_ | Add-Member -NotePropertyName AuditFilter -NotePropertyValue $auditFilter -Force
                        
                    } else {
                        Write-Verbose "  No AuditFilter returned from Get-PCAuditFilter"
                    }
                }
                catch {
                    Write-Verbose "  Failed to query AuditFilter for '$caFullName': $($_.Exception.Message)"
                }
            }
            catch {
                Write-Warning "Error processing CA: $($_.Exception.Message)"
            }
            
            # Always return the object to continue the pipeline
            $_
        }
    }

    end {
        Write-Verbose "Completed AuditFilter queries for all CAs"
    }
}
