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
    [OutputType([LS2AdcsObject[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [LS2AdcsObject[]]$AdcsObject
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Querying AuditFilter for Certification Authorities..."
    }

    process {
        $AdcsObject | Where-Object { $_.IsCertificationAuthority() } | ForEach-Object {
            try {
                $caName = $_.cn
                Write-Verbose "Processing CA: $caName"
                
                # Get CAFullName directly from the LS2AdcsObject (ScriptProperty)
                $dn = $_.distinguishedName
                $caFullName = $_.CAFullName
                
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
                        
                        # Set the property directly on the LS2AdcsObject (same reference as store)
                        $_.AuditFilter = $auditFilter
                        Write-Verbose "  Updated $($_.distinguishedName) with AuditFilter data"
                        
                    } else {
                        Write-Verbose "  No AuditFilter returned from Get-PCAuditFilter"
                    }
                } catch {
                    Write-Verbose "  Failed to query AuditFilter for '$caFullName': $($_.Exception.Message)"
                }
            } catch {
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
