function Set-CAEditFlags {
    <#
        .SYNOPSIS
        Adds EditFlags configuration properties to AD CS Certification Authority objects.

        .DESCRIPTION
        For each pKIEnrollmentService (CA) object, queries the CA's EditFlags registry
        configuration using PSCertutil's Get-PCEditFlag cmdlet and stores the results
        in the AdcsObjectStore.
        
        This function specifically tracks the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, which
        when enabled allows requesters to specify arbitrary Subject Alternative Names,
        leading to the ESC6 vulnerability.
        
        The function adds these properties to each CA object:
        - EditFlags: Array of all EditFlag objects returned by Get-PCEditFlag
        - SANFlagEnabled: Boolean indicating if EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled (ESC6)

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS Certification Authorities.
        Must have the CAFullName property set (typically by Set-CAComputerPrincipal).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe CA DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with added EditFlags properties.

        .EXAMPLE
        $cas | Set-CAEditFlags
        Queries EditFlags for all CAs and stores the results.

        .EXAMPLE
        $cas | Set-CAComputerPrincipal | Set-CAEditFlags
        Sets up CA identification and then queries EditFlags.

        .NOTES
        Requires the PSCertutil module to be installed and loaded.
        This function must be called after Set-CAComputerPrincipal has set the CAFullName property.
        
        The function silently skips CAs that:
        - Don't have a CAFullName property
        - Are unreachable or don't respond to certutil queries
        - Return errors from Get-PCEditFlag

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
        Write-Verbose "Querying EditFlags for Certification Authorities..."
    }

    process {

        foreach ($ca in $AdcsObject) {
            try {
                # Extract CA name for logging
                $caName = if ($ca.Properties -and $ca.Properties.Contains('cn')) {
                    $ca.Properties['cn'][0]
                } elseif ($ca.cn) {
                    $ca.cn
                } else {
                    'Unknown CA'
                }
                
                Write-Verbose "Processing CA: $caName"
                
                # Get CAFullName from the AdcsObjectStore (where LS2AdcsObject has CAFullName ScriptProperty)
                $dn = $ca.Properties.distinguishedName[0]
                $caFullName = if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].CAFullName
                } else {
                    $null
                }
                
                if (-not $caFullName) {
                    Write-Verbose "  CA '$caName' has no CAFullName property - skipping EditFlags query"
                    $ca
                    continue
                }
                
                Write-Verbose "  Querying EditFlags for: $caFullName"
                
                try {
                    # Query EditFlags using PSCertutil
                    $editFlags = Get-PCEditFlag -CAFullName $caFullName -ErrorAction Stop
                    
                    if ($editFlags) {
                        Write-Verbose "  Retrieved $(@($editFlags).Count) EditFlags"
                        
                        # Check specifically for EDITF_ATTRIBUTESUBJECTALTNAME2
                        $sANFlag = $editFlags | Where-Object { $_.EditFlag -eq 'EDITF_ATTRIBUTESUBJECTALTNAME2' }
                        $sANFlagEnabled = if ($sANFlag) { $sANFlag.Enabled } else { $false }
                        
                        if ($sANFlagEnabled) {
                            Write-Warning "CA '$caName' has EDITF_ATTRIBUTESUBJECTALTNAME2 ENABLED (ESC6 vulnerability)"
                        } else {
                            Write-Verbose "  EDITF_ATTRIBUTESUBJECTALTNAME2 is disabled"
                        }
                        
                        # Update the AD CS Object Store
                        $dn = $ca.Properties.distinguishedName[0]
                        if ($script:AdcsObjectStore.ContainsKey($dn)) {
                            $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName EditFlags -NotePropertyValue $editFlags -Force
                            $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName SANFlagEnabled -NotePropertyValue $sANFlagEnabled -Force
                            Write-Verbose "  Updated AD CS Object Store for $dn with EditFlags data"
                        }
                        
                        # Also add to the pipeline object for backward compatibility
                        $ca | Add-Member -NotePropertyName EditFlags -NotePropertyValue $editFlags -Force
                        $ca | Add-Member -NotePropertyName SANFlagEnabled -NotePropertyValue $sANFlagEnabled -Force
                        
                    } else {
                        Write-Verbose "  No EditFlags returned from Get-PCEditFlag"
                    }
                    
                } catch {
                    Write-Verbose "  Failed to query EditFlags for '$caFullName': $($_.Exception.Message)"
                    # Continue processing other CAs
                }
                
                # Return the modified object
                $ca
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'EditFlagQueryFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $_
                )
                $PSCmdlet.WriteError($errorRecord)
                
                # Still return the object even if processing failed
                $ca
            }
        }
    }

    end {
        Write-Verbose "Done querying EditFlags for Certification Authorities."
    }
}
