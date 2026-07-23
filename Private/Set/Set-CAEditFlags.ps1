function Set-CAEditFlags {
    <#
        .SYNOPSIS
        Adds EditFlags configuration properties to AD CS Certification Authority objects.

        .DESCRIPTION
        For each pKIEnrollmentService (CA) object, queries the CA's EditFlags registry
        configuration using PSCertutil's Get-PSCEditFlag cmdlet and stores the results
        in the AdcsObjectStore.
        
        This function specifically tracks the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, which
        when enabled allows requesters to specify arbitrary Subject Alternative Names,
        leading to the ESC6 vulnerability.
        
        The function adds these properties to each CA object:
        - EditFlags: Array of all EditFlag objects returned by Get-PSCEditFlag
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
        - Return errors from Get-PSCEditFlag

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
        Write-Verbose "Querying EditFlags for Certification Authorities..."
    }

    process {
        $AdcsObject | Where-Object { $_.IsCertificationAuthority() } | ForEach-Object {
            try {
                $caName = $_.cn
                Write-Verbose "Processing CA: $caName"
                
                # Get CAFullName directly from the LS2AdcsObject (ScriptProperty)
                $caFullName = $_.CAFullName
                
                if (-not $caFullName) {
                    Write-Verbose "  CA '$caName' has no CAFullName property - skipping EditFlags query"
                    $_
                    continue
                }
                
                Write-Verbose "  Querying EditFlags for: $caFullName"
                
                try {
                    # Query EditFlags using PSCertutil
                    $editFlags = Get-PSCEditFlag -CAFullName $caFullName -ErrorAction Stop
                    
                    if ($editFlags) {
                        Write-Verbose "  Retrieved $(@($editFlags).Count) EditFlags"
                        
                        # Check specifically for EDITF_ATTRIBUTESUBJECTALTNAME2
                        $sANFlag = $editFlags | Where-Object { $_.EditFlag -eq 'EDITF_ATTRIBUTESUBJECTALTNAME2' }
                        $sANFlagEnabled = if ($sANFlag) { $sANFlag.Enabled } else { $false }
                        
                        Write-Verbose "  EDITF_ATTRIBUTESUBJECTALTNAME2 is $(if ($sANFlagEnabled) { 'enabled' } else { 'disabled' })"
                        
                        # Set properties directly on the LS2AdcsObject (same reference as store)
                        $_.EditFlags = $editFlags
                        $_.SANFlagEnabled = $sANFlagEnabled
                        Write-Verbose "  Updated $($_.distinguishedName) with EditFlags data"
                        
                    } else {
                        Write-Verbose "  No EditFlags returned from Get-PSCEditFlag"
                    }
                    
                } catch {
                    Write-Verbose "  Failed to query EditFlags for '$caFullName': $($_.Exception.Message)"
                    # Continue processing other CAs
                }
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'EditFlagQueryFailed',
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
        Write-Verbose "Done querying EditFlags for Certification Authorities."
    }
}
