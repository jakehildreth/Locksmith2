function Set-CAInterfaceFlags {
    <#
        .SYNOPSIS
        Adds InterfaceFlags configuration properties to AD CS Certification Authority objects.

        .DESCRIPTION
        For each pKIEnrollmentService (CA) object, queries the CA's InterfaceFlags registry
        configuration using PSCertutil's Get-PCInterfaceFlag cmdlet and stores the results
        in the AdcsObjectStore.
        
        This function tracks various interface flags that control CA RPC/DCOM behavior,
        including the IF_ENFORCEENCRYPTICERTREQUEST flag which when disabled leads to
        the ESC11 vulnerability (allowing unauthenticated/unencrypted certificate requests).
        
        The function adds these properties to each CA object:
        - InterfaceFlags: Array of all InterfaceFlag objects returned by Get-PCInterfaceFlag
        - RPCEncryptionNotRequired: Boolean indicating if IF_ENFORCEENCRYPTICERTREQUEST is disabled (ESC11)

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS Certification Authorities.
        Must have the CAFullName property set (typically by Set-CAComputerPrincipal).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe CA DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with added InterfaceFlags properties.

        .EXAMPLE
        $cas | Set-CAInterfaceFlags
        Queries InterfaceFlags for all CAs and stores the results.

        .EXAMPLE
        $cas | Set-CAComputerPrincipal | Set-CAInterfaceFlags
        Sets up CA identification and then queries InterfaceFlags.

        .NOTES
        Requires the PSCertutil module to be installed and loaded.
        This function must be called after Set-CAComputerPrincipal has set the CAFullName property.
        
        The function silently skips CAs that:
        - Don't have a CAFullName property
        - Are unreachable or don't respond to certutil queries
        - Return errors from Get-PCInterfaceFlag

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
        Write-Verbose "Querying InterfaceFlags for Certification Authorities..."
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
                    Write-Verbose "  CA '$caName' has no CAFullName property - skipping InterfaceFlags query"
                    $_
                    continue
                }
                
                Write-Verbose "  Querying InterfaceFlags for: $caFullName"
                
                try {
                    # Query InterfaceFlags using PSCertutil
                    $interfaceFlags = Get-PCInterfaceFlag -CAFullName $caFullName -ErrorAction Stop
                    
                    if ($interfaceFlags) {
                        Write-Verbose "  Retrieved $(@($interfaceFlags).Count) InterfaceFlags"
                        
                        # Check specifically for IF_ENFORCEENCRYPTICERTREQUEST
                        $encryptionFlag = $interfaceFlags | Where-Object { $_.InterfaceFlag.ToString() -eq 'IF_ENFORCEENCRYPTICERTREQUEST' }
                        $rpcEncryptionNotRequired = if ($encryptionFlag) { -not $encryptionFlag.Enabled } else { $true }
                        
                        Write-Verbose "  IF_ENFORCEENCRYPTICERTREQUEST is $(if ($rpcEncryptionNotRequired) { 'disabled or missing - RPC encryption not required' } else { 'enabled - RPC encryption required' })"
                        
                        # Update the AD CS Object Store
                        $dn = $_.Properties.distinguishedName[0]
                        if ($script:AdcsObjectStore.ContainsKey($dn)) {
                            $script:AdcsObjectStore[$dn].InterfaceFlags = $interfaceFlags
                            $script:AdcsObjectStore[$dn].RPCEncryptionNotRequired = $rpcEncryptionNotRequired
                            Write-Verbose "  Updated AD CS Object Store for $dn with InterfaceFlags data"
                        }
                        
                        # Also add to the pipeline object for backward compatibility
                        $_ | Add-Member -NotePropertyName InterfaceFlags -NotePropertyValue $interfaceFlags -Force
                        $_ | Add-Member -NotePropertyName RPCEncryptionNotRequired -NotePropertyValue $rpcEncryptionNotRequired -Force
                        
                    } else {
                        Write-Verbose "  No InterfaceFlags returned from Get-PCInterfaceFlag"
                    }
                    
                } catch {
                    Write-Verbose "  Failed to query InterfaceFlags for '$caFullName': $($_.Exception.Message)"
                    # Continue processing other CAs
                }
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'InterfaceFlagQueryFailed',
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
        Write-Verbose "Done querying InterfaceFlags for Certification Authorities."
    }
}
