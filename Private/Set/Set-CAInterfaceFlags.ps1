function Set-CAInterfaceFlags {
    <#
        .SYNOPSIS
        Adds InterfaceFlags configuration properties to AD CS Certification Authority objects.

        .DESCRIPTION
        For each pKIEnrollmentService (CA) object, queries the CA's InterfaceFlags registry
        configuration using PSCertutil's Get-PSCInterfaceFlag cmdlet and stores the results
        in the AdcsObjectStore.
        
        This function tracks various interface flags that control CA RPC/DCOM behavior,
        including the IF_ENFORCEENCRYPTICERTREQUEST flag which when disabled leads to
        the ESC11 vulnerability (allowing unauthenticated/unencrypted certificate requests).
        
        The function adds these properties to each CA object:
        - InterfaceFlags: Array of all InterfaceFlag objects returned by Get-PSCInterfaceFlag
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
        - Return errors from Get-PSCInterfaceFlag

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
        Write-Verbose "Querying InterfaceFlags for Certification Authorities..."
    }

    process {
        $AdcsObject | Where-Object { $_.IsCertificationAuthority() } | ForEach-Object {
            try {
                $caName = $_.cn
                Write-Verbose "Processing CA: $caName"
                
                # Get CAFullName directly from the LS2AdcsObject (ScriptProperty)
                $caFullName = $_.CAFullName
                
                if (-not $caFullName) {
                    Write-Verbose "  CA '$caName' has no CAFullName property - skipping InterfaceFlags query"
                    $_
                    continue
                }
                
                Write-Verbose "  Querying InterfaceFlags for: $caFullName"
                
                try {
                    # Query InterfaceFlags using PSCertutil
                    $interfaceFlags = Get-PSCInterfaceFlag -CAFullName $caFullName -ErrorAction Stop
                    
                    if ($interfaceFlags) {
                        Write-Verbose "  Retrieved $(@($interfaceFlags).Count) InterfaceFlags"
                        
                        # Check specifically for IF_ENFORCEENCRYPTICERTREQUEST
                        $encryptionFlag = $interfaceFlags | Where-Object { $_.InterfaceFlag.ToString() -eq 'IF_ENFORCEENCRYPTICERTREQUEST' }
                        $rpcEncryptionNotRequired = if ($encryptionFlag) { -not $encryptionFlag.Enabled } else { $true }
                        
                        Write-Verbose "  IF_ENFORCEENCRYPTICERTREQUEST is $(if ($rpcEncryptionNotRequired) { 'disabled or missing - RPC encryption not required' } else { 'enabled - RPC encryption required' })"
                        
                        # Set properties directly on the LS2AdcsObject (same reference as store)
                        $_.InterfaceFlags = $interfaceFlags
                        $_.RPCEncryptionNotRequired = $rpcEncryptionNotRequired
                        Write-Verbose "  Updated $($_.distinguishedName) with InterfaceFlags data"
                        
                    } else {
                        Write-Verbose "  No InterfaceFlags returned from Get-PSCInterfaceFlag"
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
