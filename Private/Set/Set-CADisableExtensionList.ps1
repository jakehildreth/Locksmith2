function Set-CADisableExtensionList {
    <#
    .SYNOPSIS
        Queries and stores the Disable Extension List configuration for each Certification Authority.

    .DESCRIPTION
        This function queries the DisableExtensionList registry value for each CA using PSCertutil's
        Get-PCDisableExtensionList cmdlet. The DisableExtensionList indicates which certificate extensions
        are disabled on the CA, which is relevant for ESC16 detection (disabled CRL/AIA extensions).

        The function updates the AdcsObjectStore with an array of disabled extension OIDs for each CA.

    .PARAMETER InputObject
        Pipeline input from previous Set-CA* functions. Must contain DistinguishedName and CAFullName properties.

    .OUTPUTS
        PSCustomObject with DistinguishedName and CAFullName properties for pipeline continuation.

    .EXAMPLE
        Set-CAComputerPrincipal | Set-CAInterfaceFlags | Set-CAEditFlags | Set-CAAuditFilter | Set-CADisableExtensionList

    .NOTES
        Requires PSCertutil module with Get-PCDisableExtensionList cmdlet.
        Part of the CA configuration pipeline in Invoke-Locksmith2.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]$InputObject
    )

    begin {
        Write-Verbose "Querying DisableExtensionList for Certification Authorities..."
        
        # Verify PSCertutil is available
        if (-not (Get-Command -Name Get-PCDisableExtensionList -ErrorAction SilentlyContinue)) {
            Write-Error "Get-PCDisableExtensionList cmdlet not found. Please ensure PSCertutil module is loaded."
            return
        }
    }

    process {
        foreach ($ca in $InputObject) {
            Write-Verbose "Processing CA: $($ca.Name)"
            
            # Extract the DN from the DirectoryEntry if needed
            $dn = if ($ca.DistinguishedName -is [System.DirectoryServices.PropertyValueCollection]) {
                $ca.DistinguishedName[0]
            } elseif ($ca.DistinguishedName -is [string]) {
                $ca.DistinguishedName
            } else {
                Write-Warning "Could not extract DistinguishedName for CA: $($ca.Name)"
                continue
            }

            # Get the CAFullName from the AdcsObjectStore
            if (-not $script:AdcsObjectStore.ContainsKey($dn)) {
                Write-Warning "CA '$dn' not found in AD CS Object Store"
                continue
            }

            $caFullName = $script:AdcsObjectStore[$dn].CAFullName
            if ([string]::IsNullOrEmpty($caFullName)) {
                Write-Warning "CAFullName is empty for CA: $dn"
                continue
            }

            Write-Verbose "  Querying DisableExtensionList for: $caFullName"

            try {
                # Query DisableExtensionList using PSCertutil
                $disableExtensionListResult = Get-PCDisableExtensionList -CAFullName $caFullName -ErrorAction Stop

                # Get-PCDisableExtensionList returns an array of objects with DisabledExtension property
                # or $null if no extensions are disabled
                if ($disableExtensionListResult -and $disableExtensionListResult.Count -gt 0) {
                    # Extract the extension OIDs/names into an array
                    $disabledExtensions = $disableExtensionListResult | ForEach-Object { $_.DisabledExtension }
                    Write-Verbose "  Retrieved $($disabledExtensions.Count) disabled extension(s): $($disabledExtensions -join ', ')"
                    
                    # Update the AD CS Object Store
                    if ($script:AdcsObjectStore.ContainsKey($dn)) {
                        $script:AdcsObjectStore[$dn].DisableExtensionList = $disabledExtensions
                        Write-Verbose "  Updated AD CS Object Store for $dn with DisableExtensionList data"
                    }
                } else {
                    # No extensions disabled - store empty array
                    Write-Verbose "  No extensions disabled on this CA"
                    if ($script:AdcsObjectStore.ContainsKey($dn)) {
                        $script:AdcsObjectStore[$dn].DisableExtensionList = @()
                        Write-Verbose "  Updated AD CS Object Store for $dn with empty DisableExtensionList"
                    }
                }

                # Add DisableExtensionList to the pipeline object for backward compatibility
                $ca | Add-Member -MemberType NoteProperty -Name DisableExtensionList -Value $disabledExtensions -Force

            } catch {
                Write-Verbose "  Failed to query DisableExtensionList for '$caFullName': $($_.Exception.Message)"
                
                # Set to null on error
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].DisableExtensionList = $null
                }
            }

            # Pass the object along the pipeline
            $ca
        }
    }

    end {
        Write-Verbose "Completed DisableExtensionList queries for all CAs"
    }
}
