function Set-CADisableExtensionList {
    <#
    .SYNOPSIS
        Queries and stores the Disable Extension List configuration for each Certification Authority.

    .DESCRIPTION
        This function queries the DisableExtensionList registry value for each CA using PSCertutil's
        Get-PCDisableExtensionList cmdlet. The DisableExtensionList indicates which certificate extensions
        are disabled on the CA, which is relevant for ESC16 detection (disabled CRL/AIA extensions).

        The function updates the AdcsObjectStore with:
        - DisableExtensionList: Array of disabled extension OIDs
        - SecurityExtensionDisabled: Boolean indicating if the security extension (1.3.6.1.4.1.311.25.2) is disabled

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
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObject
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
                
                # Extract the DN from the DirectoryEntry
                $dn = if ($_.Properties -and $_.Properties.Contains('distinguishedName')) {
                    $_.Properties['distinguishedName'][0]
                } elseif ($_.distinguishedName) {
                    $_.distinguishedName
                } else {
                    Write-Warning "Could not extract DistinguishedName for CA: $caName"
                    $_
                    return
                }

                # Get the CAFullName from the AdcsObjectStore
                if (-not $script:AdcsObjectStore.ContainsKey($dn)) {
                    Write-Warning "CA '$dn' not found in AD CS Object Store"
                    $_
                    return
                }

                $caFullName = $script:AdcsObjectStore[$dn].CAFullName
                if ([string]::IsNullOrEmpty($caFullName)) {
                    Write-Warning "CAFullName is empty for CA: $dn"
                    $_
                    return
                }

                Write-Verbose "  Querying DisableExtensionList for: $caFullName"

                # Query DisableExtensionList using PSCertutil
                $disableExtensionListResult = Get-PCDisableExtensionList -CAFullName $caFullName -ErrorAction Stop
                
                # Get-PCDisableExtensionList returns an array of objects with DisabledExtension property
                # or $null if no extensions are disabled
                # Force array wrapping with @() for PS 5.1 compatibility (.Count on single objects)
                if ($disableExtensionListResult -and @($disableExtensionListResult).Count -gt 0) {
                    # Extract the extension OIDs/names into an array
                    $disabledExtensions = $disableExtensionListResult | ForEach-Object { $_.DisabledExtension }
                    Write-Verbose "  Retrieved $($disabledExtensions.Count) disabled extension(s): $($disabledExtensions -join ', ')"
                    
                    # Check if the Microsoft Certificate Template Information extension is disabled
                    # OID: 1.3.6.1.4.1.311.25.2 (szOID_CERTIFICATE_TEMPLATE)
                    $securityExtensionDisabled = $disabledExtensions -contains '1.3.6.1.4.1.311.25.2'
                    
                    if ($securityExtensionDisabled) {
                        Write-Verbose "  CRITICAL: Security extension (1.3.6.1.4.1.311.25.2) is DISABLED"
                    } else {
                        Write-Verbose "  Security extension (1.3.6.1.4.1.311.25.2) is enabled"
                    }
                    
                    # Update the AD CS Object Store
                    if ($script:AdcsObjectStore.ContainsKey($dn)) {
                        $script:AdcsObjectStore[$dn].DisableExtensionList = $disabledExtensions
                        $script:AdcsObjectStore[$dn].SecurityExtensionDisabled = $securityExtensionDisabled
                        Write-Verbose "  Updated AD CS Object Store for $dn with DisableExtensionList and SecurityExtensionDisabled"
                    }
                } else {
                    # No extensions disabled - store empty array and false
                    Write-Verbose "  No extensions disabled on this CA"
                    if ($script:AdcsObjectStore.ContainsKey($dn)) {
                        $script:AdcsObjectStore[$dn].DisableExtensionList = @()
                        $script:AdcsObjectStore[$dn].SecurityExtensionDisabled = $false
                        Write-Verbose "  Updated AD CS Object Store for $dn with empty DisableExtensionList"
                    }
                }
            } catch {
                Write-Verbose "  Failed to query DisableExtensionList for '$caFullName': $($_.Exception.Message)"
                
                # Set to null on error
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].DisableExtensionList = $null
                    $script:AdcsObjectStore[$dn].SecurityExtensionDisabled = $null
                }
            }
            
            # Always return the object to continue the pipeline
            $_
        }
    }

    end {
        Write-Verbose "Completed DisableExtensionList queries for all CAs"
    }
}
