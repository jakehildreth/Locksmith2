function Set-CAComputerPrincipal {
    <#
        .SYNOPSIS
        Adds CA identification and computer principal properties to AD CS Certification Authority objects.

        .DESCRIPTION
        For each pKIEnrollmentService (CA) object, looks up the corresponding computer
        principal in Active Directory using the dNSHostName property. This allows
        correlation between CA objects and their host computer accounts for security analysis.
        
        This function adds two synthetic properties to each CA object:
        - CAFullName: Combined display name in format "CAName (dNSHostName)"
        - ComputerPrincipal: The SID of the computer account hosting the CA, or $null if not found

        The function uses New-GCSearcher for Global Catalog lookups and Resolve-Principal
        for consistent principal resolution and caching in the PrincipalStore.

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS Certification Authorities.

        .INPUTS
        DirectoryEntry objects representing pKIEnrollmentService objects.

        .OUTPUTS
        DirectoryEntry objects with added ComputerPrincipal property.

        .EXAMPLE
        $cas | Set-CAComputerPrincipal

        .NOTES
        This function must be called after Get-AdcsObject has populated the AdcsObjectStore
        with CA objects. It requires the dNSHostName property on CA objects to locate
        the corresponding computer account.
        
        The computer principal is looked up using a Global Catalog search for efficiency
        in multi-domain forests.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObject
    )

    begin {
        Write-Verbose "Identifying computer principals for Certification Authorities..."
    }

    process {
        $AdcsObject | Where-Object SchemaClassName -EQ pKIEnrollmentService | ForEach-Object {
            try {
                # Extract CA name - check both DirectoryEntry Properties and direct property
                $caName = if ($_.Properties -and $_.Properties.Contains('cn')) {
                    $_.Properties['cn'][0]
                } elseif ($_.cn) {
                    $_.cn
                } else {
                    $null
                }
                
                # Extract dNSHostName - check both DirectoryEntry Properties and direct property
                $dnsHostName = if ($_.Properties -and $_.Properties.Contains('dNSHostName')) {
                    $_.Properties['dNSHostName'][0]
                } elseif ($_.dNSHostName) {
                    $_.dNSHostName
                } else {
                    $null
                }
                
                Write-Verbose "Processing CA: $caName"
                
                if (-not $dnsHostName) {
                    Write-Verbose "  CA '$caName' has no dNSHostName property - cannot locate computer principal"
                    $computerSID = $null
                } else {
                    Write-Verbose "  CA '$caName' is hosted on: $dnsHostName"
                    
                    # Search for the computer object by dNSHostName using existing infrastructure
                    try {
                        Write-Verbose "  Searching for computer object with dNSHostName = '$dnsHostName'"
                        
                        # Use New-GCSearcher for consistent Global Catalog lookups
                        $gcSearcher = New-GCSearcher -Filter "(&(objectClass=computer)(dNSHostName=$dnsHostName))" -PropertiesToLoad @('objectSid', 'distinguishedName', 'sAMAccountName')
                        
                        if ($gcSearcher) {
                            $result = $gcSearcher.FindOne()
                            
                            if ($result) {
                                $computerDN = $result.Properties['distinguishedname'][0]
                                Write-Verbose "  Found computer object: $computerDN"
                                
                                # Get the SID and convert to SecurityIdentifier
                                $sidBytes = $result.Properties['objectsid'][0]
                                $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                                $computerSID = $sid.Value
                                Write-Verbose "  Computer SID: $computerSID"
                                
                                # Resolve and cache the computer principal for later security auditing
                                # This populates PrincipalStore so subsequent nTSecurityDescriptor audits don't require LDAP queries
                                Resolve-Principal -IdentityReference $sid | Out-Null
                                Write-Verbose "  Cached computer principal in PrincipalStore: $computerSID"
                                
                            } else {
                                Write-Verbose "  Computer object not found for dNSHostName '$dnsHostName'"
                                $computerSID = $null
                            }
                            
                            $gcSearcher.Dispose()
                        } else {
                            Write-Verbose "  Failed to create GC searcher"
                            $computerSID = $null
                        }
                        
                    } catch {
                        Write-Verbose "  Failed to lookup computer principal: $_"
                        $computerSID = $null
                    }
                }
                
                # Update the AD CS Object Store with ComputerPrincipal property
                # Note: CAFullName is now a ScriptProperty on LS2AdcsObject and calculates automatically
                $dn = $_.Properties.distinguishedName[0]
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].ComputerPrincipal = $computerSID
                    Write-Verbose "Updated AD CS Object Store for $dn with ComputerPrincipal = $computerSID"
                }
                
                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName ComputerPrincipal -NotePropertyValue $computerSID -Force
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'CAComputerPrincipalProcessingFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $ca
                )
                $PSCmdlet.WriteError($errorRecord)
                
                # Still return the object even if processing failed
                $_
            }
        }
    }
    
    end {
        Write-Verbose "Done identifying computer principals for Certification Authorities."
    }
}
