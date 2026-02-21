function Set-CAAdministrator {
    <#
        .SYNOPSIS
        Adds CA Administrator role configuration to AD CS Certification Authority objects.

        .DESCRIPTION
        For each pKIEnrollmentService (CA) object, queries the CA's CA Administrator
        role assignments using PSCertutil's Get-PCCAAdministrator cmdlet and stores the 
        results in the AdcsObjectStore.
        
        CA Administrators have full control over the CA and can approve certificate requests,
        modify CA configuration, and perform other administrative tasks. Excessive or 
        inappropriate CA Administrator assignments can lead to ESC7 vulnerabilities.
        
        The function adds these properties to each CA object:
        - CAAdministrators: Array of all CA Administrator objects returned by Get-PCCAAdministrator

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS Certification Authorities.
        Must have the CAFullName property set (typically by Set-CAComputerPrincipal).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe CA DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with added CAAdministrators property.

        .EXAMPLE
        $cas | Set-CAAdministrator
        Queries CA Administrators for all CAs and stores the results.

        .EXAMPLE
        $cas | Set-CAComputerPrincipal | Set-CAAdministrator
        Sets up CA identification and then queries CA Administrators.

        .NOTES
        Requires the PSCertutil module to be installed and loaded.
        This function must be called after Set-CAComputerPrincipal has set the CAFullName property.
        
        The function silently skips CAs that:
        - Don't have a CAFullName property
        - Are unreachable or don't respond to certutil queries
        - Return errors from Get-PCCAAdministrator

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
        Write-Verbose "Querying CA Administrators for Certification Authorities..."
    }

    process {
        $AdcsObject | Where-Object { $_.IsCertificationAuthority() } | ForEach-Object {
            try {
                $caName = $_.cn
                Write-Verbose "Processing CA: $caName"
                
                # Get CAFullName directly from the LS2AdcsObject (ScriptProperty)
                $caFullName = $_.CAFullName
                
                if (-not $caFullName) {
                    Write-Verbose "  CA '$caName' has no CAFullName property - skipping CA Administrators query"
                    $_
                    return
                }
                
                Write-Verbose "  Querying CA Administrators for: $caFullName"
                
                try {
                    # Query CA Administrators using PSCertutil
                    $caAdministrators = Get-PCCAAdministrator -CAFullName $caFullName -ErrorAction Stop
                    
                    if ($caAdministrators) {
                        $adminCount = @($caAdministrators).Count
                        Write-Verbose "  Retrieved $adminCount CA Administrator(s)"
                        
                        # Resolve and cache each administrator in PrincipalStore
                        foreach ($admin in $caAdministrators) {
                            Write-Verbose "    CA Administrator: $($admin.CAAdministrator)"
                            
                            try {
                                # Convert the string to an NTAccount and resolve to cache in PrincipalStore
                                $ntAccount = New-Object System.Security.Principal.NTAccount($admin.CAAdministrator)
                                $null = Resolve-Principal -IdentityReference $ntAccount
                                Write-Verbose "      Cached principal in PrincipalStore"
                            } catch {
                                Write-Verbose "      Failed to resolve principal: $($_.Exception.Message)"
                            }
                        }
                        
                        # Set the property directly on the LS2AdcsObject (same reference as store)
                        $_.CAAdministrators = $caAdministrators
                        Write-Verbose "  Updated $($_.distinguishedName) with CA Administrator data"
                        
                    } else {
                        Write-Verbose "  No CA Administrators returned from Get-PCCAAdministrator"
                    }
                    
                } catch {
                    Write-Verbose "  Failed to query CA Administrators for '$caFullName': $($_.Exception.Message)"
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
        Write-Verbose "CA Administrator query complete"
    }
}
