function Set-AuthenticationEKUExist {
    <#
        .SYNOPSIS
        Adds an AuthenticationEKUExist property to AD CS certificate template objects.

        .DESCRIPTION
        Examines the pKIExtendedKeyUsage attribute of Active Directory Certificate Services
        certificate template objects to determine if they can be used for authentication purposes.
        
        The function checks for the presence of authentication-related Extended Key Usage (EKU) OIDs:
        - 1.3.6.1.5.5.7.3.2: Client Authentication
        - 1.3.6.1.5.2.3.4: PKINIT Client Authentication (Kerberos)
        - 1.3.6.1.4.1.311.20.2.2: Smart Card Logon
        
        This is a critical check for ESC1 vulnerability detection in AD CS auditing, as templates
        that allow authentication combined with other risky settings can lead to privilege escalation.
        
        The function adds a boolean AuthenticationEKUExist property to each input object indicating
        whether the template can be used for authentication.

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS certificate templates.
        These objects may contain the pKIExtendedKeyUsage attribute.

        .PARAMETER AuthenticationEKU
        An array of EKU OIDs that are considered authentication-related.
        Default includes Client Authentication, PKINIT Client Authentication, and Smart Card Logon.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe certificate template DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with an added AuthenticationEKUExist boolean property.

        .EXAMPLE
        $templates = Get-AdcsObject -RootDSE $rootDSE | Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        $templates | Set-AuthenticationEKUExist
        Processes all certificate templates and adds the AuthenticationEKUExist property to each.

        .EXAMPLE
        Get-AdcsObject -RootDSE $rootDSE | Set-AuthenticationEKUExist | Where-Object AuthenticationEKUExist
        Retrieves all AD CS objects, adds AuthenticationEKUExist property, and filters to only authentication templates.

        .EXAMPLE
        $template = Get-AdcsObject -RootDSE $rootDSE | Where-Object Name -eq 'WebServer'
        $template | Set-AuthenticationEKUExist
        if ($template.AuthenticationEKUExist) {
            Write-Host "Template can be used for authentication"
        }
        Checks a specific template for authentication capability.

        .EXAMPLE
        $customEKUs = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2')
        Get-AdcsObject -RootDSE $rootDSE | Set-AuthenticationEKUExist -AuthenticationEKU $customEKUs
        Uses a custom list of authentication EKUs to check templates.

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
        
        .LINK
        https://learn.microsoft.com/en-us/windows/win32/seccrypto/extended-key-usage
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObject,
        
        [Parameter()]
        [string[]]$AuthenticationEKU = @(
            '1.3.6.1.5.5.7.3.2',      # Client Authentication
            '1.3.6.1.5.2.3.4',        # PKINIT Client Authentication
            '1.3.6.1.4.1.311.20.2.2'  # Smart Card Logon
        )
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Identifying templates that create authentication certificates..."
    }

    process {
        $AdcsObject | Where-Object SchemaClassName -eq pKICertificateTemplate | ForEach-Object {
            try {
                $objectName = if ($_.Properties.displayName.Count -gt 0) {
                    $_.Properties.displayName[0] 
                } elseif ($_.Properties.name.Count -gt 0) {
                    $_.Properties.name[0]
                } else {
                    $_.Properties.distinguishedName[0]
                }
                Write-Verbose "Processing template: $objectName"
                
                $authenticationEKUExist = $false
                
                # Check if pKIExtendedKeyUsage attribute exists and has values
                if ($_.Properties.pKIExtendedKeyUsage.Count -gt 0) {
                    $ekuList = $_.Properties.pKIExtendedKeyUsage
                    Write-Verbose "pKIExtendedKeyUsage contains $($ekuList.Count) EKU(s): $($ekuList -join ', ')"
                    
                    # Check if any of the Authentication EKUs are present
                    foreach ($eku in $ekuList) {
                        if ($eku -in $AuthenticationEKU) {
                            $authenticationEKUExist = $true
                            Write-Verbose "Authentication EKU found: $eku"
                            break  # No need to check remaining EKUs
                        }
                    }
                    
                    if (-not $authenticationEKUExist) {
                        Write-Verbose "No authentication EKUs found in template"
                    }
                } else {
                    Write-Verbose "pKIExtendedKeyUsage is empty. Template can be used for Any Purpose."
                }
                
                # Update the AdcsObjectStore with the AuthenticationEKUExist property
                $dn = $_.Properties.distinguishedName[0]
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName AuthenticationEKUExist -NotePropertyValue $authenticationEKUExist -Force
                    Write-Verbose "Updated AD CS Object Store for $dn with AuthenticationEKUExist = $authenticationEKUExist"
                }
                
                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName AuthenticationEKUExist -NotePropertyValue $authenticationEKUExist -Force
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'AuthenticationEKUProcessingFailed',
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
        Write-Verbose "Done identifying templates that create authentication certificates."
    }
}
