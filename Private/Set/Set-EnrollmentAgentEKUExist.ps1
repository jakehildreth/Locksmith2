function Set-EnrollmentAgentEKUExist {
    <#
        .SYNOPSIS
        Adds an EnrollmentAgentEKUExist property to AD CS certificate template objects.

        .DESCRIPTION
        Examines the pKIExtendedKeyUsage attribute of Active Directory Certificate Services
        certificate template objects to determine if they include the Certificate Request Agent
        (Enrollment Agent) Extended Key Usage.
        
        The function checks for the presence of the Enrollment Agent EKU (OID 1.3.6.1.4.1.311.20.2.1).
        Templates with this EKU can be used to request certificates on behalf of other principals,
        which can be abused in ESC3 Condition 1 attacks when combined with other misconfigurations.
        
        The function adds a boolean EnrollmentAgentEKUExist property to each input object
        indicating whether the template includes the Enrollment Agent EKU.

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS certificate templates.
        These objects must contain the pKIExtendedKeyUsage attribute.

        .PARAMETER EnrollmentAgentEKU
        Optional. Array of OID strings representing the Enrollment Agent EKU.
        Default is '1.3.6.1.4.1.311.20.2.1' (Certificate Request Agent).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe certificate template DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with an added EnrollmentAgentEKUExist boolean property.

        .EXAMPLE
        $templates = Get-AdcsObject -RootDSE $rootDSE | Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        $templates | Set-EnrollmentAgentEKUExist
        Processes all certificate templates and adds the EnrollmentAgentEKUExist property to each.

        .EXAMPLE
        Get-AdcsObject -RootDSE $rootDSE | Set-EnrollmentAgentEKUExist | Where-Object EnrollmentAgentEKUExist
        Retrieves all AD CS objects, adds EnrollmentAgentEKUExist property, and filters to only enrollment agent templates.

        .NOTES
        The Certificate Request Agent (Enrollment Agent) EKU allows certificates to be requested
        on behalf of other users. This is commonly used in restricted enrollment scenarios but
        can be dangerous when combined with:
        - No manager approval requirement (msPKI-Enrollment-Flag not set to 2)
        - No authorized signature requirement (msPKI-RA-Signature = 0 or null)
        - Enrollment permissions granted to low-privilege or dangerous principals

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObject,
        
        [Parameter()]
        [string[]]$EnrollmentAgentEKU = @(
            '1.3.6.1.4.1.311.20.2.1'  # Certificate Request Agent
        )
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Identifying templates that create Enrollment Agent certificates..."
    }

    process {
        $AdcsObject | Where-Object SchemaClassName -EQ pKICertificateTemplate | ForEach-Object {
            try {
                $objectName = if ($_.Properties.displayName.Count -gt 0) {
                    $_.Properties.displayName[0] 
                } elseif ($_.Properties.name.Count -gt 0) {
                    $_.Properties.name[0]
                } else {
                    $_.Properties.distinguishedName[0]
                }
                Write-Verbose "Processing template: $objectName"
                
                $enrollmentAgentEKUExist = $false
                
                # Check if pKIExtendedKeyUsage attribute exists and has values
                if ($_.Properties.pKIExtendedKeyUsage.Count -gt 0) {
                    $ekuList = $_.Properties.pKIExtendedKeyUsage
                    Write-Verbose "pKIExtendedKeyUsage contains $($ekuList.Count) EKU(s): $($ekuList -join ', ')"
                    
                    # Check if any of the Enrollment Agent EKUs are present
                    foreach ($eku in $ekuList) {
                        if ($eku -in $EnrollmentAgentEKU) {
                            $enrollmentAgentEKUExist = $true
                            Write-Verbose "Enrollment Agent EKU found: $eku"
                            break
                        }
                    }
                    
                    if (-not $enrollmentAgentEKUExist) {
                        Write-Verbose "No Enrollment Agent EKUs found in template"
                    }
                } else {
                    Write-Verbose "pKIExtendedKeyUsage is empty or not present"
                }
                
                # Update the AdcsObjectStore with the EnrollmentAgentEKUExist property
                $dn = $_.Properties.distinguishedName[0]
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName EnrollmentAgentEKUExist -NotePropertyValue $enrollmentAgentEKUExist -Force
                    Write-Verbose "Updated AD CS Object Store for $dn with EnrollmentAgentEKUExist = $enrollmentAgentEKUExist"
                }
                
                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName EnrollmentAgentEKUExist -NotePropertyValue $enrollmentAgentEKUExist -Force
                
                # Return the modified object
                $_
            } catch {
                Write-Error "Error processing template $($_.Properties.distinguishedName[0]): $_"
            }
        }
    }

    end {
        Write-Verbose "Finished identifying templates with Enrollment Agent EKU"
    }
}
