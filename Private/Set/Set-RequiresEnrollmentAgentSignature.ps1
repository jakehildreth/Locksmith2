function Set-RequiresEnrollmentAgentSignature {
    <#
        .SYNOPSIS
        Adds a RequiresEnrollmentAgentSignature property to AD CS certificate template objects.

        .DESCRIPTION
        Examines the msPKI-RA-Signature and msPKI-RA-Application-Policies attributes of Active Directory
        Certificate Services certificate template objects to determine if they require enrollment agent
        signatures for certificate requests.
        
        The function checks for:
        - msPKI-RA-Signature = 1 (requires authorized signature)
        - msPKI-RA-Application-Policies contains '1.3.6.1.4.1.311.20.2.1' (Certificate Request Agent)
        
        Templates with these settings are vulnerable to ESC3 Condition 2 attacks, where holders of
        enrollment agent certificates can request certificates on behalf of other principals.
        
        The function adds a boolean RequiresEnrollmentAgentSignature property to each input object
        indicating whether the template requires enrollment agent signatures.

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS certificate templates.
        These objects must contain the msPKI-RA-Signature and msPKI-RA-Application-Policies attributes.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe certificate template DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with an added RequiresEnrollmentAgentSignature boolean property.

        .EXAMPLE
        $templates = Get-AdcsObject -RootDSE $rootDSE | Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        $templates | Set-RequiresEnrollmentAgentSignature
        Processes all certificate templates and adds the RequiresEnrollmentAgentSignature property to each.

        .EXAMPLE
        Get-AdcsObject -RootDSE $rootDSE | Set-RequiresEnrollmentAgentSignature | Where-Object RequiresEnrollmentAgentSignature
        Retrieves all AD CS objects, adds RequiresEnrollmentAgentSignature property, and filters to vulnerable templates.

        .NOTES
        Templates requiring enrollment agent signatures (ESC3 Condition 2) are vulnerable when:
        - msPKI-RA-Signature = 1 (requires authorized signature)
        - msPKI-RA-Application-Policies contains Certificate Request Agent EKU
        - Template includes Client Authentication EKU
        - Enrollment permissions granted to low-privilege or dangerous principals
        
        An attacker with an enrollment agent certificate can use these templates to request
        certificates on behalf of other principals and authenticate as them.

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
        Write-Verbose "Identifying templates that require enrollment agent signatures..."
        $enrollmentAgentEKU = '1.3.6.1.4.1.311.20.2.1'
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
                
                $requiresEnrollmentAgentSignature = $false
                
                # Check if msPKI-RA-Signature = 1 (requires authorized signature)
                if ($_.Properties.'msPKI-RA-Signature'.Count -gt 0) {
                    [int]$raSignature = $_.Properties.'msPKI-RA-Signature'[0]
                    Write-Verbose "msPKI-RA-Signature value: $raSignature"
                    
                    # Check if msPKI-RA-Application-Policies contains enrollment agent EKU
                    if ($raSignature -eq 1 -and $_.Properties.'msPKI-RA-Application-Policies'.Count -gt 0) {
                        $raPolicies = $_.Properties.'msPKI-RA-Application-Policies'
                        Write-Verbose "msPKI-RA-Application-Policies contains $($raPolicies.Count) policy/ies: $($raPolicies -join ', ')"
                        
                        if ($enrollmentAgentEKU -in $raPolicies) {
                            $requiresEnrollmentAgentSignature = $true
                            Write-Verbose "Template requires enrollment agent signature"
                        } else {
                            Write-Verbose "Template requires signature but not from enrollment agent"
                        }
                    } else {
                        Write-Verbose "Template does not require enrollment agent signature (RA-Signature: $raSignature)"
                    }
                } else {
                    Write-Verbose "msPKI-RA-Signature not present or is 0 - no signature required"
                }
                
                # Update the AdcsObjectStore with the RequiresEnrollmentAgentSignature property
                $dn = $_.Properties.distinguishedName[0]
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName RequiresEnrollmentAgentSignature -NotePropertyValue $requiresEnrollmentAgentSignature -Force
                    Write-Verbose "Updated AD CS Object Store for $dn with RequiresEnrollmentAgentSignature = $requiresEnrollmentAgentSignature"
                }
                
                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName RequiresEnrollmentAgentSignature -NotePropertyValue $requiresEnrollmentAgentSignature -Force
                
                # Return the modified object
                $_
            }
            catch {
                Write-Error "Error processing template $($_.Properties.distinguishedName[0]): $_"
            }
        }
    }

    end {
        Write-Verbose "Finished identifying templates requiring enrollment agent signatures"
    }
}
