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
    [OutputType([LS2AdcsObject[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [LS2AdcsObject[]]$AdcsObject
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Identifying templates that require enrollment agent signatures..."
        $enrollmentAgentEKU = '1.3.6.1.4.1.311.20.2.1'
    }

    process {
        $AdcsObject | Where-Object SchemaClassName -EQ pKICertificateTemplate | ForEach-Object {
            try {
                $objectName = $_.GetFriendlyName()
                Write-Verbose "Processing template: $objectName"
                
                $requiresEnrollmentAgentSignature = $false
                
                # Check if RASignature = 1 (requires authorized signature)
                if ($null -ne $_.RASignature) {
                    [int]$raSignature = $_.RASignature
                    Write-Verbose "msPKI-RA-Signature value: $raSignature"
                    
                    # Check if RAApplicationPolicies contains enrollment agent EKU
                    if ($raSignature -eq 1 -and $_.RAApplicationPolicies.Count -gt 0) {
                        $raPolicies = $_.RAApplicationPolicies
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
                    Write-Verbose "RASignature not present or is 0 - no signature required"
                }
                
                # Set the property directly on the LS2AdcsObject (same reference as store)
                $_.RequiresEnrollmentAgentSignature = $requiresEnrollmentAgentSignature
                Write-Verbose "Updated $($_.distinguishedName) with RequiresEnrollmentAgentSignature = $requiresEnrollmentAgentSignature"
                
                # Return the modified object
                $_
            } catch {
                Write-Error "Error processing template $($_.distinguishedName): $_"
            }
        }
    }

    end {
        Write-Verbose "Finished identifying templates requiring enrollment agent signatures"
    }
}
