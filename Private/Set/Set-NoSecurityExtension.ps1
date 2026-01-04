function Set-NoSecurityExtension {
    <#
        .SYNOPSIS
        Adds a NoSecurityExtension property to AD CS certificate template objects.

        .DESCRIPTION
        Examines the msPKI-Enrollment-Flag attribute of Active Directory Certificate Services
        certificate template objects to determine if the szOID_NTDS_CA_SECURITY_EXT security
        extension is disabled (ESC9).
        
        The function checks if the CT_FLAG_NO_SECURITY_EXTENSION flag (0x80000) is set in the
        msPKI-Enrollment-Flag attribute. When this flag is set, certificates issued from the
        template will not enforce strong certificate binding, making them vulnerable to ESC9.
        
        Templates with this flag disabled combined with client authentication EKUs can be
        exploited by modifying userPrincipalName or dNSHostName attributes to impersonate
        higher-privileged accounts.
        
        The function adds a boolean NoSecurityExtension property to each input object
        indicating whether the template has the security extension disabled.

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS certificate templates.
        These objects must contain the msPKI-Enrollment-Flag attribute.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe certificate template DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with an added NoSecurityExtension boolean property.

        .EXAMPLE
        $templates = Get-AdcsObject -RootDSE $rootDSE | Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        $templates | Set-NoSecurityExtension
        Processes all certificate templates and adds the NoSecurityExtension property to each.

        .EXAMPLE
        Get-AdcsObject -RootDSE $rootDSE | Set-NoSecurityExtension | Where-Object NoSecurityExtension
        Retrieves all AD CS objects, adds NoSecurityExtension property, and filters to vulnerable templates.

        .NOTES
        The CT_FLAG_NO_SECURITY_EXTENSION flag (0x80000) in msPKI-Enrollment-Flag indicates that
        the szOID_NTDS_CA_SECURITY_EXT security extension is disabled on certificates issued
        from this template.
        
        When this flag is set (security extension disabled), certificates do not enforce strong
        certificate binding. Combined with client authentication EKU and the ability to modify
        userPrincipalName or dNSHostName, this creates the ESC9 vulnerability.
        
        Strong certificate binding enforcement was introduced in KB5014754 to prevent these
        types of attacks by requiring proper subject-to-certificate mapping.

        .LINK
        https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc9-no-security-extension-on-certificate-template
        
        .LINK
        https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObject
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Identifying templates with szOID_NTDS_CA_SECURITY_EXT disabled (ESC9)..."
        $CT_FLAG_NO_SECURITY_EXTENSION = 0x80000
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
                
                $noSecurityExtension = $false
                
                # Check if msPKI-Enrollment-Flag has CT_FLAG_NO_SECURITY_EXTENSION set
                if ($_.Properties.'msPKI-Enrollment-Flag'.Count -gt 0) {
                    [int]$enrollmentFlag = $_.Properties.'msPKI-Enrollment-Flag'[0]
                    Write-Verbose "msPKI-Enrollment-Flag value: $enrollmentFlag"
                    
                    if ($enrollmentFlag -band $CT_FLAG_NO_SECURITY_EXTENSION) {
                        $noSecurityExtension = $true
                        Write-Verbose "CT_FLAG_NO_SECURITY_EXTENSION is SET - security extension disabled (ESC9 vulnerable)"
                    } else {
                        Write-Verbose "CT_FLAG_NO_SECURITY_EXTENSION is NOT set - security extension enabled"
                    }
                } else {
                    Write-Verbose "msPKI-Enrollment-Flag not present - security extension enabled by default"
                }
                
                # Update the AdcsObjectStore with the NoSecurityExtension property
                $dn = $_.Properties.distinguishedName[0]
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName NoSecurityExtension -NotePropertyValue $noSecurityExtension -Force
                    Write-Verbose "Updated AD CS Object Store for $dn with NoSecurityExtension = $noSecurityExtension"
                }
                
                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName NoSecurityExtension -NotePropertyValue $noSecurityExtension -Force
                
                # Return the modified object
                $_
            } catch {
                Write-Error "Error processing template $($_.Properties.distinguishedName[0]): $_"
            }
        }
    }

    end {
        Write-Verbose "Finished identifying templates with security extension disabled"
    }
}
