function Set-SANAllowed {
    <#
        .SYNOPSIS
        Adds a SANAllowed property to AD CS certificate template objects.

        .DESCRIPTION
        Examines the msPKI-Certificate-Name-Flag attribute of Active Directory Certificate Services
        certificate template objects to determine if Subject Alternative Names (SANs) are allowed.
        
        The function checks bit 1 (0x00000001) of the msPKI-Certificate-Name-Flag attribute.
        When this bit is set, the certificate template allows enrollees to specify SANs in
        certificate requests, which can be a security risk if not properly controlled.
        
        This is a key indicator for ESC1 vulnerability detection in AD CS auditing.
        
        The function adds a boolean SANAllowed property to each input object indicating
        whether the template permits SANs.

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS certificate templates.
        These objects must contain the msPKI-Certificate-Name-Flag attribute.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe certificate template DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with an added SANAllowed boolean property.

        .EXAMPLE
        $templates = Get-AdcsObject -RootDSE $rootDSE | Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        $templates | Set-SANAllowed
        Processes all certificate templates and adds the SANAllowed property to each.

        .EXAMPLE
        Get-AdcsObject -RootDSE $rootDSE | Set-SANAllowed | Where-Object SANAllowed
        Retrieves all AD CS objects, adds SANAllowed property, and filters to only those allowing SANs.

        .EXAMPLE
        $template = Get-AdcsObject -RootDSE $rootDSE | Where-Object Name -eq 'WebServer'
        $template | Set-SANAllowed
        if ($template.SANAllowed) {
            Write-Host "Template allows Subject Alternative Names"
        }
        Checks a specific template for SAN permission.

        .NOTES
        The msPKI-Certificate-Name-Flag attribute uses bitwise flags:
        - Bit 1 (0x00000001): ENROLLEE_SUPPLIES_SUBJECT (allows SAN specification)
        
        When SAN is allowed without proper enrollment restrictions, it can lead to
        privilege escalation vulnerabilities (ESC1) by allowing users to request
        certificates for arbitrary principals.

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
        
        .LINK
        https://github.com/GhostPack/Certify
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry[]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObject
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "Starting processing of AD CS objects for SAN flag detection..."
    }

    process {
        $AdcsObject | ForEach-Object {
            try {
                $objectName = if ($_.Properties['name'].Count -gt 0) { $_.Properties['name'][0] } else { $_.distinguishedName }
                Write-Verbose "Processing object: $objectName"
                
                $sanAllowed = $false
                
                # Check if the msPKI-Certificate-Name-Flag attribute exists
                if ($_.Properties['msPKI-Certificate-Name-Flag'].Count -gt 0) {
                    [int]$NameFlag = $_.'msPKI-Certificate-Name-Flag'[0]
                    Write-Verbose "msPKI-Certificate-Name-Flag value: $NameFlag (0x$($NameFlag.ToString('X8')))"
                    
                    # Bit 1 (0x00000001) = ENROLLEE_SUPPLIES_SUBJECT (SAN allowed)
                    if ($NameFlag -band 1) {
                        $sanAllowed = $true
                        Write-Verbose "SAN is ALLOWED (bit 1 is set)"
                    } else {
                        Write-Verbose "SAN is NOT allowed (bit 1 is not set)"
                    }
                } else {
                    Write-Verbose "msPKI-Certificate-Name-Flag attribute not found on object"
                }
                
                # Add the SANAllowed property to the object
                $_ | Add-Member -NotePropertyName SANAllowed -NotePropertyValue $sanAllowed -Force
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'SANFlagProcessingFailed',
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
        Write-Verbose "Completed processing AD CS objects for SAN flag detection."
    }
}
