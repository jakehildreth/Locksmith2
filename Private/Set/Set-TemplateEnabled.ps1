function Set-TemplateEnabled {
    <#
        .SYNOPSIS
        Adds Enabled and EnabledOn properties to AD CS certificate template objects.

        .DESCRIPTION
        Examines the certificateTemplates property of all Certification Authority (CA)
        objects in the AdcsObjectStore to determine which templates are published/enabled
        on which CAs.
        
        This function adds two synthetic properties to each certificate template:
        1. Enabled: Boolean indicating whether the template is published on at least one CA
        2. EnabledOn: Array of CA names where the template is published
        
        A template is considered "enabled" if it appears in the certificateTemplates
        property of at least one pKIEnrollmentService (CA) object. Templates that are
        defined but not published on any CA will have Enabled = $false and EnabledOn = @().

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS certificate templates.

        .INPUTS
        DirectoryEntry objects representing certificate templates.

        .OUTPUTS
        DirectoryEntry objects with added Enabled and EnabledOn properties.

        .EXAMPLE
        $templates | Set-TemplateEnabled

        .NOTES
        This function must be called after Get-AdcsObject has populated the AdcsObjectStore
        with both template and CA objects, including the certificateTemplates property on CAs.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObject
    )

    begin {
        Write-Verbose "Identifying which templates are enabled on which CAs..."

        # Get all CA objects from the store
        $caObjects = $script:AdcsObjectStore.Values | Where-Object { $_.objectClass -contains 'pKIEnrollmentService' }
        Write-Verbose "Found $($caObjects.Count) CA object(s) in AD CS Object Store"

        # Build a mapping of template CN -> list of CA names
        $templateToCAs = @{}

        foreach ($ca in $caObjects) {
            $caName = $ca.name
            Write-Verbose "Processing CA: $caName"

            # Get the certificateTemplates array for this CA
            $publishedTemplates = $ca.certificateTemplates
            if ($publishedTemplates -and $publishedTemplates.Count -gt 0) {
                Write-Verbose "  CA '$caName' has $($publishedTemplates.Count) published template(s)"
                
                foreach ($templateCN in $publishedTemplates) {
                    if (-not $templateToCAs.ContainsKey($templateCN)) {
                        $templateToCAs[$templateCN] = [System.Collections.Generic.List[string]]::new()
                    }
                    $templateToCAs[$templateCN].Add($caName)
                    Write-Verbose "    Template '$templateCN' is published on '$caName'"
                }
            } else {
                Write-Verbose "  CA '$caName' has no published templates"
            }
        }
    }

    process {
        $AdcsObject | Where-Object SchemaClassName -eq pKICertificateTemplate | ForEach-Object {
            try {
                $templateCN = $_.Properties['cn'][0]
                Write-Verbose "Processing template: $templateCN"

                if ($templateToCAs.ContainsKey($templateCN)) {
                    # Template is enabled on one or more CAs
                    $enabledOnCAs = $templateToCAs[$templateCN].ToArray()
                    $enabled = $true
                    Write-Verbose "  Template '$templateCN' is ENABLED on $($enabledOnCAs.Count) CA(s): $($enabledOnCAs -join ', ')"
                } else {
                    # Template is not published on any CA
                    $enabledOnCAs = @()
                    $enabled = $false
                    Write-Verbose "  Template '$templateCN' is NOT enabled on any CA"
                }

                # Update the AD CS Object Store with the properties
                $dn = $_.Properties.distinguishedName[0]
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn].Enabled = $enabled
                    $script:AdcsObjectStore[$dn].EnabledOn = $enabledOnCAs
                    Write-Verbose "Updated AD CS Object Store for $dn with Enabled = $enabled and EnabledOn"
                }

                # Return the modified object
                $_

            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'TemplateEnabledProcessingFailed',
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
        Write-Verbose "Done identifying which templates are enabled on which CAs."
    }
}
