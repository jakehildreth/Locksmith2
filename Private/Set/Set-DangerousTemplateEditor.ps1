function Set-DangerousTemplateEditor {
    <#
        .SYNOPSIS
        Adds a DangerousTemplateEditor property to AD CS certificate template objects.

        .DESCRIPTION
        Examines the access control lists (ACLs) of Active Directory Certificate Services
        certificate template objects to identify principals with dangerous write/modify permissions.
        
        The function checks for permissions that allow principals to modify template settings,
        granted to well-known dangerous principals that represent overly broad groups. These
        should typically not have write access to templates, as they can lead to privilege
        escalation vulnerabilities through ESC4 attacks.
        
        Dangerous permissions include GenericAll, GenericWrite, WriteDacl, WriteOwner, and
        WriteProperty on security-critical template attributes (msPKI-Certificate-Name-Flag,
        pKIExtendedKeyUsage, msPKI-Enrollment-Flag, etc.).
        
        This is a critical check for ESC4 vulnerability detection, as templates with dangerous
        editors can be modified to create ESC1, ESC2, ESC3, or ESC9 conditions.
        
        The function adds two properties to each template object:
        1. DangerousTemplateEditor: Array of SIDs for dangerous principals with write access
        2. DangerousTemplateEditorNames: Array of human-readable names formatted as "DOMAIN\User (SID)"
           or "SID (could not resolve)" if the principal cannot be resolved.

        .PARAMETER AdcsObject
        One or more DirectoryEntry objects representing AD CS certificate templates.
        These objects must contain ObjectSecurity.Access information.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        You can pipe certificate template DirectoryEntry objects to this function.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the input objects with added properties:
        - DangerousTemplateEditor: Array of SIDs
        - DangerousTemplateEditorNames: Array of human-readable names

        .EXAMPLE
        $templates = Get-AdcsObject | 
            Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        $templates | Set-DangerousTemplateEditor
        Processes all certificate templates and adds the DangerousTemplateEditor property to each.

        .EXAMPLE
        Get-AdcsObject | 
            Set-DangerousTemplateEditor | 
            Where-Object { $_.DangerousTemplateEditor.Count -gt 0 }
        Retrieves all AD CS objects, adds DangerousTemplateEditor property, and filters to 
        only those with dangerous editors.

        .EXAMPLE
        $template = Get-AdcsObject | Where-Object Name -eq 'WebServer'
        $template | Set-DangerousTemplateEditor
        if ($template.DangerousTemplateEditor) {
            Write-Host "Template has dangerous editors:"
            $template.DangerousTemplateEditorNames | ForEach-Object { Write-Host "  $_" }
        }
        Checks a specific template for dangerous editors and displays human-readable names.

        .NOTES
        Well-known dangerous principals checked by default:
        - S-1-0-0: NULL SID
        - S-1-1-0: Everyone (all users possibly including anonymous)
        - S-1-5-7: Anonymous Logon
        - S-1-5-32-545: BUILTIN\Users
        - S-1-5-11: Authenticated Users
        - SIDs ending in -513: Domain Users groups
        - SIDs ending in -515: Domain Computers groups
        
        Templates with these principals having write permissions are considered
        high-risk as they can be modified to create additional vulnerabilities (ESC4).

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
        Write-Verbose "Identifying templates with dangerous principals that have write access..."
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
                
                [array]$dangerousIdentityReference = foreach ($ace in $_.ObjectSecurity.Access) {
                    # Test if ACE grants dangerous write permissions first
                    $isDangerousAce = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                    if ($isDangerousAce.IsDangerous) {
                        # Now check if the principal holding this ACE is dangerous
                        $aceSid = $ace.IdentityReference | Convert-IdentityReferenceToSid
                        $isDangerousPrincipal = $aceSid | Test-IsDangerousPrincipal
                        if ($isDangerousPrincipal) {
                            Write-Verbose "Dangerous template editor found: $($ace.IdentityReference) ($($isDangerousAce.MatchedPermission))"
                            # Ensure the principal is in the store (triggers cache population)
                            $null = $ace.IdentityReference | Resolve-Principal
                            # Convert to SID and return as the key to PrincipalStore
                            $aceSid.Value
                        }
                    }
                }

                $dangerousIdentityReference = $dangerousIdentityReference | Sort-Object -Unique
                
                if ($dangerousIdentityReference) {
                    Write-Verbose "Template has $($dangerousIdentityReference.Count) dangerous editor(s): $($dangerousIdentityReference -join ', ')"
                } else {
                    Write-Verbose "No dangerous editors found in template"
                }

                # Build human-readable names array from PrincipalStore
                [array]$dangerousEditorNames = $dangerousIdentityReference | ForEach-Object {
                    if ($script:PrincipalStore -and $script:PrincipalStore.ContainsKey($_)) {
                        $name = $script:PrincipalStore[$_].ntAccountName
                        if ($name) {
                            "$name ($_)"
                        } else {
                            "$_ (could not resolve)"
                        }
                    } else {
                        "$_ (could not resolve)"
                    }
                } | Sort-Object -Unique

                # Update the AD CS Object Store with the DangerousTemplateEditor property
                $dn = $_.Properties.distinguishedName[0]
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName DangerousTemplateEditor -NotePropertyValue $dangerousIdentityReference -Force
                    $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName DangerousTemplateEditorNames -NotePropertyValue $dangerousEditorNames -Force
                    Write-Verbose "Updated AD CS Object Store for $dn with DangerousTemplateEditor"
                }

                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName DangerousTemplateEditor -NotePropertyValue $dangerousIdentityReference -Force
                $_ | Add-Member -NotePropertyName DangerousTemplateEditorNames -NotePropertyValue $dangerousEditorNames -Force
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'DangerousTemplateEditorProcessingFailed',
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
        Write-Verbose "Done identifying templates with dangerous principals that have write access."
    }
}
