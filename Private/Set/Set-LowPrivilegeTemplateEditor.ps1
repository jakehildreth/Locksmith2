function Set-LowPrivilegeTemplateEditor {
    <#
        .SYNOPSIS
        Adds a LowPrivilegeTemplateEditor property to AD CS certificate template objects.

        .DESCRIPTION
        Examines the access control lists (ACLs) of Active Directory Certificate Services
        certificate template objects to identify write/modify permissions granted to principals
        that are neither high-privilege administrators nor overly broad dangerous groups.
        
        This function identifies "middle ground" editors - specific users or groups that have
        dangerous write permissions on templates but aren't part of the standard administrative
        hierarchy or the dangerous principals that represent broad attack surfaces.
        
        The function excludes two categories of principals:
        1. Safe/Administrative principals: Domain Admins, Enterprise Admins, SYSTEM, etc.
        2. Dangerous principals: Everyone, Authenticated Users, Domain Users, etc.
        
        What remains are custom editors that may represent specific service accounts, security
        groups, or users that have been granted write permissions outside the standard model.
        These should be reviewed as they can modify templates to create ESC4-style vulnerabilities.
        
        The function adds two properties to each template object:
        1. LowPrivilegeTemplateEditor: Array of SIDs for custom editors with write access
        2. LowPrivilegeTemplateEditorNames: Array of human-readable names formatted as "DOMAIN\User (SID)"
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
        - LowPrivilegeTemplateEditor: Array of SIDs
        - LowPrivilegeTemplateEditorNames: Array of human-readable names

        .EXAMPLE
        $templates = Get-AdcsObject | 
            Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        $templates | Set-LowPrivilegeTemplateEditor
        Processes all certificate templates and adds the LowPrivilegeTemplateEditor property to each.

        .EXAMPLE
        Get-AdcsObject | 
            Set-LowPrivilegeTemplateEditor | 
            Where-Object { $_.LowPrivilegeTemplateEditor.Count -gt 0 }
        Retrieves all AD CS objects, adds LowPrivilegeTemplateEditor property, and filters to 
        only those with custom editors.

        .EXAMPLE
        $template = Get-AdcsObject | Where-Object Name -eq 'WebServer'
        $template | Set-LowPrivilegeTemplateEditor
        if ($template.LowPrivilegeTemplateEditor) {
            Write-Host "Template has custom editors:"
            $template.LowPrivilegeTemplateEditorNames | ForEach-Object { Write-Host "  $_" }
        }
        Checks a specific template for custom/low-privilege editors and displays human-readable names.

        .NOTES
        Safe/Administrative principals excluded by default:
        - Domain Admins (-512), Enterprise Admins (-519), Builtin Administrators (-544)
        - SYSTEM (-18), Builtin Administrator (-500)
        - Cert Publishers (-517)
        - Domain Controllers (-516), Read-Only Domain Controllers (-521)
        - Enterprise Domain Controllers (-498), Enterprise Read-Only Domain Controllers (-9)
        - Key Admins (-526), Enterprise Key Admins (-527)
        - SELF (S-1-5-10)
        
        Dangerous principals excluded by default:
        - NULL SID, Everyone, Anonymous Logon, BUILTIN\Users
        - Authenticated Users, Domain Users, Domain Computers

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
        Write-Verbose "Identifying templates with low-privilege principals that have write access..."
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
                
                [array]$lowPrivilegeIdentityReference = foreach ($ace in $_.ObjectSecurity.Access) {
                    # Test if ACE grants dangerous write permissions first
                    $isDangerousAce = $ace | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
                    if ($isDangerousAce.IsDangerous) {
                        # Now check if the principal holding this ACE is low-privilege
                        $aceSid = $ace.IdentityReference | Convert-IdentityReferenceToSid
                        $isLowPrivilegePrincipal = $aceSid | Test-IsLowPrivilegePrincipal
                        if ($isLowPrivilegePrincipal) {
                            Write-Verbose "Low-privilege template editor found: $($ace.IdentityReference) ($($isDangerousAce.MatchedPermission))"
                            # Ensure the principal is in the store (triggers cache population)
                            $null = $ace.IdentityReference | Resolve-Principal
                            # Convert to SID and return as the key to PrincipalStore
                            $aceSid.Value
                        }
                    }
                }

                $lowPrivilegeIdentityReference = $lowPrivilegeIdentityReference | Sort-Object -Unique
                
                if ($lowPrivilegeIdentityReference) {
                    Write-Verbose "Template has $($lowPrivilegeIdentityReference.Count) low privilege editor(s): $($lowPrivilegeIdentityReference -join ', ')"
                    
                    # Expand any groups to include their direct members
                    Write-Verbose "Expanding group memberships for low privilege editors..."
                    $lowPrivilegeIdentityReference = Expand-GroupMembership -SidList $lowPrivilegeIdentityReference
                    Write-Verbose "After expansion: $($lowPrivilegeIdentityReference.Count) unique principal(s)"
                } else {
                    Write-Verbose "No low privilege editors found in template"
                }

                # Build human-readable names array from PrincipalStore
                [array]$lowPrivilegeEditorNames = $lowPrivilegeIdentityReference | ForEach-Object {
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

                # Update the AD CS Object Store with the LowPrivilegeTemplateEditor property
                $dn = $_.Properties.distinguishedName[0]
                if ($script:AdcsObjectStore.ContainsKey($dn)) {
                    $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName LowPrivilegeTemplateEditor -NotePropertyValue $lowPrivilegeIdentityReference -Force
                    $script:AdcsObjectStore[$dn] | Add-Member -NotePropertyName LowPrivilegeTemplateEditorNames -NotePropertyValue $lowPrivilegeEditorNames -Force
                    Write-Verbose "Updated AD CS Object Store for $dn with LowPrivilegeTemplateEditor"
                }

                # Also add to the pipeline object for backward compatibility
                $_ | Add-Member -NotePropertyName LowPrivilegeTemplateEditor -NotePropertyValue $lowPrivilegeIdentityReference -Force
                $_ | Add-Member -NotePropertyName LowPrivilegeTemplateEditorNames -NotePropertyValue $lowPrivilegeEditorNames -Force
                
                # Return the modified object
                $_
                
            } catch {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    $_.Exception,
                    'LowPrivilegeTemplateEditorProcessingFailed',
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
        Write-Verbose "Done identifying templates with low-privilege principals that have write access."
    }
}
