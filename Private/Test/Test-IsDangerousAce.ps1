function Test-IsDangerousAce {
    <#
        .SYNOPSIS
        Tests if an Active Directory access control entry grants dangerous permissions on AD CS objects.

        .DESCRIPTION
        Examines Active Directory access control entries (ACEs) on AD CS objects (templates, CAs,
        containers, computer accounts) to determine if they grant dangerous permissions that enable
        privilege escalation attacks.
        
        Dangerous permissions include GenericAll, WriteDacl, WriteOwner, GenericWrite, and specific
        WriteProperty rights depending on object class. The function matches ACEs against a
        comprehensive list of dangerous permission combinations defined in AceDefinitions.psd1,
        filtering by object class to ensure property-specific permissions are only flagged on
        relevant object types.
        
        Only Allow ACEs are considered dangerous; Deny ACEs always return false.
        
        This is critical for ESC1/ESC4/ESC5/ESC7/ESC9/ESC10 vulnerability detection in AD CS auditing.

        .PARAMETER Ace
        One or more ActiveDirectoryAccessRule objects to test for dangerous permissions.
        Typically obtained from an object's ObjectSecurity.Access property.

        .PARAMETER ObjectClass
        The objectClass or SchemaClassName of the object being audited. Used to filter
        dangerous ACE definitions to only those applicable to this object type.
        Valid values: pKICertificateTemplate, pKIEnrollmentService, certificationAuthority, computer

        .INPUTS
        System.DirectoryServices.ActiveDirectoryAccessRule[]
        You can pipe access control entries to this function.

        .OUTPUTS
        System.Management.Automation.PSCustomObject
        Returns a custom object for each ACE containing:
        - IsDangerous: Boolean indicating if ACE is dangerous for this object class
        - MatchedPermission: Name of the matched dangerous permission (if any)
        - Description: What the permission allows
        - Ace: The original ACE object

        .EXAMPLE
        $template = Get-AdcsObject | Where-Object Name -eq 'WebServer'
        $template.ObjectSecurity.Access | Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate'
        Tests all ACEs on the WebServer template for dangerous permissions.

        .EXAMPLE
        $ca = Get-AdcsObject | Where-Object { $_.objectClass -contains 'pKIEnrollmentService' } | Select-Object -First 1
        $ca.ObjectSecurity.Access | Test-IsDangerousAce -ObjectClass 'pKIEnrollmentService'
        Tests ACEs on a CA object for dangerous permissions (ESC7).

        .EXAMPLE
        $computer = Get-ADComputer 'CA-SERVER$'
        $computer.nTSecurityDescriptor.Access | Test-IsDangerousAce -ObjectClass 'computer'
        Tests ACEs on a CA host computer account for dangerous permissions (ESC9/ESC10).

        .EXAMPLE
        $dangerousAces = $template.ObjectSecurity.Access | 
            Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate' | 
            Where-Object IsDangerous
        Get only the ACEs that grant dangerous permissions.

        .EXAMPLE
        $template.ObjectSecurity.Access | 
            Test-IsDangerousAce -ObjectClass 'pKICertificateTemplate' | 
            Where-Object IsDangerous | 
            Select-Object @{N='Identity';E={$_.Ace.IdentityReference}}, MatchedPermission, Description
        Display dangerous ACEs with formatted output.

        .NOTES
        Automatically loads dangerous ACE definitions from DangerousAces.psd1.
        Definitions are cached in $script:DangerousAces for subsequent calls.
        
        ObjectClass parameter is mandatory to ensure property-specific permissions are
        only flagged on applicable object types (e.g., WriteProperty on msPKI-Certificate-Name-Flag
        is only dangerous on templates, not on CAs or computers).

        .LINK
        https://specterops.io/blog/2021/06/17/certified-pre-owned/
        
        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.ActiveDirectoryAccessRule[]]$Ace,
        
        [Parameter(Mandatory)]
        [string]$ObjectClass
    )

    #requires -Version 5.1

    begin {
        # Load dangerous ACE definitions from PSD1 data file
        if (-not $script:DangerousAces) {
            $dataFilePath = Join-Path $PSScriptRoot '..\Data\AceDefinitions.psd1'
            
            if (Test-Path $dataFilePath) {
                $data = Import-PowerShellDataFile -Path $dataFilePath
                $script:DangerousAces = $data.DangerousAces
                Write-Verbose "Loaded $($script:DangerousAces.Count) dangerous ACE definitions from $dataFilePath"
            } else {
                Write-Warning "AceDefinitions.psd1 not found at $dataFilePath. Unable to test for dangerous permissions."
                return
            }
        } else {
            Write-Verbose "Using cached $($script:DangerousAces.Count) dangerous ACE definitions"
        }
        
        # Filter to ACEs applicable to this object class
        $applicableAces = $script:DangerousAces | Where-Object { $_.ApplicableToClasses -contains $ObjectClass }
        Write-Verbose "Filtered to $($applicableAces.Count) ACE definitions applicable to objectClass '$ObjectClass'"
    }

    process {
        $Ace | ForEach-Object {
            $currentAce = $_
            $identityRef = $currentAce.IdentityReference
            
            Write-Verbose "Testing ACE for $identityRef - Rights: $($currentAce.ActiveDirectoryRights), Type: $($currentAce.AccessControlType)"
            
            # Only Allow ACEs are dangerous (Deny ACEs are protective)
            if ($currentAce.AccessControlType -ne 'Allow') {
                Write-Verbose "  Deny ACE - not dangerous (protective)"
                [PSCustomObject]@{
                    IsDangerous       = $false
                    MatchedPermission = $null
                    Description       = $null
                    Ace               = $currentAce
                }
                return
            }
            
            # Check against all applicable dangerous ACE definitions
            $matchedPermission = $null
            
            foreach ($dangerousAce in $applicableAces) {
                # Check if ActiveDirectoryRights matches
                $rightsMatch = $currentAce.ActiveDirectoryRights -match $dangerousAce.Rights
                
                if (-not $rightsMatch) {
                    continue
                }
                
                # For WriteProperty, also check ObjectType GUID
                if ($dangerousAce.Rights -eq 'WriteProperty' -and $dangerousAce.ObjectTypeGUID) {
                    $objectTypeMatch = $currentAce.ObjectType.ToString() -eq $dangerousAce.ObjectTypeGUID
                    
                    if (-not $objectTypeMatch) {
                        Write-Verbose "  Rights match ($($dangerousAce.Rights)) but ObjectType mismatch: ACE=$($currentAce.ObjectType), Expected=$($dangerousAce.ObjectTypeGUID)"
                        continue
                    }
                }
                
                # Match found
                $matchedPermission = $dangerousAce
                Write-Verbose "  DANGEROUS: Matched '$($dangerousAce.Name)'"
                break
            }
            
            # Return result
            if ($matchedPermission) {
                [PSCustomObject]@{
                    IsDangerous       = $true
                    MatchedPermission = $matchedPermission.Name
                    Description       = $matchedPermission.Description
                    ObjectTypeName    = $matchedPermission.ObjectTypeName
                    Ace               = $currentAce
                }
            } else {
                Write-Verbose "  Not dangerous - no matching dangerous permission found for objectClass '$ObjectClass'"
                [PSCustomObject]@{
                    IsDangerous       = $false
                    MatchedPermission = $null
                    Description       = $null
                    Ace               = $currentAce
                }
            }
        }
    }

    end {
        Write-Verbose "Finished testing ACEs for dangerous permissions on objectClass '$ObjectClass'"
    }
}
