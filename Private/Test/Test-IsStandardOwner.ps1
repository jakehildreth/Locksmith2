function Test-IsStandardOwner {
    <#
    .SYNOPSIS
        Tests whether an owner SID matches standard PKI ownership patterns.

    .DESCRIPTION
        Evaluates an owner identity (SID or NTAccount) against a list of standard
        ownership patterns to determine if the owner is an approved administrative
        principal for AD CS objects.
        
        Standard owners typically include:
        - Enterprise Admins (SID ending in -519)
        - Domain Admins (SID ending in -512)
        - Administrators (SID ending in -544)
        - SYSTEM (S-1-5-18)
        - Enterprise Domain Controllers (SID ending in -516)
        - Schema Admins (SID ending in -518)
        
        By default, uses the script-level $script:StandardOwners array populated by
        Initialize-PrincipalDefinitions. Custom patterns can be provided via parameter.

    .PARAMETER OwnerIdentity
        The owner identity to test. Can be a SID string (S-1-5-...) or NTAccount
        name (DOMAIN\User). If an NTAccount is provided, it will be translated to SID.

    .PARAMETER StandardOwners
        Optional array of standard owner SID patterns. If not provided, uses
        $script:StandardOwners. Patterns can be exact SIDs or regex patterns
        (ending with $).

    .INPUTS
        System.String
        You can pipe owner identities (SIDs or NTAccount names) to this function.

    .OUTPUTS
        System.Boolean
        Returns $true if the owner matches a standard pattern, $false otherwise.

    .EXAMPLE
        Test-IsStandardOwner -OwnerIdentity 'S-1-5-21-1234567890-1234567890-1234567890-519'
        Tests if the SID matches Enterprise Admins pattern (ends with -519).

    .EXAMPLE
        Test-IsStandardOwner -OwnerIdentity 'CONTOSO\Domain Admins'
        Translates the NTAccount to SID and tests if it matches standard patterns.

    .EXAMPLE
        'S-1-5-18' | Test-IsStandardOwner
        Pipeline example testing if SYSTEM is a standard owner.

    .EXAMPLE
        $customStandard = @('S-1-5-21-.*-512$', 'S-1-5-21-.*-519$')
        Test-IsStandardOwner -OwnerIdentity 'DOMAIN\Administrator' -StandardOwners $customStandard
        Uses custom standard owner patterns for validation.

    .NOTES
        This function is designed to work in conjunction with Set-HasNonStandardOwner
        and follows the pattern established by Test-IsDangerousPrincipal and
        Test-IsLowPrivilegePrincipal.
        
        Standard owner patterns support both exact SID matches and regex patterns
        (patterns ending with $).

    .LINK
        Set-HasNonStandardOwner
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$OwnerIdentity,

        [Parameter()]
        [string[]]$StandardOwners
    )

    #requires -Version 5.1

    begin {
        # Use script-level StandardOwners if not provided
        if (-not $StandardOwners) {
            if (-not $script:StandardOwners -or $script:StandardOwners.Count -eq 0) {
                Write-Warning "StandardOwners not initialized and none provided. Cannot validate ownership."
                return $false
            }
            $StandardOwners = $script:StandardOwners
        }
        
        Write-Verbose "Using $($StandardOwners.Count) standard owner patterns"
    }

    process {
        # Convert owner to SID if it's not already
        $ownerSid = $null
        if ($OwnerIdentity -match '^S-1-') {
            $ownerSid = $OwnerIdentity
            Write-Verbose "Testing if '$OwnerIdentity' is a standard owner..."
        } else {
            try {
                $ownerPrincipal = New-Object System.Security.Principal.NTAccount($OwnerIdentity)
                $ownerSid = $ownerPrincipal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                Write-Verbose "Testing if '$OwnerIdentity' ($ownerSid) is a standard owner..."
            } catch {
                Write-Verbose "Could not translate owner '$OwnerIdentity' to SID: $_"
                return $false
            }
        }
        
        if (-not $ownerSid) {
            return $false
        }
        
        # Check if owner SID matches any standard owner pattern
        foreach ($pattern in $StandardOwners) {
            # Check for exact SID match
            if ($pattern -eq $ownerSid) {
                Write-Verbose "'$ownerSid' matches standard owner pattern (exact): $pattern"
                return $true
            }
            # Check for regex pattern match (patterns ending in $)
            elseif ($pattern -match '\$$' -and $ownerSid -match $pattern) {
                Write-Verbose "'$ownerSid' matches standard owner pattern (regex): $pattern"
                return $true
            }
        }
        
        Write-Verbose "'$ownerSid' is not a standard owner"
        return $false
    }
}
