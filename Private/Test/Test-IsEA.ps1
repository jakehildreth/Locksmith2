function Test-IsEA {
    <#
        .SYNOPSIS
        Tests if the current user (or supplied credential user) is a member of Enterprise Admins.

        .DESCRIPTION
        Checks if the current user, or the user specified by -Credential, is a member of
        the Enterprise Admins group (RID 519) in the forest root domain.

        When -RootDSE is supplied, the function queries Active Directory directly using
        the provided credential. This supports non-domain joined machines where the
        current process token does not contain the credential user's group memberships.

        When -RootDSE is omitted, the function checks the current Windows identity token
        for the well-known RID 519. This requires no network calls and works offline.

        .PARAMETER Credential
        PSCredential for authenticating to Active Directory. Optional; when omitted,
        the current Windows identity is used.

        .PARAMETER RootDSE
        A DirectoryEntry object for the RootDSE. Used to determine the forest root domain
        for LDAP queries. When supplied, an AD query is performed instead of a token check.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        System.Boolean
        Returns $true if the user is a member of Enterprise Admins.
        Returns $false otherwise.

        .EXAMPLE
        Test-IsEA
        Returns $true if the current user is a member of Enterprise Admins.

        .EXAMPLE
        Test-IsEA -Credential $cred -RootDSE $rootDSE
        Returns $true if the credential user is a member of Enterprise Admins in the
        target forest.

        .NOTES
        Well-known RID checked:
        - 519: Enterprise Admins (forest-wide administrative group)

        Enterprise Admins exists only in the forest root domain. This function checks
        the root domain identified by RootDSE.rootDomainNamingContext when -RootDSE is
        supplied.

        .LINK
        https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids

        .LINK
        https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]
        $RootDSE
    )

    #requires -Version 5.1

    try {
        # If no credential or RootDSE, fall back to the current user's token.
        if (-not $Credential -or -not $RootDSE) {
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            Write-Verbose "Checking if user '$($identity.Name)' has Enterprise Admin privileges via token"

            $enterpriseAdmins = $identity.Groups | Where-Object { $_.Value -match '-519$' }
            if ($enterpriseAdmins) {
                Write-Verbose "User is member of Enterprise Admins (RID 519)"
                return $true
            }

            Write-Verbose "User does not have Enterprise Admin privileges"
            return $false
        }

        # Resolve the credential user to a SID.
        $ntAccount = New-Object System.Security.Principal.NTAccount($Credential.UserName)
        $sid = $ntAccount | Convert-IdentityReferenceToSid
        if (-not $sid) {
            Write-Warning "Could not resolve credential user to SID: $($Credential.UserName)"
            return $false
        }

        Write-Verbose "Checking if SID $($sid.Value) is member of Enterprise Admins group"

        # Extract server from RootDSE.
        if ($RootDSE.Path -notmatch 'LDAP://([^/]+)') {
            Write-Warning "Could not extract server from RootDSE path."
            return $false
        }
        $server = $Matches[1]

        # Enterprise Admins only exists in the forest root domain.
        $rootDomainDN = $RootDSE.rootDomainNamingContext.Value
        if (-not $rootDomainDN) {
            Write-Warning "Could not determine root domain naming context from RootDSE."
            return $false
        }

        $rootDomainEntry = New-AuthenticatedDirectoryEntry -Path "LDAP://$server/$rootDomainDN" -Credential $Credential
        $rootDomainSid = $null
        try {
            if ($rootDomainEntry.Properties['objectSid'].Count -gt 0) {
                $rootDomainSid = New-Object System.Security.Principal.SecurityIdentifier($rootDomainEntry.Properties['objectSid'][0], 0)
            }
        } finally {
            $rootDomainEntry.Dispose()
        }

        if (-not $rootDomainSid) {
            Write-Warning "Could not determine root domain SID from RootDSE."
            return $false
        }

        $enterpriseAdminsSid = New-Object System.Security.Principal.SecurityIdentifier("$($rootDomainSid.Value)-519")
        Write-Verbose "Enterprise Admins SID: $($enterpriseAdminsSid.Value)"

        # Locate the user object by SID and check tokenGroups.
        $userSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $userSearcher.SearchRoot = New-AuthenticatedDirectoryEntry -Path "LDAP://$server/$rootDomainDN" -Credential $Credential
        $userSearcher.Filter = "(objectSid=$($sid.Value))"
        $userSearcher.PropertiesToLoad.AddRange(@('distinguishedName')) | Out-Null
        $userSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree

        $userResult = $userSearcher.FindOne()
        if ($userResult) {
            $userEntry = $userResult.GetDirectoryEntry()
            try {
                $userEntry.RefreshCache(@('tokenGroups'))

                if ($userEntry.Properties['tokenGroups'].Count -gt 0) {
                    foreach ($tokenGroupBytes in $userEntry.Properties['tokenGroups']) {
                        $tokenGroupSid = New-Object System.Security.Principal.SecurityIdentifier($tokenGroupBytes, 0)
                        if ($tokenGroupSid.Value -eq $enterpriseAdminsSid.Value) {
                            Write-Verbose "SID $($sid.Value) is a member of Enterprise Admins in $rootDomainDN"
                            return $true
                        }
                    }
                }
            } finally {
                $userEntry.Dispose()
            }
        }

        $userSearcher.Dispose()

        Write-Verbose "SID $($sid.Value) is NOT a member of Enterprise Admins"
        return $false

    } catch {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception,
            'EnterpriseAdminCheckFailed',
            [System.Management.Automation.ErrorCategory]::NotSpecified,
            $Credential
        )
        $PSCmdlet.WriteError($errorRecord)
        return $false
    }
}
