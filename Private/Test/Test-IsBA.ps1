function Test-IsBA {
    <#
        .SYNOPSIS
        Tests if the current user (or supplied credential user) is a member of the BUILTIN\Administrators group.

        .DESCRIPTION
        Checks if the current user, or the user specified by -Credential, is a member of
        the BUILTIN\Administrators group (S-1-5-32-544) by querying Active Directory and
        checking both direct and nested group membership using the tokenGroups attribute.

        The BUILTIN\Administrators group (S-1-5-32-544) is a well-known local group that
        exists on every domain controller and member computer. This function checks membership
        across all domains in the forest to support multi-domain environments.

        When -Credential is supplied, the credential user is resolved to a SID and checked
        against Active Directory. This supports non-domain joined machines where the current
        process token does not reflect the credential user's privileges.

        The function performs efficient membership checks by:
        1. First checking direct membership in the Administrators group
        2. Then using the tokenGroups constructed attribute for nested membership detection
        3. Searching across all domains in the forest for comprehensive coverage

        .PARAMETER Credential
        PSCredential for authenticating to Active Directory. Optional; when omitted,
        the current Windows identity is used via New-AuthenticatedDirectoryEntry.

        .PARAMETER RootDSE
        A DirectoryEntry object for the RootDSE. Used to determine forest domains for LDAP queries.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        System.Boolean
        Returns $true if the principal is a member (direct or nested) of the BUILTIN\Administrators group.
        Returns $false otherwise.

        .EXAMPLE
        Test-IsBA -Credential $cred -RootDSE $rootDSE
        Checks if the credential user is a member of BUILTIN\Administrators.

        .EXAMPLE
        Test-IsBA -RootDSE $rootDSE
        Checks if the current user is a member of BUILTIN\Administrators.

        .EXAMPLE
        Test-IsBA -Credential $cred -RootDSE $rootDSE -Verbose
        Checks membership with verbose output showing whether membership is direct or nested.

        .NOTES
        Well-known SID checked:
        - S-1-5-32-544: BUILTIN\Administrators

        This function checks all domains in the forest to support multi-domain environments.
        Verbose output indicates whether membership is DIRECT or NESTED.

        The tokenGroups attribute is a constructed attribute that contains all security groups
        (direct and nested) that the principal is a member of, making nested membership
        detection efficient without manual recursion.

        .LINK
        https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids

        .LINK
        https://learn.microsoft.com/en-us/windows/win32/adschema/a-tokengroups
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]
        $RootDSE
    )

    #requires -Version 5.1

    process {
        try {
            # Determine which identity to check.
            if ($Credential) {
                $ntAccount = New-Object System.Security.Principal.NTAccount($Credential.UserName)
                $IdentityReference = $ntAccount | Convert-IdentityReferenceToSid
                if (-not $IdentityReference) {
                    Write-Warning "Could not resolve credential user to SID: $($Credential.UserName)"
                    return $false
                }
                Write-Verbose "Checking credential user: $($Credential.UserName) ($($IdentityReference.Value))"
            } else {
                $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $IdentityReference = $identity.User
                Write-Verbose "No credential specified, checking current user: $($IdentityReference.Value)"
            }

            Write-Verbose "Checking if SID $($IdentityReference.Value) is member of domain Administrators groups"

            # Extract server from RootDSE
            if ($RootDSE.Path -match 'LDAP://([^/]+)') {
                $server = $Matches[1]
            } else {
                Write-Warning "Could not extract server from RootDSE path."
                return $false
            }

            # Get all domain partitions in the forest using Global Catalog
            $configNC = $RootDSE.configurationNamingContext.Value
            $rootDomainDN = $RootDSE.rootDomainNamingContext.Value

            # Query for all crossRef objects to find all domains
            $partitionsPath = "LDAP://$server/CN=Partitions,$configNC"
            $partitionsEntry = New-AuthenticatedDirectoryEntry -Path $partitionsPath -Credential $Credential

            $partitionsSearcher = New-Object System.DirectoryServices.DirectorySearcher
            $partitionsSearcher.SearchRoot = $partitionsEntry
            $partitionsSearcher.Filter = "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))"
            $partitionsSearcher.PropertiesToLoad.AddRange(@('nCName')) | Out-Null
            $partitionsSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel

            $allPartitions = $partitionsSearcher.FindAll()

            # Check each domain for Administrators group membership
            foreach ($partition in $allPartitions) {
                if ($partition.Properties['nCName'].Count -gt 0) {
                    $domainDN = $partition.Properties['nCName'][0]
                    Write-Verbose "Checking domain: $domainDN"

                    # The Administrators group is always S-1-5-32-544 (BUILTIN\Administrators)
                    # This is a well-known SID that exists in every domain
                    $adminGroupSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')

                    Write-Verbose "Administrators group SID: $($adminGroupSid.Value)"

                    # Search for the Administrators group and check membership
                    $domainPath = "LDAP://$server/$domainDN"
                    $domainEntry = New-AuthenticatedDirectoryEntry -Path $domainPath -Credential $Credential

                    $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher
                    $groupSearcher.SearchRoot = $domainEntry
                    $groupSearcher.Filter = "(objectSid=$($adminGroupSid.Value))"
                    $groupSearcher.PropertiesToLoad.AddRange(@('member')) | Out-Null
                    $groupSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree

                    $groupResult = $groupSearcher.FindOne()

                    if ($groupResult) {
                        # Use tokenGroups attribute for recursive membership check
                        # This is more efficient than manually recursing through groups
                        Write-Verbose "Found Administrators group, checking membership recursively"

                        # First check for direct membership
                        $members = $groupResult.Properties['member']
                        $isDirectMember = $false

                        foreach ($memberDN in $members) {
                            # Get the member's SID
                            $memberPath = "LDAP://$server/$memberDN"
                            $memberEntry = New-AuthenticatedDirectoryEntry -Path $memberPath -Credential $Credential

                            if ($memberEntry.Properties['objectSid'].Count -gt 0) {
                                $memberSidBytes = $memberEntry.Properties['objectSid'][0]
                                $memberSid = New-Object System.Security.Principal.SecurityIdentifier($memberSidBytes, 0)

                                if ($memberSid.Value -eq $IdentityReference.Value) {
                                    $isDirectMember = $true
                                    $memberEntry.Dispose()
                                    break
                                }
                            }

                            $memberEntry.Dispose()
                        }

                        # Search for the user/group object by SID
                        $userSearcher = New-Object System.DirectoryServices.DirectorySearcher
                        $userSearcher.SearchRoot = $domainEntry
                        $userSearcher.Filter = "(objectSid=$($IdentityReference.Value))"
                        $userSearcher.PropertiesToLoad.AddRange(@('distinguishedName')) | Out-Null
                        $userSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree

                        $userResult = $userSearcher.FindOne()

                        if ($userResult) {
                            # Get the DirectoryEntry for the user to access tokenGroups
                            $userEntry = $userResult.GetDirectoryEntry()
                            $userEntry.RefreshCache(@('tokenGroups'))

                            if ($userEntry.Properties['tokenGroups'].Count -gt 0) {
                                # tokenGroups contains all groups (direct and nested) the user is a member of
                                foreach ($tokenGroupBytes in $userEntry.Properties['tokenGroups']) {
                                    $tokenGroupSid = New-Object System.Security.Principal.SecurityIdentifier($tokenGroupBytes, 0)

                                    if ($tokenGroupSid.Value -eq $adminGroupSid.Value) {
                                        if ($isDirectMember) {
                                            Write-Verbose "SID $($IdentityReference.Value) is a DIRECT member of Administrators in $domainDN"
                                        } else {
                                            Write-Verbose "SID $($IdentityReference.Value) is a NESTED member of Administrators in $domainDN"
                                        }

                                        # Cleanup
                                        $userEntry.Dispose()
                                        $userSearcher.Dispose()
                                        $groupSearcher.Dispose()
                                        $domainEntry.Dispose()
                                        $allPartitions.Dispose()
                                        $partitionsSearcher.Dispose()
                                        $partitionsEntry.Dispose()

                                        return $true
                                    }
                                }
                                Write-Verbose "SID $($IdentityReference.Value) is NOT a member of Administrators in $domainDN"
                            } else {
                                Write-Verbose "tokenGroups attribute is empty for SID $($IdentityReference.Value) in $domainDN"
                            }

                            $userEntry.Dispose()
                        } else {
                            Write-Verbose "Could not find user object for SID $($IdentityReference.Value) in $domainDN"
                        }

                        $userSearcher.Dispose()
                    }

                    $groupSearcher.Dispose()
                    $domainEntry.Dispose()
                }
            }

            # Cleanup
            $allPartitions.Dispose()
            $partitionsSearcher.Dispose()
            $partitionsEntry.Dispose()

            Write-Verbose "SID $($IdentityReference.Value) is NOT a member of domain Administrators in any domain"
            return $false

        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $_.Exception,
                'AdministratorsCheckFailed',
                [System.Management.Automation.ErrorCategory]::InvalidOperation,
                $Credential
            )
            $PSCmdlet.WriteError($errorRecord)
            return $false
        }
    }
}
