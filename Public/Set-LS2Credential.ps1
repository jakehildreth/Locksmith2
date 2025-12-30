function Set-LS2Credential {
    <#
        .SYNOPSIS
        Sets the script-scope Credential variable for Locksmith2.

        .DESCRIPTION
        Prompts for or sets the PSCredential object that will be used for all LDAP/GC
        queries during the Locksmith2 scan. Stores the value in $script:Credential.

        .PARAMETER Credential
        A PSCredential object containing the username and password to use for AD queries.
        If not provided, the user will be prompted to enter credentials interactively.

        .INPUTS
        None

        .OUTPUTS
        None
        Sets the module-level $script:Credential variable.

        .EXAMPLE
        $cred = Get-Credential
        Set-LS2Credential -Credential $cred
        Sets the credential without prompting.

        .EXAMPLE
        Set-LS2Credential
        Prompts the user to enter username and password.

        .NOTES
        This function should be called before Initialize-DomainStore or any AD queries.
        Username should be in NTAccount format (DOMAIN\username).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCredential]$Credential
    )

    #requires -Version 5.1

    if (-not $Credential) {
        Write-Host "`nPowerShell credential request`nEnter your credentials."
        $User = Read-Host "Username in NTAccount format (DOMAIN\username)" 
        $Password = Read-Host "Password for user $User" -AsSecureString
        $script:Credential = [System.Management.Automation.PSCredential]::New($User, $Password)
    } else {
        $script:Credential = $Credential
    }

    Write-Verbose "Credential set for user: $($script:Credential.UserName)"
}
