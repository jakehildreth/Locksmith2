function Show-ConnectionContext {
    <#
        .SYNOPSIS
        Displays the resolved connection context and prompts for confirmation.

        .DESCRIPTION
        Shows the forest, user, computer, and connection method that will be used
        for the scan. When running interactively, prompts the user to proceed.
        Returns $true if the scan should continue, $false if it should be cancelled.

        .PARAMETER Context
        Hashtable with keys Forest, Credential, and Method from Resolve-LS2ConnectionContext.

        .PARAMETER Force
        Suppresses the interactive confirmation prompt.

        .OUTPUTS
        System.Boolean
        Returns $true if the scan should proceed, $false otherwise.

        .EXAMPLE
        $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
        Show-ConnectionContext -Context $ctx

        Displays the connection context and prompts the user to proceed.

        .EXAMPLE
        $ctx = @{ Forest = 'contoso.com'; Credential = $cred; Method = 'ExplicitCredential' }
        Show-ConnectionContext -Context $ctx -Force

        Displays the connection context and skips the confirmation prompt.

        .NOTES
        This is a UI helper only. It does not perform any AD operations.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Context,

        [Parameter()]
        [switch]$Force
    )

    #requires -Version 5.1

    $rawUser = if ($Context.Credential) {
        $Context.Credential.UserName
    } else {
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }

    $userDisplay = if ($rawUser -match '^([^\\]+)\\(.+)$') {
        "$($Matches[1].ToUpper())\$($Matches[2])"
    } else {
        $rawUser
    }

    Write-Host ''
    Write-Host 'Connection Context' -ForegroundColor Cyan
    Write-Host "  Forest   : $($Context.Forest)"
    Write-Host "  User     : $userDisplay"
    Write-Host "  Computer : $($env:USERDOMAIN.ToUpper())\$($env:COMPUTERNAME.ToUpper())"
    Write-Host "  Method   : $($Context.Method)"
    Write-Host ''

    Write-Verbose "Connection context: Forest=$($Context.Forest), Method=$($Context.Method), User=$userDisplay"

    if ((Test-IsInteractiveSession) -and -not $Force) {
        $confirm = Read-Choice -Question 'Proceed with scan?' -Options @('y', 'n') -Default 'y'
        if ($confirm -ne 'y') {
            Write-Host 'Scan cancelled.' -ForegroundColor Yellow
            return $false
        }
    }

    return $true
}
