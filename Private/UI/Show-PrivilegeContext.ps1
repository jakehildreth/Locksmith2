function Show-PrivilegeContext {
    <#
        .SYNOPSIS
        Displays the current principal's privileges in the target forest.

        .DESCRIPTION
        Reports Domain Admin, Enterprise Admin, Builtin Administrator, and local
        administrator status. Also emits a short degradation note when the session
        lacks elevated AD rights.

        .PARAMETER Context
        Hashtable with keys Forest, Credential, and Method from Resolve-LS2ConnectionContext.

        .PARAMETER RootDSE
        DirectoryEntry for the target forest RootDSE. Required for the Builtin
        Administrator check.

        .PARAMETER Force
        Suppresses the interactive confirmation prompt after displaying privileges.

        .OUTPUTS
        System.Boolean
        Returns $true if the scan should proceed, $false if the user cancelled.

        .EXAMPLE
        $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
        Show-PrivilegeContext -Context $ctx

        Displays the current principal's privilege status. Builtin Administrator
        status is shown as Unknown because no credential was supplied.

        .EXAMPLE
        $cred = Get-Credential -Message 'Domain admin credential'
        $rootDSE = Get-RootDSE -Forest 'contoso.com' -Credential $cred
        $ctx = @{ Forest = 'contoso.com'; Credential = $cred; Method = 'ExplicitCredential' }
        Show-PrivilegeContext -Context $ctx -RootDSE $rootDSE

        Displays the current principal's privilege status, including Builtin
        Administrator membership in the target forest.

        .NOTES
        This is a UI helper only. It relies on Test-IsBA, Test-IsDA, Test-IsEA,
        and Test-IsLocalAdmin for the actual privilege checks.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Context,

        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$RootDSE,

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

    $transientMessage = "Checking $userDisplay's privileges in the $($Context.Forest) forest..."
    $canEditBuffer = $Host.Name -notin @('Windows PowerShell ISE Host', 'ConsoleHost') -and
        $Host.UI.RawUI -and
        -not [string]::IsNullOrEmpty($env:TERM)

    if ((Test-IsInteractiveSession) -and -not $Force) {
        Write-Host $transientMessage -NoNewline
    } else {
        Write-Verbose $transientMessage
    }

    $isDA = Test-IsDA
    $isEA = Test-IsEA
    $isLocalAdmin = Test-IsLocalAdmin -WarningAction SilentlyContinue

    $isBA = $false
    $baStatus = 'No'
    if ($RootDSE) {
        try {
            $isBA = Test-IsBA -RootDSE $RootDSE -Credential $Context.Credential -ErrorAction Stop
            $baStatus = if ($isBA) { 'Yes' } else { 'No' }
        } catch {
            $baStatus = 'Unknown'
            Write-Warning "Unable to determine Builtin Administrator status: $_"
        }
    } else {
        $baStatus = 'Unknown'
        Write-Warning 'RootDSE not available; Builtin Administrator status cannot be determined.'
    }

    $daStatus = if ($isDA) { 'Yes' } else { 'No' }
    $eaStatus = if ($isEA) { 'Yes' } else { 'No' }
    $localAdminStatus = if ($isLocalAdmin) { 'Yes' } else { 'No' }

    if ((Test-IsInteractiveSession) -and -not $Force) {
        if ($canEditBuffer) {
            $clearLine = "`r$(' ' * $transientMessage.Length)`r"
            Write-Host $clearLine -NoNewline
        } else {
            Write-Host ''
        }

        Write-Host ''
        Write-Host 'Privilege Context' -ForegroundColor Cyan
        Write-Host "  Domain Admin      : $daStatus"
        Write-Host "  Enterprise Admin  : $eaStatus"
        Write-Host "  Builtin Admin     : $baStatus"
        Write-Host "  Local Admin       : $localAdminStatus"
        Write-Host ''

        if (-not ($isDA -or $isEA -or $isBA)) {
            Write-Host '[!] Running without elevated AD rights. Some checks may be incomplete:' -ForegroundColor Yellow
            Write-Host '    - CA audit filter details may be unavailable or incomplete.'
            Write-Host '    - Fix/revert scripts cannot be executed automatically.'
            Write-Host '    - Some CA security settings may require local admin or CA admin rights to read.'
            Write-Host ''
        }

        $confirm = Read-Choice -Question 'Proceed with scan?' -Options @('y', 'n') -Default 'y'
        if ($confirm -ne 'y') {
            Write-Host 'Scan cancelled.' -ForegroundColor Yellow
            return $false
        }
    }

    Write-Verbose "Privilege context: DA=$daStatus, EA=$eaStatus, BA=$baStatus, LocalAdmin=$localAdminStatus"

    if (-not ($isDA -or $isEA -or $isBA)) {
        Write-Verbose 'Running without elevated AD rights. Audit filter and remediation data may be incomplete.'
    }

    return $true
}
