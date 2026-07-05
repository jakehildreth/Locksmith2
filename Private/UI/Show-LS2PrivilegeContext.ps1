function Show-LS2PrivilegeContext {
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

        .OUTPUTS
        None. Outputs directly to the console and verbose stream.

        .EXAMPLE
        $ctx = @{ Forest = 'contoso.com'; Credential = $null; Method = 'DomainUser' }
        Show-LS2PrivilegeContext -Context $ctx

        Displays the current principal's privilege status. Builtin Administrator
        status is shown as Unknown because no credential was supplied.

        .EXAMPLE
        $cred = Get-Credential -Message 'Domain admin credential'
        $rootDSE = Get-RootDSE -Forest 'contoso.com' -Credential $cred
        $ctx = @{ Forest = 'contoso.com'; Credential = $cred; Method = 'ExplicitCredential' }
        Show-LS2PrivilegeContext -Context $ctx -RootDSE $rootDSE

        Displays the current principal's privilege status, including Builtin
        Administrator membership in the target forest.

        .NOTES
        This is a UI helper only. It relies on Test-IsBA, Test-IsDA, Test-IsEA,
        and Test-IsLocalAdmin for the actual privilege checks.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Context,

        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$RootDSE
    )

    #requires -Version 5.1

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

    if (Test-IsInteractiveSession) {
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
    }

    Write-Verbose "Privilege context: DA=$daStatus, EA=$eaStatus, BA=$baStatus, LocalAdmin=$localAdminStatus"

    if (-not ($isDA -or $isEA -or $isBA)) {
        Write-Verbose 'Running without elevated AD rights. Audit filter and remediation data may be incomplete.'
    }
}
