function Test-IsInteractiveSession {
    <#
        .SYNOPSIS
        Tests if the current PowerShell session is interactive (a human is at the keyboard).

        .DESCRIPTION
        Determines whether the current session is running interactively by checking two conditions:
        - [Environment]::UserInteractive: false when running as a service, scheduled task, or
          non-interactive process (e.g. SYSTEM via Invoke-CommandAs)
        - [Console]::IsInputRedirected: true when stdin is piped or redirected (automation)

        Both conditions must indicate an interactive context for this function to return $true.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        System.Boolean
        Returns $true if the session is interactive.
        Returns $false if running non-interactively (service, scheduled task, piped input, CI).

        .EXAMPLE
        Test-IsInteractiveSession
        Returns $true when a human is at the keyboard.

        .EXAMPLE
        if (Test-IsInteractiveSession) {
            $cred = Get-Credential
        } else {
            throw 'No credential supplied and session is non-interactive.'
        }

        .NOTES
        Used by Resolve-LS2ConnectionContext and Get-RootDSE to gate interactive prompts.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    #requires -Version 5.1

    $isUserInteractive = [Environment]::UserInteractive
    $isInputRedirected = [Console]::IsInputRedirected

    Write-Verbose "UserInteractive: $isUserInteractive, IsInputRedirected: $isInputRedirected"

    return $isUserInteractive -and -not $isInputRedirected
}
