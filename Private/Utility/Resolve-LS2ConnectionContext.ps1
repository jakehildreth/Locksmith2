function Resolve-LS2ConnectionContext {
    <#
        .SYNOPSIS
        Detects the appropriate forest name and credential for a Locksmith2 scan.

        .DESCRIPTION
        Applies a prioritized detection strategy to determine the correct AD forest
        and credential to use:

        1. Both -Forest and -Credential supplied at CLI            -> Explicit
        2. -Credential only (no -Forest)                           -> ExplicitCredential (forest derived from UserName)
        3. -Forest only; current user is domain user               -> DomainUser (no credential)
        4. Neither; current user is domain user                    -> DomainUser (forest from GetCurrentDomain)
        5. Non-domain user, domain-joined machine                  -> DomainComputer (machine account auth, no credential)
        6. Non-domain user, non-domain machine, interactive        -> PromptedAll (prompt for both)
        7. Non-domain user, non-domain machine, non-interactive    -> terminating error

        When running interactively, failed RootDSE binds trigger up to 3 retry prompts.

        .PARAMETER Forest
        Optional. DNS name of the target AD forest. If omitted, auto-detection is used.

        .PARAMETER Credential
        Optional. PSCredential for the scan. If omitted, auto-detection is used.

        .OUTPUTS
        System.Collections.Hashtable with keys: Forest, Credential, Method

        .EXAMPLE
        $ctx = Resolve-LS2ConnectionContext
        Initialize-LS2Scan -Forest $ctx.Forest -Credential $ctx.Credential

        .NOTES
        Method values: Explicit | ExplicitCredential | DomainUser | DomainComputer | PromptedAll
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter()]
        [string]$Forest,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    # -------------------------------------------------------------------------
    # Short-circuit: both explicitly supplied
    if ($Forest -and $Credential) {
        return @{
            Forest     = $Forest
            Credential = $Credential
            Method     = 'Explicit'
        }
    }

    # -------------------------------------------------------------------------
    # Credential-only: derive forest from UserName (DOMAIN\user or user@domain.com)
    if (-not $Forest -and $Credential) {
        $derivedForest = if ($Credential.UserName -match '^([^\\]+)\\') {
            $Matches[1]
        } elseif ($Credential.UserName -match '@(.+)$') {
            $Matches[1]
        } else {
            $Credential.UserName
        }
        return @{
            Forest     = $derivedForest
            Credential = $Credential
            Method     = 'ExplicitCredential'
        }
    }

    # -------------------------------------------------------------------------
    # Forest-only or neither: run detection
    $maxAttempts    = 3
    $attempt        = 0
    $resolvedForest = $Forest  # may be $null if neither was supplied

    do {
        $attempt++

        # Step 1: domain user path
        if (Test-IsDomainUser) {
            if (-not $resolvedForest) {
                try {
                    $resolvedForest = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
                } catch {
                    $PSCmdlet.WriteError(
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.Exception]::new('Unable to determine current domain. Supply -Forest explicitly.'),
                            'DomainDiscoveryFailed',
                            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                            $null
                        )
                    )
                    return
                }
            }
            $script:CredentialResolved = $true
            return @{
                Forest     = $resolvedForest
                Credential = $null
                Method     = 'DomainUser'
            }
        }

        # Step 2: domain-joined machine — authenticate via computer account
        if (Test-IsDomainComputer) {
            $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
            $machineDomain = $computerInfo.Domain

            $script:CredentialResolved = $true
            return @{
                Forest     = if ($resolvedForest) { $resolvedForest } else { $machineDomain }
                Credential = $null
                Method     = 'DomainComputer'
            }
        }

        # Step 3: non-domain machine — must prompt for both
        if (Test-IsInteractiveSession) {
            $promptedForest = Read-Host -Prompt 'Enter the target AD forest DNS name'
            Write-Host ''
            Write-Host 'Windows PowerShell credential request'
            Write-Host "Enter credentials for forest '$promptedForest'"
            $promptedUser   = Read-Host 'User (DOMAIN\username or user@domain.com)'
            $promptedPass   = Read-Host "Password for user $promptedUser" -AsSecureString
            $promptedCred   = [System.Management.Automation.PSCredential]::new($promptedUser, $promptedPass)

            if ($promptedForest -and $promptedCred) {
                $ctx = @{
                    Forest     = $promptedForest
                    Credential = $promptedCred
                    Method     = 'PromptedAll'
                }
                # Validate via RootDSE bind
                $testRootDSE = Get-RootDSE -Forest $ctx.Forest -Credential $ctx.Credential -ErrorAction SilentlyContinue
                if ($testRootDSE) {
                    return $ctx
                }
                Write-Warning "RootDSE bind failed for '$promptedForest'. Attempt $attempt of $maxAttempts."
                continue
            }
        }

        # Non-interactive, non-domain — nothing we can do
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('Cannot resolve connection context in non-interactive session on a non-domain machine. Supply -Forest and -Credential explicitly.'),
                'NonInteractiveResolutionFailed',
                [System.Management.Automation.ErrorCategory]::AuthenticationError,
                $null
            )
        )
        return

    } while ($attempt -lt $maxAttempts)

    # Exhausted all attempts
    $PSCmdlet.ThrowTerminatingError(
        [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new("Failed to establish a valid connection context after $maxAttempts attempts. Supply -Forest and -Credential explicitly."),
            'ConnectionContextResolutionExhausted',
            [System.Management.Automation.ErrorCategory]::AuthenticationError,
            $null
        )
    )
}