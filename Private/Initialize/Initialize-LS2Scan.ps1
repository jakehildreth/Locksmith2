function Initialize-LS2Scan {
    <#
        .SYNOPSIS
        Ensures AdcsObjectStore and IssueStore are populated before vulnerability queries.

        .DESCRIPTION
        This internal helper function handles the initialization requirements for all Find-LS2* functions.
        It performs two critical checks:

        1. AdcsObjectStore Population:
           - Checks if AdcsObjectStore is populated with AD CS objects
           - If empty, initializes Forest/Credential context and queries LDAP
           - Populates DomainStore, PrincipalStore, and AdcsObjectStore

        2. IssueStore Population:
           - Checks if IssueStore contains vulnerability data
           - If empty, runs a complete vulnerability scan across all techniques
           - Scans templates (ESC1-ESC4, ESC9), CAs (ESC6, ESC7a/m, ESC11, ESC16), and objects (ESC5a/o)

        After this function completes successfully, both stores are guaranteed to be populated
        and ready for vulnerability queries.

        .PARAMETER Forest
        Fully qualified domain name of the forest/domain/domain controller to scan.
        If not specified and not already set, will prompt interactively.

        .PARAMETER Credential
        PSCredential for authenticating to Active Directory.
        If not specified and not already set, will prompt interactively.

        .PARAMETER Rescan
        Forces a fresh vulnerability scan even if IssueStore is already populated.
        Clears the IssueStore and rescans all AD CS configurations.

        .OUTPUTS
        System.Boolean
        Returns $true if initialization succeeded, $false if it failed.

        .NOTES
        This is an internal function used by Find-LS2VulnerableTemplate, Find-LS2VulnerableCA,
        Find-LS2VulnerableObject, and Find-LS2RiskyPrincipal to ensure consistent initialization.

        The full vulnerability scan only runs once per session. Subsequent calls to any Find-LS2*
        function will use the cached IssueStore data.

        .EXAMPLE
        Initialize-LS2Scan -Forest 'contoso.com'
        Initializes the Locksmith2 scan context for the contoso.com forest using the current user's
        credentials. Returns $true on success.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [string]$Forest,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [switch]$Rescan
    )

    #requires -Version 5.1

    # Validate definition data loaded at module import
    if (-not $script:DangerousAces) {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [System.InvalidOperationException]::new('DangerousAces definitions not loaded. The module may not have imported correctly.'),
                'DangerousAcesNotInitialized',
                [System.Management.Automation.ErrorCategory]::InvalidOperation,
                $null
            )
        )
    }
    if (-not $script:ESCDefinitions) {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [System.InvalidOperationException]::new('ESCDefinitions not loaded. The module may not have imported correctly.'),
                'ESCDefinitionsNotInitialized',
                [System.Management.Automation.ErrorCategory]::InvalidOperation,
                $null
            )
        )
    }
    if (-not $script:PrincipalDefinitionsBase) {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [System.InvalidOperationException]::new('PrincipalDefinitionsBase not loaded. The module may not have imported correctly.'),
                'PrincipalDefinitionsBaseNotInitialized',
                [System.Management.Automation.ErrorCategory]::InvalidOperation,
                $null
            )
        )
    }

    # Prevent recursive calls during initialization
    if ($script:InitializingStores) {
        return $true
    }

    # If Rescan is specified, clear stores to force repopulation
    if ($Rescan) {
        Write-Verbose "Rescan specified. Clearing AdcsObjectStore and IssueStore..."
        $script:AdcsObjectStore = @{}
        $script:IssueStore = @{}
    }

    $progressActivity = 'Locksmith2 AD CS Scan'

    try {
        # Check if AdcsObjectStore is populated
        if (-not $script:AdcsObjectStore -or $script:AdcsObjectStore.Count -eq 0) {
            Write-Progress -Activity $progressActivity -Status 'Connecting to Active Directory...' -PercentComplete 5
            Write-Verbose "AdcsObjectStore is empty. Setting up prerequisites..."

            # Set up required context only if not already set or parameter provided
            if ($PSBoundParameters.ContainsKey('Forest') -or -not $script:Forest) {
                Set-LS2Forest -Forest $Forest
            }

            # Skip credential prompt if Resolve-LS2ConnectionContext already determined none is needed
            if (-not $script:CredentialResolved) {
                if ($PSBoundParameters.ContainsKey('Credential') -or -not $script:Credential) {
                    Set-LS2Credential -Credential $Credential
                }
            }

            if (-not $script:RootDSE) {
                $script:RootDSE = Get-RootDSE
            }

            if (-not $script:Server) {
                $script:Server = $script:Forest
            }

            Write-Progress -Activity $progressActivity -Status 'Discovering domains...' -PercentComplete 15
            Initialize-DomainStore

            Write-Progress -Activity $progressActivity -Status 'Loading principal definitions...' -PercentComplete 25
            Initialize-PrincipalDefinitions

            Write-Progress -Activity $progressActivity -Status 'Reading AD CS objects...' -PercentComplete 35
            Initialize-AdcsObjectStore

            # Check again after initialization attempt
            if (-not $script:AdcsObjectStore -or $script:AdcsObjectStore.Count -eq 0) {
                Write-Warning "AdcsObjectStore could not be populated. Verify credentials and forest connectivity."
                return $false
            }
        }

        # If IssueStore is empty, populate with all vulnerability scans
        if (-not $script:IssueStore -or $script:IssueStore.Count -eq 0) {
            Write-Progress -Activity $progressActivity -Status 'Running vulnerability scans...' -PercentComplete 50
            Write-Verbose "IssueStore is empty. Running full vulnerability scan..."

            # Set flag to prevent recursive initialization
            $script:InitializingStores = $true

            try {
                # Scan all template techniques
                Write-Progress -Activity $progressActivity -Status 'Scanning certificate templates...' -PercentComplete 55
                Write-Verbose "Scanning certificate templates..."
                $templateTechniques = @('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC9', 'ESC4a', 'ESC4o', 'ESC13', 'ESC15', 'SchemaV1')
                foreach ($tech in $templateTechniques) {
                    Find-LS2VulnerableTemplate -Technique $tech | Out-Null
                }

                # Scan all CA techniques
                Write-Progress -Activity $progressActivity -Status 'Scanning certification authorities...' -PercentComplete 75
                Write-Verbose "Scanning certification authorities..."
                $caTechniques = @('ESC6', 'ESC7a', 'ESC7m', 'ESC8', 'ESC11', 'ESC16', 'Auditing')
                foreach ($tech in $caTechniques) {
                    Find-LS2VulnerableCA -Technique $tech | Out-Null
                }

                # Scan all object techniques
                Write-Progress -Activity $progressActivity -Status 'Scanning infrastructure objects...' -PercentComplete 90
                Write-Verbose "Scanning infrastructure objects..."
                $objectTechniques = @('ESC5a', 'ESC5o')
                foreach ($tech in $objectTechniques) {
                    Find-LS2VulnerableObject -Technique $tech | Out-Null
                }

                Write-Progress -Activity $progressActivity -Status 'Scan complete.' -PercentComplete 100
                Write-Verbose "Full vulnerability scan complete."
            } finally {
                # Always clear the flag
                $script:InitializingStores = $false
            }
        }

        return $true
    } finally {
        Write-Progress -Activity $progressActivity -Completed
    }
}
