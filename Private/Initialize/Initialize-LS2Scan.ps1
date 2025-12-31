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

        .PARAMETER Force
        Forces a fresh vulnerability scan even if IssueStore is already populated.
        Use this to re-run scans and refresh vulnerability data.

        .OUTPUTS
        System.Boolean
        Returns $true if initialization succeeded, $false if it failed.

        .NOTES
        This is an internal function used by Find-LS2VulnerableTemplate, Find-LS2VulnerableCA,
        Find-LS2VulnerableObject, and Find-LS2RiskyPrincipal to ensure consistent initialization.
        
        The full vulnerability scan only runs once per session. Subsequent calls to any Find-LS2*
        function will use the cached IssueStore data.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [string]$Forest,
        
        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [switch]$Force
    )

    #requires -Version 5.1

    # Check if AdcsObjectStore is populated
    if (-not $script:AdcsObjectStore -or $script:AdcsObjectStore.Count -eq 0) {
        Write-Verbose "AdcsObjectStore is empty. Setting up prerequisites..."
        
        # Set up required context only if not already set or parameter provided
        if ($PSBoundParameters.ContainsKey('Forest') -or -not $script:Forest) {
            Set-LS2Forest -Forest $Forest
        }
        
        if ($PSBoundParameters.ContainsKey('Credential') -or -not $script:Credential) {
            Set-LS2Credential -Credential $Credential
        }
        
        if (-not $script:RootDSE) {
            $script:RootDSE = Get-RootDSE
        }
        
        if (-not $script:Server) {
            $script:Server = $script:Forest
        }
        
        # Initialize stores
        Initialize-DomainStore
        Initialize-PrincipalDefinitions
        Initialize-AdcsObjectStore
        
        # Check again after initialization attempt
        if (-not $script:AdcsObjectStore -or $script:AdcsObjectStore.Count -eq 0) {
            Write-Warning "AdcsObjectStore could not be populated. Verify credentials and forest connectivity."
            return $false
        }
    }

    # If IssueStore is empty or Force is specified, populate with all vulnerability scans
    if ($Force -or -not $script:IssueStore -or $script:IssueStore.Count -eq 0) {
        if ($Force) {
            Write-Verbose "Force specified. Running fresh vulnerability scan..."
        } else {
            Write-Verbose "IssueStore is empty. Running full vulnerability scan..."
        }
        
        # Scan all template techniques
        Write-Verbose "Scanning certificate templates..."
        $templateTechniques = @('ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC9', 'ESC4a', 'ESC4o')
        foreach ($tech in $templateTechniques) {
            Find-LS2VulnerableTemplate -Technique $tech | Out-Null
        }
        
        # Scan all CA techniques
        Write-Verbose "Scanning certification authorities..."
        $caTechniques = @('ESC6', 'ESC7a', 'ESC7m', 'ESC11', 'ESC16')
        foreach ($tech in $caTechniques) {
            Find-LS2VulnerableCA -Technique $tech | Out-Null
        }
        
        # Scan all object techniques
        Write-Verbose "Scanning infrastructure objects..."
        $objectTechniques = @('ESC5a', 'ESC5o')
        foreach ($tech in $objectTechniques) {
            Find-LS2VulnerableObject -Technique $tech | Out-Null
        }
        
        Write-Verbose "Full vulnerability scan complete."
    }

    return $true
}
