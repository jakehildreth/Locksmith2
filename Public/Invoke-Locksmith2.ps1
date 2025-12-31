function Invoke-Locksmith2 {
    <#
        .SYNOPSIS
        Performs comprehensive AD CS security audit scanning for known ESC vulnerabilities.

        .DESCRIPTION
        Invoke-Locksmith2 audits Active Directory Certificate Services (AD CS) infrastructure
        for security misconfigurations documented as ESC (Escalation) techniques. It scans:
        
        - Certificate templates (ESC1, ESC2, ESC3, ESC4, ESC9)
        - Certification Authorities (ESC6, ESC7a, ESC7m, ESC11, ESC16)
        - PKI container objects (ESC5)
        
        The function initializes four module-level stores:
        - PrincipalStore: Caches resolved SIDs and NTAccount principals
        - AdcsObjectStore: Stores all AD CS objects (templates, CAs, OIDs, etc.)
        - DomainStore: Caches domain information
        - IssueStore: Collects discovered vulnerabilities by technique
        
        Results are returned as structured LS2Issue objects containing vulnerability details,
        affected principals, and PowerShell remediation scripts.

        .PARAMETER Forest
        Fully qualified domain name of the forest/domain/domain controller to audit.
        If not specified, prompts interactively for the target forest.

        .PARAMETER Credential
        PSCredential object for authenticating to the target forest.
        If not specified, prompts interactively for username and password.
        Username should be in NTAccount format (DOMAIN\username).

        .PARAMETER SkipVersionCheck
        Skips checking for module updates from PowerShell Gallery.
        Use when running in air-gapped environments or to speed up execution.

        .PARAMETER SkipPowerShellCheck
        Skips validation and remediation of PowerShell environment settings.
        Use if you've already validated PowerShell profile and encoding settings.

        .PARAMETER Mode
        Specifies the output mode for displaying scan results.
        If not specified, returns LS2Issue objects to the pipeline without formatting.
        - Mode 0: Identify issues, output to console in table format
        - Mode 1: Identify issues and fixes, output to console in list format

        .PARAMETER SkipForestCheck
        Reserved for future use. Currently not implemented.

        .PARAMETER ExpandGroups
        Expands issues where the IdentityReference is a group into individual issues
        for each direct member of the group. This allows attribution of vulnerabilities
        to individual users rather than just showing group permissions.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        Hashtable
        Returns four hashtables:
        - PrincipalStore: All resolved principals by SID
        - DomainStore: All domains in the audited forest
        - AdcsObjectStore: All AD CS objects
        - IssueStore: All discovered vulnerabilities grouped by technique

        .EXAMPLE
        Invoke-Locksmith2
        
        Runs interactive audit and returns LS2Issue objects to the pipeline.

        .EXAMPLE
        $cred = Get-Credential CONTOSO\admin
        Invoke-Locksmith2 -Forest 'dc01.contoso.com' -Credential $cred
        
        Audits contoso.com forest and returns LS2Issue objects to the pipeline.

        .EXAMPLE
        Invoke-Locksmith2 -Forest 'contoso.com' -Credential $cred -SkipPowerShellCheck
        
        Runs audit skipping PowerShell environment validation.

        .EXAMPLE
        Invoke-Locksmith2 -Mode 0
        
        Runs audit and displays results in table format (default behavior).

        .EXAMPLE
        Invoke-Locksmith2 -Mode 1
        
        Runs audit and displays results in list format with fix scripts.

        .EXAMPLE
        Invoke-Locksmith2 -ExpandGroups
        
        Runs audit and expands group issues into individual per-member issues.

        .LINK
        https://github.com/jakehildreth/Locksmith2

        .LINK
        Find-LS2VulnerableCA

        .LINK
        Find-LS2VulnerableTemplate

        .LINK
        Find-LS2VulnerableObject

        .LINK
        Get-LS2Stores

        .NOTES
        Author: Jake Hildreth (@jakehildreth)
        Requires PowerShell 5.1 or later
        Requires appropriate AD permissions to read Public Key Services container
    #>
    [CmdletBinding()]
    param (
        [string]$Forest,
        [System.Management.Automation.PSCredential]$Credential,
        [ValidateSet(0, 1)]
        [Nullable[int]]$Mode,
        [switch]$SkipVersionCheck,
        [switch]$SkipPowerShellCheck,
        [switch]$SkipForestCheck,
        [switch]$ExpandGroups
    )

    #requires -Version 5.1

    begin {
        # Initialize module-level caches
        # These caches persist for the duration of the module session
        # and dramatically reduce LDAP queries for repeated lookups
        
        Write-Verbose "Initializing Locksmith2 data stores..."
        
        # Principal Store: SID/NTAccount => Full principal object with all properties
        # Stores: distinguishedName, sAMAccountName, objectSid, objectClass, displayName, memberOf, etc.
        # Key: IdentityReference.Value (SID string or NTAccount string)
        if (-not $script:PrincipalStore) {
            $script:PrincipalStore = @{}
        }
        
        # AD CS Object Store: Distinguished Name => Full AD CS object with all properties
        # Stores: Certificate templates, CAs, OID objects with all attributes
        # Key: distinguishedName
        # Value: PSCustomObject with all AD CS object properties
        if (-not $script:AdcsObjectStore) {
            $script:AdcsObjectStore = @{}
        }
        
        # Domain Store: Domain DN => Full domain object with all properties
        # Stores: Domain information including netBiosName, domainSid, DNS name, functional level
        # Key: Domain DN (e.g., DC=contoso,DC=com)
        # Value: PSCustomObject with domain properties
        if (-not $script:DomainStore) {
            $script:DomainStore = @{}
        }
        
        # Issue Store: Technique => Array of issue objects
        # Stores: All discovered security issues organized by technique (ESC1, ESC2, etc.)
        # Key: Technique name (e.g., 'ESC1', 'ESC6', 'ESC11')
        # Value: Array of issue objects with vulnerability details
        if (-not $script:IssueStore) {
            $script:IssueStore = @{}
        }
        
        Write-Verbose "Stores initialized - Principals: $($script:PrincipalStore.Count), AD CS Objects: $($script:AdcsObjectStore.Count), Domains: $($script:DomainStore.Count)"
    }

    end {
        Show-Logo2
        if (-not $SkipPowerShellCheck) {
            Test-PowerShellEnvironment | Repair-PowerShellEnvironment | Out-Null
        }
        
        Write-Verbose "Starting Locksmith2 AD CS security audit..."
        
        # Set Forest and Credential only if not already set or parameter provided
        if ($PSBoundParameters.ContainsKey('Forest') -or -not $script:Forest) {
            Set-LS2Forest -Forest $Forest
        } else {
            Write-Verbose "Using existing Forest: $($script:Forest)"
        }
        
        if ($PSBoundParameters.ContainsKey('Credential') -or -not $script:Credential) {
            Set-LS2Credential -Credential $Credential
        } else {
            Write-Verbose "Using existing Credential: $($script:Credential.UserName)"
        }
        
        $script:RootDSE = Get-RootDSE
        
        # Set server for LDAP/GC queries (same as Forest parameter)
        $script:Server = $script:Forest
            
        # Initialize DomainStore with all domains in the forest
        Initialize-DomainStore
        
        # Initialize PrincipalDefinitions with forest-specific SIDs
        Initialize-PrincipalDefinitions
        
        # Initialize AdcsObjectStore with all AD CS objects
        Initialize-AdcsObjectStore
        
        # Run vulnerability scans
        Write-Verbose "`nRunning vulnerability scans..."
        
        Write-Verbose "Scanning all certificate template vulnerabilities..."
        Find-LS2VulnerableTemplate | Out-Null
        
        Write-Verbose "Scanning all CA vulnerabilities..."
        Find-LS2VulnerableCA | Out-Null
        
        Write-Verbose "Scanning all infrastructure object vulnerabilities..."
        Find-LS2VulnerableObject | Out-Null
        
        Write-Verbose "`nScan complete. Issue summary:"
        Write-Verbose "  ESC1:  $(Get-IssueCount -Technique 'ESC1') issue(s)"
        Write-Verbose "  ESC2:  $(Get-IssueCount -Technique 'ESC2') issue(s)"
        Write-Verbose "  ESC3c1: $(Get-IssueCount -Technique 'ESC3c1') issue(s)"
        Write-Verbose "  ESC3c2: $(Get-IssueCount -Technique 'ESC3c2') issue(s)"
        Write-Verbose "  ESC4a: $(Get-IssueCount -Technique 'ESC4a') issue(s)"
        Write-Verbose "  ESC4o: $(Get-IssueCount -Technique 'ESC4o') issue(s)"
        Write-Verbose "  ESC5a: $(Get-IssueCount -Technique 'ESC5a') issue(s)"
        Write-Verbose "  ESC5o: $(Get-IssueCount -Technique 'ESC5o') issue(s)"
        Write-Verbose "  ESC6:  $(Get-IssueCount -Technique 'ESC6') issue(s)"
        Write-Verbose "  ESC7a: $(Get-IssueCount -Technique 'ESC7a') issue(s)"
        Write-Verbose "  ESC7m: $(Get-IssueCount -Technique 'ESC7m') issue(s)"
        Write-Verbose "  ESC9:  $(Get-IssueCount -Technique 'ESC9') issue(s)"
        Write-Verbose "  ESC11: $(Get-IssueCount -Technique 'ESC11') issue(s)"
        Write-Verbose "  ESC16: $(Get-IssueCount -Technique 'ESC16') issue(s)"

        # Get all flattened issues
        $allIssues = Get-FlattenedIssues
        
        # Expand groups if requested
        if ($ExpandGroups) {
            Write-Verbose "Expanding group memberships into individual issues..."
            $allIssues = $allIssues | ForEach-Object { Expand-IssueByGroup $_ }
            Write-Verbose "Expansion complete. Total issues: $($allIssues.Count)"
        }
        
        # Output based on whether Mode was specified
        if ($PSBoundParameters.ContainsKey('Mode')) {
            # Display issues in console using specified mode
            Show-IssueReport -Issues $allIssues -Mode $Mode
        } else {
            # Return LS2Issue objects to pipeline
            $allIssues
        }
    }
}
