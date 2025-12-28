function Invoke-Locksmith2 {
    <#
        .SYNOPSIS
        Performs comprehensive AD CS security audit scanning for known ESC vulnerabilities.

        .DESCRIPTION
        Invoke-Locksmith2 audits Active Directory Certificate Services (AD CS) infrastructure
        for security misconfigurations documented as ESC (Escalation) techniques. It scans:
        
        - Certificate templates (ESC1, ESC2, ESC3, ESC4, ESC9)
        - Certification Authorities (ESC6, ESC7, ESC11, ESC16)
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

        .PARAMETER SkipForestCheck
        Reserved for future use. Currently not implemented.

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
        
        Runs interactive audit prompting for forest name and credentials.

        .EXAMPLE
        $cred = Get-Credential CONTOSO\admin
        Invoke-Locksmith2 -Forest 'dc01.contoso.com' -Credential $cred
        
        Audits contoso.com forest using provided credentials.

        .EXAMPLE
        Invoke-Locksmith2 -Forest 'contoso.com' -Credential $cred -SkipPowerShellCheck
        
        Runs audit skipping PowerShell environment validation.

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
        [switch]$SkipVersionCheck,
        [switch]$SkipPowerShellCheck,
        [switch]$SkipForestCheck
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
            Test-PowerShellEnvironment | Repair-PowerShellEnvironment
        }
        
        Write-Verbose "Starting Locksmith2 AD CS security audit..."
        
        # Set Forest and Credential
        Set-LS2Forest -Forest $Forest
        Set-LS2Credential -Credential $Credential
        
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
        
        Write-Verbose "Checking for ESC1 (Misconfigured Certificate Templates)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC1') ESC1 issue(s)"
        
        Write-Verbose "Checking for ESC2 (Any Purpose / SubCA Templates)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC2') ESC2 issue(s)"
        
        Write-Verbose "Checking for ESC3 Condition 1 (Enrollment Agent Templates)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC3c1') ESC3 Condition 1 issue(s)"
        
        Write-Verbose "Checking for ESC3 Condition 2 (Templates Accepting Agent Certificates)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC3c2') ESC3 Condition 2 issue(s)"
        
        Write-Verbose "Checking for ESC9 (No Security Extension)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC9') ESC9 issue(s)"
        
        Write-Verbose "Checking for ESC4a (Vulnerable Certificate Template Access Control)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC4a') ESC4a issue(s)"
        
        Write-Verbose "Checking for ESC4o (Vulnerable Certificate Template Ownership)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC4o') ESC4o issue(s)"
        
        Write-Verbose "Checking for ESC6 (CA EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC6') ESC6 issue(s)"
        
        Write-Verbose "Checking for ESC11 (CA RPC Encryption Not Required)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC11') ESC11 issue(s)"
        
        Write-Verbose "Checking for ESC7 (Vulnerable CA Access Control)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC7') ESC7 issue(s)"
        
        Write-Verbose "Checking for ESC16 (Disabled Security Extension)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC16') ESC16 issue(s)"
        
        Write-Verbose "Checking for ESC5a (Vulnerable PKI Object Access Control)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC5a') ESC5a issue(s)"
        
        Write-Verbose "Checking for ESC5o (Vulnerable PKI Object Ownership)..."
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC5o') ESC5o issue(s)"

        Get-FlattenedIssues # | Out-HtmlView -FilePath .\Ignore\FlattenedIssues.html
        
        # $script:PrincipalStore
        # $script:DomainStore
        # $script:AdcsObjectStore
        # $script:IssueStore
    }
}
