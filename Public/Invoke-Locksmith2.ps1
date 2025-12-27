function Invoke-Locksmith2 {
    <#
        .SYNOPSIS
        Help

        .DESCRIPTION

        .PARAMETER Parameter

        .INPUTS

        .OUTPUTS

        .EXAMPLE

        .LINK
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
        Write-Verbose "Forest: $(if ($Forest) { $Forest } else { 'Current domain' })"
        
        if (-not $Forest) {
            $script:Forest = Read-Host 'Enter fully qualified domain controller/domain/forest name'
        } else {
            $script:Forest = $Forest
        }

        if (-not $Credential) {
            Write-Host "`nPowerShell credential request`nEnter your credentials."
            $User = Read-Host "Username in NTAccount format (DOMAIN\username)" 
            $Password = Read-Host "Password for user $User" -AsSecureString
            $script:Credential = [System.Management.Automation.PSCredential]::New($User, $Password)
        } else {
            $script:Credential = $Credential
        }
        $script:RootDSE = Get-RootDSE
        
        # Set server for LDAP/GC queries (same as Forest parameter)
        $script:Server = $script:Forest
            
        # Initialize DomainStore with all domains in the forest
        Initialize-DomainStore
        
        # Initialize PrincipalDefinitions with forest-specific SIDs
        Initialize-PrincipalDefinitions
        
        $script:AdcsObject = Get-AdcsObject
        
        Write-Verbose "Retrieved $($AdcsObject.Count) AD CS objects from Public Key Services container"
        
        $Templates = $AdcsObject | Where-Object SchemaClassName -EQ pKICertificateTemplate
        Write-Verbose "Processing $($Templates.Count) certificate templates..."
        
        $Templates = $Templates |
        Set-SANAllowed |
        Set-AuthenticationEKUExist |
        Set-AnyPurposeEKUExist |
        Set-EnrollmentAgentEKUExist |
        Set-RequiresEnrollmentAgentSignature |
        Set-NoSecurityExtension |
        Set-DangerousEnrollee |
        Set-LowPrivilegeEnrollee |
        Set-DangerousEditor |
        Set-LowPrivilegeEditor |
        Set-ManagerApprovalNotRequired |
        Set-AuthorizedSignatureNotRequired |
        Set-TemplateEnabled |
        Set-HasNonStandardOwner
        
        $CAs = $AdcsObject | Where-Object { $_.objectClass -contains 'pKIEnrollmentService' }
        $caCount = @($CAs).Count
        Write-Verbose "Processing $caCount Certification Authority object(s)..."
        
        $CAs = $CAs | Set-CAComputerPrincipal |
        Set-CAInterfaceFlags |
        Set-CAEditFlags |
        Set-CAAuditFilter |
        Set-CADisableExtensionList |
        Set-CAAdministrator |
        Set-CACertificateManager |
        Set-DangerousCAAdministrator |
        Set-LowPrivilegeCAAdministrator |
        Set-DangerousCACertificateManager |
        Set-LowPrivilegeCACertificateManager |
        Set-HasNonStandardOwner
        
        # Process all other infrastructure objects for non-standard owners
        $OtherObjects = $AdcsObject | Where-Object {
            $_.SchemaClassName -ne 'pKICertificateTemplate' -and
            $_.objectClass -notcontains 'pKIEnrollmentService'
        }
        $otherObjectCount = @($OtherObjects).Count
        Write-Verbose "Processing $otherObjectCount infrastructure object(s)..."
        
        $OtherObjects = $OtherObjects | 
        Set-DangerousEditor |
        Set-LowPrivilegeEditor |
        Set-HasNonStandardOwner
        
        Write-Verbose "Audit complete. Store statistics:"
        Write-Verbose "  - Principals stored: $($script:PrincipalStore.Count)"
        Write-Verbose "  - AD CS objects stored: $($script:AdcsObjectStore.Count)"
        Write-Verbose "  - Domains stored: $($script:DomainStore.Count)"
        
        # Run vulnerability scans
        Write-Verbose "`nRunning vulnerability scans..."
        
        Write-Verbose "Checking for ESC1 (Misconfigured Certificate Templates)..."
        [array]$ESC1Issues = Find-LS2VulnerableTemplate -Technique ESC1
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC1') ESC1 issue(s)"
        
        Write-Verbose "Checking for ESC2 (Any Purpose / SubCA Templates)..."
        [array]$ESC2Issues = Find-LS2VulnerableTemplate -Technique ESC2
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC2') ESC2 issue(s)"
        
        Write-Verbose "Checking for ESC3 Condition 1 (Enrollment Agent Templates)..."
        [array]$ESC3c1Issues = Find-LS2VulnerableTemplate -Technique ESC3c1
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC3c1') ESC3 Condition 1 issue(s)"
        
        Write-Verbose "Checking for ESC3 Condition 2 (Templates Accepting Agent Certificates)..."
        [array]$ESC3c2Issues = Find-LS2VulnerableTemplate -Technique ESC3c2
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC3c2') ESC3 Condition 2 issue(s)"
        
        Write-Verbose "Checking for ESC9 (No Security Extension)..."
        [array]$ESC9Issues = Find-LS2VulnerableTemplate -Technique ESC9
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC9') ESC9 issue(s)"
        
        Write-Verbose "Checking for ESC4a (Vulnerable Certificate Template Access Control)..."
        [array]$ESC4aIssues = Find-LS2VulnerableTemplate -Technique ESC4a
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC4a') ESC4a issue(s)"
        
        Write-Verbose "Checking for ESC4o (Vulnerable Certificate Template Ownership)..."
        [array]$ESC4oIssues = Find-LS2VulnerableTemplate -Technique ESC4o
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC4o') ESC4o issue(s)"
        
        Write-Verbose "Checking for ESC6 (CA EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled)..."
        [array]$ESC6Issues = Find-LS2VulnerableCA -Technique ESC6
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC6') ESC6 issue(s)"
        
        Write-Verbose "Checking for ESC11 (CA RPC Encryption Not Required)..."
        [array]$ESC11Issues = Find-LS2VulnerableCA -Technique ESC11
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC11') ESC11 issue(s)"
        
        Write-Verbose "Checking for ESC7 (Vulnerable CA Access Control)..."
        [array]$ESC7Issues = Find-LS2VulnerableCA -Technique ESC7
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC7') ESC7 issue(s)"
        
        Write-Verbose "Checking for ESC16 (Disabled Security Extension)..."
        [array]$ESC16Issues = Find-LS2VulnerableCA -Technique ESC16
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC16') ESC16 issue(s)"
        
        Write-Verbose "Checking for ESC5a (Vulnerable PKI Object Access Control)..."
        [array]$ESC5aIssues = Find-LS2VulnerableObject -Technique ESC5a
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC5a') ESC5a issue(s)"
        
        Write-Verbose "Checking for ESC5o (Vulnerable PKI Object Ownership)..."
        [array]$ESC5oIssues = Find-LS2VulnerableObject -Technique ESC5o
        Write-Verbose "Found $(Get-IssueCount -Technique 'ESC5o') ESC5o issue(s)"
        
        $script:PrincipalStore
        $script:DomainStore
        $script:AdcsObjectStore
        $script:IssueStore
    }
}
