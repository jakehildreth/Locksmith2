function Initialize-AdcsObjectStore {
    <#
        .SYNOPSIS
        Populates the module-level AdcsObjectStore with all AD CS objects.

        .DESCRIPTION
        Queries the Public Key Services container for all AD CS objects (templates, CAs,
        and infrastructure objects), enriches them with computed properties, and stores
        them in the module-level AdcsObjectStore hashtable for fast lookups.
        
        This function should be called once during Invoke-Locksmith2 to populate the
        AdcsObjectStore, avoiding repeated processing during vulnerability scans.

        .INPUTS
        None
        Uses module-level variables $script:Credential and $script:RootDSE.

        .OUTPUTS
        None
        Populates the module-level $script:AdcsObjectStore hashtable.

        .EXAMPLE
        Initialize-AdcsObjectStore
        Populates the AdcsObjectStore with all AD CS objects.

        .NOTES
        Requires Get-AdcsObject and various Set-* enrichment functions.
        The AdcsObjectStore is keyed by object Distinguished Name.
        
        Store structure:
        - Key: AD CS object Distinguished Name
        - Value: LS2AdcsObject with enriched properties
    #>
    [CmdletBinding()]
    param()

    #requires -Version 5.1

    begin {
        Write-Verbose "Initializing AdcsObjectStore..."
        
        # Initialize AdcsObject Store if it doesn't exist
        if (-not $script:AdcsObjectStore) {
            $script:AdcsObjectStore = @{}
        }
    }

    process {
        # Require Credential and RootDSE
        if (-not $script:Credential) {
            Write-Warning "Credential not set. Cannot initialize AdcsObjectStore."
            return
        }

        if (-not $script:RootDSE) {
            Write-Warning "RootDSE not set. Cannot initialize AdcsObjectStore."
            return
        }

        # Get all AD CS objects from Public Key Services container
        $script:AdcsObject = Get-AdcsObject
        Write-Verbose "Retrieved $($script:AdcsObject.Count) AD CS objects from Public Key Services container"
        
        # Process certificate templates
        $Templates = $script:AdcsObject | Where-Object SchemaClassName -EQ pKICertificateTemplate
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
        
        # Process Certification Authorities
        $CAs = $script:AdcsObject | Where-Object { $_.objectClass -contains 'pKIEnrollmentService' }
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
        $OtherObjects = $script:AdcsObject | Where-Object {
            $_.SchemaClassName -ne 'pKICertificateTemplate' -and
            $_.objectClass -notcontains 'pKIEnrollmentService'
        }
        $otherObjectCount = @($OtherObjects).Count
        Write-Verbose "Processing $otherObjectCount infrastructure object(s)..."
        
        $OtherObjects = $OtherObjects | 
        Set-DangerousEditor |
        Set-LowPrivilegeEditor |
        Set-HasNonStandardOwner
        
        Write-Verbose "AdcsObjectStore initialization complete. Statistics:"
        Write-Verbose "  - Principals stored: $($script:PrincipalStore.Count)"
        Write-Verbose "  - AD CS objects stored: $($script:AdcsObjectStore.Count)"
        Write-Verbose "  - Domains stored: $($script:DomainStore.Count)"
    }
}
