class LS2AdcsObject {
    # Common properties for all AD CS objects
    [string]$distinguishedName
    [string[]]$objectClass
    [string]$name
    [string]$displayName
    [string]$cn
    [System.DirectoryServices.ActiveDirectorySecurity]$ObjectSecurity
    [string]$Path
    [string]$Owner
    [Nullable[bool]]$HasNonStandardOwner
    
    # Certificate Template properties (pKICertificateTemplate)
    [Nullable[int]]$flags
    [Nullable[int]]$pKIDefaultKeySpec
    [Nullable[int]]$pKIMaxIssuingDepth
    [string[]]$pKICriticalExtensions
    [string[]]$pKIExtendedKeyUsage
    [Nullable[int]]$CertificateNameFlag    # msPKI-Certificate-Name-Flag
    [Nullable[int]]$EnrollmentFlag         # msPKI-Enrollment-Flag
    [Nullable[int]]$PrivateKeyFlag         # msPKI-Private-Key-Flag
    [Nullable[int]]$RASignature            # msPKI-RA-Signature
    [string[]]$RAApplicationPolicies       # msPKI-RA-Application-Policies
    [Nullable[int]]$TemplateSchemaVersion  # msPKI-Template-Schema-Version
    [Nullable[int]]$TemplateMinorRevision  # msPKI-Template-Minor-Revision
    
    # CA properties (pKIEnrollmentService)
    [string[]]$certificateTemplates
    [string]$dNSHostName
    [string]$CAFullName
    [object[]]$CAAdministrators
    [object[]]$CertificateManagers
    [string[]]$DangerousCAAdministrator
    [string[]]$DangerousCAAdministratorNames
    [string[]]$LowPrivilegeCAAdministrator
    [string[]]$LowPrivilegeCAAdministratorNames
    [string[]]$DangerousCACertificateManager
    [string[]]$DangerousCACertificateManagerNames
    [string[]]$LowPrivilegeCACertificateManager
    [string[]]$LowPrivilegeCACertificateManagerNames
    
    # Computed properties (added by Set-* functions)
    [Nullable[bool]]$SANAllowed
    [Nullable[bool]]$AuthenticationEKUExist
    [Nullable[bool]]$AnyPurposeEKUExist
    [Nullable[bool]]$EnrollmentAgentEKUExist
    [Nullable[bool]]$NoSecurityExtension
    [Nullable[bool]]$RequiresEnrollmentAgentSignature
    [string[]]$DangerousEnrollee
    [string[]]$DangerousEnrolleeNames
    [string[]]$LowPrivilegeEnrollee
    [string[]]$LowPrivilegeEnrolleeNames
    [string[]]$DangerousEditor
    [string[]]$DangerousEditorNames
    [string[]]$LowPrivilegeEditor
    [string[]]$LowPrivilegeEditorNames
    [Nullable[bool]]$ManagerApprovalNotRequired
    [Nullable[bool]]$AuthorizedSignatureNotRequired
    [Nullable[bool]]$Enabled
    [string[]]$EnabledOn
    [string]$ComputerPrincipal
    [Nullable[bool]]$RPCEncryptionNotRequired
    [object[]]$EditFlags
    [Nullable[bool]]$SANFlagEnabled
    [object[]]$InterfaceFlags
    [Nullable[int]]$AuditFilter
    [object[]]$DisableExtensionList
    [Nullable[bool]]$SecurityExtensionDisabled
    [object[]]$WebEnrollmentEndpoints
    
    # Schema class name for easy type checking
    [string]$SchemaClassName
    
    # Constructor from DirectoryEntry
    LS2AdcsObject([System.DirectoryServices.DirectoryEntry]$DirectoryEntry) {
        # Common properties - set these FIRST
        $this.distinguishedName = if ($DirectoryEntry.distinguishedName) { $DirectoryEntry.distinguishedName.Value } else { $null }
        $this.objectClass = if ($DirectoryEntry.objectClass) { @($DirectoryEntry.objectClass) } else { @() }
        $this.name = if ($DirectoryEntry.name) { $DirectoryEntry.name.Value } else { $null }
        $this.displayName = if ($DirectoryEntry.displayName) { $DirectoryEntry.displayName.Value } else { $null }
        $this.cn = if ($DirectoryEntry.cn) { $DirectoryEntry.cn.Value } else { $null }
        $this.Path = $DirectoryEntry.Path
        
        # CA properties - set dNSHostName and compute CAFullName
        $this.certificateTemplates = if ($DirectoryEntry.Properties.Contains('certificateTemplates')) { @($DirectoryEntry.certificateTemplates) } else { @() }
        $this.dNSHostName = if ($DirectoryEntry.Properties.Contains('dNSHostName')) { $DirectoryEntry.Properties['dNSHostName'][0] } else { $null }
        
        # Compute CAFullName once from dNSHostName and cn
        if ($this.dNSHostName -and $this.cn) {
            $this.CAFullName = "$($this.dNSHostName)\$($this.cn)"
        } elseif ($this.cn) {
            $this.CAFullName = $this.cn
        } else {
            $this.CAFullName = $null
        }
        
        # Determine schema class name (most specific objectClass)
        if ($this.objectClass.Count -gt 0) {
            $this.SchemaClassName = $this.objectClass[$this.objectClass.Count - 1]
        }
        
        # Certificate Template properties
        $this.flags = if ($DirectoryEntry.Properties.Contains('flags')) { $DirectoryEntry.flags.Value } else { $null }
        $this.pKIDefaultKeySpec = if ($DirectoryEntry.Properties.Contains('pKIDefaultKeySpec')) { $DirectoryEntry.pKIDefaultKeySpec.Value } else { $null }
        $this.pKIMaxIssuingDepth = if ($DirectoryEntry.Properties.Contains('pKIMaxIssuingDepth')) { $DirectoryEntry.pKIMaxIssuingDepth.Value } else { $null }
        $this.pKICriticalExtensions = if ($DirectoryEntry.Properties.Contains('pKICriticalExtensions')) { @($DirectoryEntry.pKICriticalExtensions) } else { @() }
        $this.pKIExtendedKeyUsage = if ($DirectoryEntry.Properties.Contains('pKIExtendedKeyUsage')) { @($DirectoryEntry.pKIExtendedKeyUsage) } else { @() }
        
        # msPKI-* properties with proper type conversion
        $this.CertificateNameFlag = if ($DirectoryEntry.Properties.Contains('msPKI-Certificate-Name-Flag')) { [int]$DirectoryEntry.Properties['msPKI-Certificate-Name-Flag'][0] } else { $null }
        $this.EnrollmentFlag = if ($DirectoryEntry.Properties.Contains('msPKI-Enrollment-Flag')) { [int]$DirectoryEntry.Properties['msPKI-Enrollment-Flag'][0] } else { $null }
        $this.PrivateKeyFlag = if ($DirectoryEntry.Properties.Contains('msPKI-Private-Key-Flag')) { [int]$DirectoryEntry.Properties['msPKI-Private-Key-Flag'][0] } else { $null }
        $this.RASignature = if ($DirectoryEntry.Properties.Contains('msPKI-RA-Signature')) { [int]$DirectoryEntry.Properties['msPKI-RA-Signature'][0] } else { $null }
        $this.RAApplicationPolicies = if ($DirectoryEntry.Properties.Contains('msPKI-RA-Application-Policies')) { @($DirectoryEntry.Properties['msPKI-RA-Application-Policies']) } else { @() }
        $this.TemplateSchemaVersion = if ($DirectoryEntry.Properties.Contains('msPKI-Template-Schema-Version')) { [int]$DirectoryEntry.Properties['msPKI-Template-Schema-Version'][0] } else { $null }
        $this.TemplateMinorRevision = if ($DirectoryEntry.Properties.Contains('msPKI-Template-Minor-Revision')) { [int]$DirectoryEntry.Properties['msPKI-Template-Minor-Revision'][0] } else { $null }
        
        # Security descriptor and ownership
        try {
            $this.ObjectSecurity = $DirectoryEntry.ObjectSecurity
            $this.Owner = $this.ObjectSecurity.Owner
        } catch {
            Write-Verbose "Could not retrieve ObjectSecurity for '$($this.distinguishedName)': $_"
            $this.ObjectSecurity = $null
            $this.Owner = $null
        }
        
        # Initialize HasNonStandardOwner (preserve value if already set by Set-HasNonStandardOwner)
        if ($DirectoryEntry.PSObject.Properties['HasNonStandardOwner'] -and $null -ne $DirectoryEntry.HasNonStandardOwner) {
            $this.HasNonStandardOwner = $DirectoryEntry.HasNonStandardOwner
        } else {
            $this.HasNonStandardOwner = $null
        }
        
        # Initialize computed properties to defaults
        $this.SANAllowed = $null
        $this.AuthenticationEKUExist = $null
        $this.AnyPurposeEKUExist = $null
        $this.EnrollmentAgentEKUExist = $null
        $this.NoSecurityExtension = $null
        $this.RequiresEnrollmentAgentSignature = $null
        $this.DangerousEnrollee = @()
        $this.DangerousEnrolleeNames = @()
        $this.LowPrivilegeEnrollee = @()
        $this.LowPrivilegeEnrolleeNames = @()
        $this.DangerousEditor = @()
        $this.DangerousEditorNames = @()
        $this.LowPrivilegeEditor = @()
        $this.LowPrivilegeEditorNames = @()
        $this.ManagerApprovalNotRequired = $null
        $this.AuthorizedSignatureNotRequired = $null
        $this.Enabled = $null
        $this.EnabledOn = @()
        $this.RPCEncryptionNotRequired = $null
        $this.SANFlagEnabled = $null
        $this.AuditFilter = $null
        $this.DisableExtensionList = @()
        
        # Initialize CA-specific properties
        $this.CAAdministrators = @()
        $this.CertificateManagers = @()
        $this.DangerousCAAdministrator = @()
        $this.DangerousCAAdministratorNames = @()
        $this.LowPrivilegeCAAdministrator = @()
        $this.LowPrivilegeCAAdministratorNames = @()
        $this.DangerousCACertificateManager = @()
        $this.DangerousCACertificateManagerNames = @()
        $this.LowPrivilegeCACertificateManager = @()
        $this.LowPrivilegeCACertificateManagerNames = @()
    }
    
    # Method to check if this is a Certificate Template
    [bool] IsCertificateTemplate() {
        return $this.SchemaClassName -eq 'pKICertificateTemplate'
    }
    
    # Method to check if this is a CA
    [bool] IsCertificationAuthority() {
        return $this.objectClass -contains 'pKIEnrollmentService'
    }
    
    # Method to get a friendly name for logging
    [string] GetFriendlyName() {
        if ($this.displayName) {
            return $this.displayName
        } elseif ($this.name) {
            return $this.name
        } elseif ($this.cn) {
            return $this.cn
        } else {
            return $this.distinguishedName
        }
    }
}
