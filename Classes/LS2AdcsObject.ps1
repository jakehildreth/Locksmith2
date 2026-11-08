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
    [string[]]$CertificatePolicy           # msPKI-Certificate-Policy (OIDs on templates)
    [string]$CertTemplateOID               # msPKI-Cert-Template-OID (on msPKI-Enterprise-Oid objects)
    [string]$OIDToGroupLink                # msDS-OIDToGroupLink (on msPKI-Enterprise-Oid objects)
    
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
    [Nullable[bool]]$AuditingIncomplete
    [object[]]$DisableExtensionList
    [Nullable[bool]]$SecurityExtensionDisabled
    [bool]$IsCATemplate
    [object[]]$WebEnrollmentEndpoints
    [Nullable[bool]]$HasLinkedGroupOIDPolicy  # true when ≥1 CertificatePolicy OID links to a group
    [string[]]$LinkedGroupOIDPolicies         # group DNs linked via OID application policies

    # Identity of the CA behind an object, used to tie AIA / CDP objects to their CA
    [string[]]$CACertificateSubject           # subject DNs of cACertificate values (CA, AIA, Certification Authorities objects)
    [string]$CRLIssuer                        # issuer DN of the CRL on a cRLDistributionPoint object
    
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
        $this.CertificatePolicy = if ($DirectoryEntry.Properties.Contains('msPKI-Certificate-Policy')) { @($DirectoryEntry.Properties['msPKI-Certificate-Policy']) } else { @() }
        $this.CertTemplateOID = if ($DirectoryEntry.Properties.Contains('msPKI-Cert-Template-OID')) { $DirectoryEntry.Properties['msPKI-Cert-Template-OID'][0] } else { $null }
        $this.OIDToGroupLink = if ($DirectoryEntry.Properties.Contains('msDS-OIDToGroupLink')) { $DirectoryEntry.Properties['msDS-OIDToGroupLink'][0] } else { $null }
        
        # Security descriptor and ownership
        try {
            $this.ObjectSecurity = $DirectoryEntry.ObjectSecurity
            $this.Owner = $this.ObjectSecurity.Owner
        } catch {
            Write-Verbose "Could not retrieve ObjectSecurity for '$($this.distinguishedName)': $_"
            $this.ObjectSecurity = $null
            $this.Owner = $null
        }

        # CA identity: certificate subjects and CRL issuer (parsed here so the raw blobs aren't kept)
        $this.CACertificateSubject = if ($DirectoryEntry.Properties.Contains('cACertificate')) {
            [LS2AdcsObject]::GetCertificateSubjects(@($DirectoryEntry.Properties['cACertificate']))
        } else { @() }
        $crlBytes = $null
        foreach ($crlAttribute in 'certificateRevocationList', 'deltaRevocationList') {
            if (-not $crlBytes -and $DirectoryEntry.Properties.Contains($crlAttribute)) {
                $crlBytes = $DirectoryEntry.Properties[$crlAttribute][0]
            }
        }
        $this.CRLIssuer = if ($crlBytes) { [LS2AdcsObject]::GetCRLIssuer([byte[]]$crlBytes) } else { $null }
        
        # Initialize HasNonStandardOwner (preserve value if already set by Set-HasNonStandardOwner)
        if ($DirectoryEntry.PSObject.Properties['HasNonStandardOwner'] -and $null -ne $DirectoryEntry.HasNonStandardOwner) {
            $this.HasNonStandardOwner = $DirectoryEntry.HasNonStandardOwner
        } else {
            $this.HasNonStandardOwner = $null
        }
        
        # Initialize computed properties to defaults
        $this.SANAllowed = $null
        $this.AuthenticationEKUExist = $null
        $this.HasLinkedGroupOIDPolicy = $null
        $this.LinkedGroupOIDPolicies = @()
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
        $this.IsCATemplate = $false
        
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

    # Distinct subject DNs of DER-encoded certificates; values that don't parse are skipped
    static [string[]] GetCertificateSubjects([object[]]$RawCertificates) {
        $subjects = [System.Collections.Generic.List[string]]::new()
        foreach ($raw in $RawCertificates) {
            try {
                $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$raw)
                $subject = $certificate.SubjectName.Name
                if (-not $subjects.Contains($subject)) { $subjects.Add($subject) }
            } catch {
                continue
            }
        }
        return $subjects.ToArray()
    }

    # Reads [tag, header length, content length] of the DER element at $Offset
    static [int[]] ReadDerHeader([byte[]]$Data, [int]$Offset) {
        $length = [int]$Data[$Offset + 1]
        $headerLength = 2
        if ($length -band 0x80) {
            $lengthByteCount = $length -band 0x7F
            $length = 0
            for ($i = 0; $i -lt $lengthByteCount; $i++) {
                $length = ($length -shl 8) -bor [int]$Data[$Offset + 2 + $i]
            }
            $headerLength = 2 + $lengthByteCount
        }
        return @([int]$Data[$Offset], $headerLength, $length)
    }

    # Issuer DN of a DER-encoded CRL, or $null if it can't be parsed
    # CertificateList ::= SEQUENCE { tbsCertList SEQUENCE { version INTEGER OPTIONAL, signature SEQUENCE, issuer Name, ... }, ... }
    static [string] GetCRLIssuer([byte[]]$Crl) {
        try {
            $certificateList = [LS2AdcsObject]::ReadDerHeader($Crl, 0)
            $tbsOffset = $certificateList[1]
            $tbs = [LS2AdcsObject]::ReadDerHeader($Crl, $tbsOffset)
            $offset = $tbsOffset + $tbs[1]
            $element = [LS2AdcsObject]::ReadDerHeader($Crl, $offset)
            if ($element[0] -eq 0x02) {
                $offset += $element[1] + $element[2]
                $element = [LS2AdcsObject]::ReadDerHeader($Crl, $offset)
            }
            $offset += $element[1] + $element[2]
            $issuer = [LS2AdcsObject]::ReadDerHeader($Crl, $offset)
            $issuerLength = $issuer[1] + $issuer[2]
            if ($issuerLength -le 2 -or ($offset + $issuerLength) -gt $Crl.Length) {
                return $null
            }
            $issuerBytes = [byte[]]$Crl[$offset..($offset + $issuerLength - 1)]
            return [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($issuerBytes).Name
        } catch {
            return $null
        }
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
