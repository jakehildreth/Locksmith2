@{
    ESC1   = @{
        # ESC1: Misconfigured Certificate Templates
        Technique          = 'ESC1'
        
        # Conditions that make a template vulnerable
        Conditions         = @(
            @{ Property = 'SANAllowed'; Value = $true }
            @{ Property = 'AuthenticationEKUExist'; Value = $true }
            @{ Property = 'ManagerApprovalNotRequired'; Value = $true }
            @{ Property = 'AuthorizedSignatureNotRequired'; Value = $true }
        )
        
        # Which enrollee properties to check (pre-calculated by Set-* functions)
        EnrolleeProperties = @(
            'DangerousEnrollee'
            'LowPrivilegeEnrollee'
        )
        
        # Issue description template (supports variables: $(IdentityReference), $(TemplateName))
        IssueTemplate      = @(
            "`$(IdentityReference) can provide a Subject Alternative Name (SAN) while enrolling in this Client "
            "Authentication template, and enrollment does not require Manager Approval.`n`n"
            "The resultant certificate can be used by an attacker to authenticate as any principal listed in the SAN "
            "up to and including Domain Admins, Enterprise Admins, or Domain Controllers.`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )
        
        # Fix script template (supports variable: $(DistinguishedName))
        FixTemplate        = @(
            "# Enable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}"
        )
        
        # Revert script template (supports variable: $(DistinguishedName))
        RevertTemplate     = @(
            "# Disable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}"
        )
    }

    ESC2   = @{
        Technique          = 'ESC2'
        
        # Conditions that templates must match to be vulnerable
        Conditions         = @(
            @{ Property = 'AnyPurposeEKUExist'; Value = $true }
            @{ Property = 'ManagerApprovalNotRequired'; Value = $true }
            @{ Property = 'AuthorizedSignatureNotRequired'; Value = $true }
        )
        
        # Properties to check for problematic enrollees
        EnrolleeProperties = @(
            'DangerousEnrollee'
            'LowPrivilegeEnrollee'
        )
        
        # Issue description template
        IssueTemplate      = @(
            "`$(IdentityReference) can use the `$(TemplateName) template to request any type of certificate - including "
            "Enrollment Agent certificates and Subordinate Certification Authority (SubCA) certificate - without Manager "
            "Approval.`n`n"
            "If an attacker requests an Enrollment Agent certificate and there exists at least one enabled ESC3 Condition 2 "
            "or ESC15 template available that does not require Manager Approval, the attacker can request a certificate on "
            "behalf of another principal. The risk presented depends on the privileges granted to the other principal.`n`n"
            "If an attacker requests a SubCA certificate, the resultant certificate can be used by an attacker to "
            "instantiate their own SubCA which is trusted by AD.`n`n"
            "By default, certificates created from this attacker-controlled SubCA cannot be used for authentication, but "
            "they can be used for other purposes such as TLS certs and code signing."
        )

        # Remediation script template
        FixTemplate        = @(
            "# Enable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}"
        )

        # Revert script template
        RevertTemplate     = @(
            "# Disable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}"
        )
    }

    ESC3c1 = @{
        Technique          = 'ESC3c1'
        
        # Conditions that templates must match to be vulnerable
        Conditions         = @(
            @{ Property = 'EnrollmentAgentEKUExist'; Value = $true }
            @{ Property = 'ManagerApprovalNotRequired'; Value = $true }
            @{ Property = 'AuthorizedSignatureNotRequired'; Value = $true }
        )
        
        # Properties to check for problematic enrollees
        EnrolleeProperties = @(
            'DangerousEnrollee'
            'LowPrivilegeEnrollee'
        )
        
        # Issue description template
        IssueTemplate      = @(
            "`$(IdentityReference) can use the `$(TemplateName) template to request an Enrollment Agent certificate without "
            "Manager Approval.`n`n"
            "The resulting certificate can be used to enroll in any template that allows an Enrollment Agent to submit the "
            "request.`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )

        # Remediation script template
        FixTemplate        = @(
            "# Enable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}"
        )

        # Revert script template
        RevertTemplate     = @(
            "# Disable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}"
        )
    }

    ESC3c2 = @{
        Technique          = 'ESC3c2'
        
        # Conditions that templates must match to be vulnerable
        Conditions         = @(
            @{ Property = 'AuthenticationEKUExist'; Value = $true }
            @{ Property = 'ManagerApprovalNotRequired'; Value = $true }
            @{ Property = 'RequiresEnrollmentAgentSignature'; Value = $true }
        )
        
        # Properties to check for problematic enrollees
        EnrolleeProperties = @(
            'DangerousEnrollee'
            'LowPrivilegeEnrollee'
        )
        
        # Issue description template
        IssueTemplate      = @(
            "If the holder of a SubCA, Any Purpose, or Enrollment Agent certificate requests a certificate using the "
            "`$(TemplateName) template, they will receive a certificate which allows them to authenticate as "
            "`$(IdentityReference).`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )

        # Remediation script template
        FixTemplate        = @(
            "# First, eliminate unused Enrollment Agent templates."
            "# Then, tightly scope any Enrollment Agent templates that remain and:"
            "# Enable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}"
        )

        # Revert script template
        RevertTemplate     = @(
            "# Disable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}"
        )
    }

    ESC9   = @{
        Technique          = 'ESC9'
        
        # Conditions that templates must match to be vulnerable
        Conditions         = @(
            @{ Property = 'AuthenticationEKUExist'; Value = $true }
            @{ Property = 'NoSecurityExtension'; Value = $true }
        )
        
        # Properties to check for problematic enrollees
        EnrolleeProperties = @(
            'DangerousEnrollee'
            'LowPrivilegeEnrollee'
        )
        
        # Issue description template
        IssueTemplate      = @(
            "The `$(TemplateName) template has the szOID_NTDS_CA_SECURITY_EXT security extension disabled. "
            "Certificates issued from this template will not enforce strong certificate binding. Depending on the "
            "current Certificate Binding Enforcement level ESC6 status, it may be possible to request and receive "
            "certificates that rely on weak (aka attacker-controllable) binding methods.`n`n"
            "An attacker can abuse this weakness by:`n"
            "1. Getting access to a user or computer account.`n"
            "2. Modifying the user's userPrincipalName attribute (or the computer's dNSHostName attribute) to match a "
            "higher-privileged account.`n"
            "3. Requesting a client authentication certificate from this template with szOID_NTDS_CA_SECURITY_EXT disabled.`n"
            "4. Using the client authentication certificate to authenticate as the higher-privileged account.`n"
            "5. Profiting.`n`n"
            "More info:`n"
            "  - ESC9 description: https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc9-no-security-extension-on-certificate-template`n"
            "  - Strong Mapping/Enforcement Mode: https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16"
        )

        # Remediation script template
        FixTemplate        = @(
            "# Enable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}"
        )

        # Revert script template
        RevertTemplate     = @(
            "# Disable Manager Approval"
            "`$Object = '`$(DistinguishedName)'"
            "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}"
        )
    }

    ESC6   = @{
        Technique      = 'ESC6'
        
        # Conditions that CAs must match to be vulnerable
        Conditions     = @(
            @{ Property = 'SANFlagEnabled'; Value = $true }
        )
        
        # Issue description template
        IssueTemplate  = @(
            "The Certification Authority `$(CAName) has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled. "
            "This allows ANY certificate request to specify Subject Alternative Names (SANs) regardless of "
            "template configuration.`n`n"
            "An attacker with enrollment rights to ANY template on this CA can request certificates with "
            "arbitrary SANs, enabling authentication as any principal (including Domain Admins, Enterprise "
            "Admins, or Domain Controllers).`n`n"
            "This setting overrides template-level SAN restrictions and should be disabled unless absolutely "
            "necessary with strict template controls.`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )
        
        # Remediation script template
        FixTemplate    = @(
            "# Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA"
            "certutil -config `$(CAFullName) -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2"
            "# Restart Certificate Services for the change to take effect"
            "Restart-Service -Name CertSvc -Force"
        )
        
        # Revert script template
        RevertTemplate = @(
            "# Re-enable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA"
            "certutil -config `$(CAFullName) -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2"
            "# Restart Certificate Services"
            "Restart-Service -Name CertSvc -Force"
        )
    }

    ESC11  = @{
        Technique      = 'ESC11'
        
        # Conditions that CAs must match to be vulnerable
        Conditions     = @(
            @{ Property = 'RPCEncryptionNotRequired'; Value = $true }
        )
        
        # Issue description template
        IssueTemplate  = @(
            "The Certification Authority `$(CAName) does not require RPC encryption for certificate "
            "requests (IF_ENFORCEENCRYPTICERTREQUEST flag is disabled).`n`n"
            "This allows certificate requests to be submitted over unencrypted RPC/DCOM connections, "
            "which can be intercepted and manipulated via network-based attacks (NTLM relay).`n`n"
            "An attacker positioned on the network can:`n"
            "1. Relay NTLM authentication to the CA's RPC interface`n"
            "2. Request certificates on behalf of the relayed victim`n"
            "3. Use the obtained certificate to authenticate as the victim`n`n"
            "This is particularly dangerous when combined with coercion techniques.`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d"
        )
        
        # Remediation script template
        FixTemplate    = @(
            "# Enable IF_ENFORCEENCRYPTICERTREQUEST on the CA"
            "certutil -config `$(CAFullName) -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST"
            "# Restart Certificate Services"
            "Restart-Service -Name CertSvc -Force"
        )
        
        # Revert script template
        RevertTemplate = @(
            "# Disable IF_ENFORCEENCRYPTICERTREQUEST on the CA"
            "certutil -config `$(CAFullName) -setreg CA\\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST"
            "# Restart Certificate Services"
            "Restart-Service -Name CertSvc -Force"
        )
    }

    ESC7a  = @{
        Technique       = 'ESC7a'
        
        # Properties to check for problematic CA administrators
        AdminProperties = @(
            'DangerousCAAdministrator'
            'LowPrivilegeCAAdministrator'
        )
        
        # Issue description template for CA Administrators
        IssueTemplate   = @(
            "`$(IdentityReference) has CA Administrator rights on `$(CAName).`n`n"
            "CA Administrators can manage CA configuration, approve certificate requests, and modify "
            "security settings. This principal should not have these rights.`n`n"
            "An attacker with these rights can:`n"
            "1. Approve pending certificate requests (including malicious ones)`n"
            "2. Disable manager approval on templates`n"
            "3. Publish vulnerable certificate templates`n"
            "4. Modify CA configuration to enable additional attack vectors`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )
        
        # Remediation requires manual review
        FixTemplate     = @(
            "# Remove CA Administrator role"
            "certutil -config `$(CAFullName) -delreg ca\\Security\\Roles\\Administrators\\`$(IdentityReference)"
            "# Restart Certificate Services"
            "Restart-Service -Name CertSvc -Force"
            "# NOTE: Review whether this principal needs these rights before removing"
        )
        
        # Revert template
        RevertTemplate  = @(
            "# Re-add CA Administrator role"
            "certutil -config `$(CAFullName) -setreg ca\\Security\\Roles\\Administrators\\`$(IdentityReference) +ManageCA"
            "# Restart Certificate Services"
            "Restart-Service -Name CertSvc -Force"
        )
    }

    ESC7m  = @{
        Technique       = 'ESC7m'
        
        # Properties to check for problematic certificate managers
        AdminProperties = @(
            'DangerousCACertificateManager'
            'LowPrivilegeCACertificateManager'
        )
        
        # Issue description template for Certificate Managers
        IssueTemplate   = @(
            "`$(IdentityReference) has Certificate Manager rights on `$(CAName).`n`n"
            "Certificate Managers can approve/deny certificate requests and revoke certificates. "
            "This principal should not have these rights.`n`n"
            "An attacker with these rights can approve malicious certificate requests that would "
            "normally require manager approval.`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )
        
        # Remediation requires manual review
        FixTemplate     = @(
            "# Remove Certificate Manager role"
            "certutil -config `$(CAFullName) -delreg ca\\Security\\Roles\\Officers\\`$(IdentityReference)"
            "# Restart Certificate Services"
            "Restart-Service -Name CertSvc -Force"
            "# NOTE: Review whether this principal needs these rights before removing"
        )
        
        # Revert template
        RevertTemplate  = @(
            "# Re-add Certificate Manager role"
            "certutil -config `$(CAFullName) -setreg ca\\Security\\Roles\\Officers\\`$(IdentityReference) +ManageCertificates"
            "# Restart Certificate Services"
            "Restart-Service -Name CertSvc -Force"
        )
    }

    ESC16  = @{
        Technique      = 'ESC16'
        
        # Conditions that CAs must match to be vulnerable
        Conditions     = @(
            @{ Property = 'SecurityExtensionDisabled'; Value = $true }
        )
        
        # Issue description template
        IssueTemplate  = @(
            "The Certification Authority `$(CAName) has disabled the Certificate Template Information extension (OID: 1.3.6.1.4.1.311.25.2).`n`n"
            "This extension contains critical information about the certificate template used to issue certificates. "
            "Disabling this extension prevents proper certificate template validation and can allow certificate "
            "template abuse.`n`n"
            "When this extension is disabled:`n"
            "1. Certificate template information is not embedded in issued certificates`n"
            "2. Template-based security controls cannot be enforced`n"
            "3. Certificate template identification becomes unreliable`n`n"
            "This can be exploited to bypass template-level restrictions.`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d"
        )
        
        # Remediation script template
        FixTemplate    = @(
            "# Re-enable disabled extensions on the CA"
            "# Remove the extension OIDs from the DisableExtensionList registry value"
            "certutil -config `$(CAFullName) -delreg policy\\DisableExtensionList"
            "# Restart Certificate Services"
            "Restart-Service -Name CertSvc -Force"
            "# NOTE: Review which extensions should be enabled before applying this fix"
        )
        
        # Revert script template
        RevertTemplate = @(
            "# Re-disable the extensions (use with caution)"
            "certutil -config `$(CAFullName) -setreg policy\\DisableExtensionList `$(DisabledExtensions)"
            "# Restart Certificate Services"
            "Restart-Service -Name CertSvc -Force"
        )
    }

    # ============================================================================
    # ESC4a: Vulnerable Certificate Template Access Control (ACE-based)
    # ============================================================================
    ESC4a  = @{
        Technique        = 'ESC4a'
        
        # No conditions - all templates are checked for dangerous ACEs
        Conditions       = @()
        
        # Which editor properties to check (pre-calculated by Set-* functions)
        EditorProperties = @(
            'DangerousEditor'
            'LowPrivilegeEditor'
        )
        
        # Issue description template
        IssueTemplate    = @(
            "`$(IdentityReference) has `$(ActiveDirectoryRights) rights on the '`$(TemplateName)' certificate template.`n`n"
            "This permission allows the principal to modify template settings without proper authorization. "
            "Per Microsoft security best practices, only highly privileged administrators (Domain Admins, "
            "Enterprise Admins) should have write access to certificate templates.`n`n"
            "An attacker with these permissions can:`n"
            "1. Modify enrollment permissions (grant themselves enrollment rights)`n"
            "2. Change template EKUs to enable authentication or code signing`n"
            "3. Disable security extensions or manager approval requirements`n"
            "4. Enable subject name flexibility (ENROLLEE_SUPPLIES_SUBJECT)`n"
            "5. Create ESC1, ESC2, ESC3, or ESC9 conditions on the template`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )
        
        # Remediation script template
        FixTemplate      = @(
            "# Remove write permissions for `$(IdentityReference)"
            "`$Template = [ADSI]'LDAP://`$(DistinguishedName)'"
            "`$Identity = New-Object System.Security.Principal.NTAccount('`$(IdentityReference)')"
            "`$TemplateSecurity = `$Template.ObjectSecurity"
            "# Remove all ACEs for this identity"
            "`$TemplateSecurity.Access | Where-Object { `$_.IdentityReference -eq `$Identity } | ForEach-Object {"
            "    `$TemplateSecurity.RemoveAccessRule(`$_) | Out-Null"
            "}"
            "`$Template.CommitChanges()"
        )
        
        # Revert script template
        RevertTemplate   = @(
            "# Manual restoration required - review original ACL and restore appropriate permissions"
            "# Get-ADObject '`$(DistinguishedName)' -Properties nTSecurityDescriptor"
        )
    }

    # ============================================================================
    # ESC4o: Vulnerable Certificate Template Ownership
    # ============================================================================
    ESC4o  = @{
        Technique      = 'ESC4o'
        
        # Conditions to identify vulnerable templates
        Conditions     = @(
            @{
                Property = 'HasNonStandardOwner'
                Operator = 'eq'
                Value    = $true
            }
        )
        
        # Issue description template
        IssueTemplate  = @(
            "The certificate template '`$(TemplateName)' is owned by `$(Owner), which is not a standard owner.`n`n"
            "Per Microsoft security best practices, certificate templates should be owned exclusively "
            "by the forest's Enterprise Admins group. Templates with non-standard owners can be exploited "
            "by the owner to modify critical template properties without proper authorization.`n`n"
            "An attacker who controls the template owner can:`n"
            "1. Modify enrollment permissions (grant themselves enrollment rights)`n"
            "2. Change template EKUs to enable authentication or code signing`n"
            "3. Disable security extensions or manager approval requirements`n"
            "4. Enable subject name flexibility (ENROLLEE_SUPPLIES_SUBJECT)`n"
            "5. Create ESC1, ESC2, ESC3, or ESC9 conditions on the template`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )
        
        # Remediation script template
        FixTemplate    = @(
            "# Transfer ownership to Enterprise Admins"
            "`$Template = [ADSI]'LDAP://`$(DistinguishedName)'"
            "`$Owner = New-Object System.Security.Principal.NTAccount('Enterprise Admins')"
            "`$TemplateSecurity = `$Template.ObjectSecurity"
            "`$TemplateSecurity.SetOwner(`$Owner)"
            "`$Template.CommitChanges()"
        )
        
        # Revert script template
        RevertTemplate = @(
            "# Restore original owner"
            "`$Template = [ADSI]'LDAP://`$(DistinguishedName)'"
            "`$Owner = New-Object System.Security.Principal.NTAccount('`$(OriginalOwner)')"
            "`$TemplateSecurity = `$Template.ObjectSecurity"
            "`$TemplateSecurity.SetOwner(`$Owner)"
            "`$Template.CommitChanges()"
        )
    }

    # ============================================================================
    # ESC5a: Vulnerable PKI Object Access Control
    # ============================================================================
    ESC5a  = @{
        Technique        = 'ESC5a'
        
        # Conditions are empty since we check editor properties directly
        Conditions       = @()
        
        # Which editor properties to check (pre-calculated by Set-* functions)
        EditorProperties = @(
            'DangerousEditor'
            'LowPrivilegeEditor'
        )
        
        # Issue description template
        IssueTemplate    = @(
            "`$(IdentityReference) has `$(ActiveDirectoryRights) rights on the '`$(ObjectName)' PKI object.`n`n"
            "This permission allows the principal to modify PKI infrastructure settings without proper authorization. "
            "Per Microsoft security best practices, only highly privileged administrators (Domain Admins, "
            "Enterprise Admins) should have write access to PKI infrastructure objects.`n`n"
            "An attacker with these permissions can:`n"
            "1. Modify object permissions (WriteDacl)`n"
            "2. Grant themselves additional rights`n"
            "3. For CAs: Modify CA configuration, disable security extensions, grant dangerous permissions`n"
            "4. For containers: Create vulnerable templates or CAs`n"
            "5. For computer objects: Modify CA host configuration`n"
            "6. Manipulate PKI trust relationships and create ESC1, ESC2, ESC3, or ESC4 conditions`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )
        
        # Remediation script template
        FixTemplate      = @(
            "# Remove write permissions for `$(IdentityReference)"
            "`$Object = [ADSI]'LDAP://`$(DistinguishedName)'"
            "`$Identity = New-Object System.Security.Principal.NTAccount('`$(IdentityReference)')"
            "`$ObjectSecurity = `$Object.ObjectSecurity"
            "# Remove all ACEs for this identity"
            "`$ObjectSecurity.Access | Where-Object { `$_.IdentityReference -eq `$Identity } | ForEach-Object {"
            "    `$ObjectSecurity.RemoveAccessRule(`$_) | Out-Null"
            "}"
            "`$Object.CommitChanges()"
        )
        
        # Revert script template
        RevertTemplate   = @(
            "# Manual restoration required - review original ACL and restore appropriate permissions"
            "# Get-ADObject '`$(DistinguishedName)' -Properties nTSecurityDescriptor"
        )
    }

    ESC5o  = @{
        Technique      = 'ESC5o'
        
        # Conditions to identify vulnerable objects
        Conditions     = @(
            @{
                Property = 'HasNonStandardOwner'
                Operator = 'eq'
                Value    = $true
            }
        )
        
        # Issue description template
        IssueTemplate  = @(
            "The `$(ObjectType) '`$(ObjectName)' is owned by `$(Owner), which is not a standard owner.`n`n"
            "Per Microsoft security best practices, AD CS infrastructure objects should be owned exclusively "
            "by the forest's Enterprise Admins group. Objects with non-standard owners may be vulnerable to "
            "ESC4-style attacks where the owner can modify security-critical settings.`n`n"
            "An attacker who controls the owner principal can:`n"
            "1. Modify object permissions (WriteDacl)`n"
            "2. Grant themselves additional rights`n"
            "3. For CAs: Modify CA configuration, disable security extensions, grant dangerous permissions`n"
            "4. For containers: Create vulnerable templates or CAs`n"
            "5. For computer objects: Modify CA host configuration`n"
            "6. Manipulate PKI trust relationships`n`n"
            "More info:`n"
            "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
        )
        
        # Remediation script template
        FixTemplate    = @(
            "# Transfer ownership to Enterprise Admins"
            "`$Object = [ADSI]'LDAP://`$(DistinguishedName)'"
            "`$Owner = New-Object System.Security.Principal.NTAccount('Enterprise Admins')"
            "`$ObjectSecurity = `$Object.ObjectSecurity"
            "`$ObjectSecurity.SetOwner(`$Owner)"
            "`$Object.CommitChanges()"
        )
        
        # Revert script template
        RevertTemplate = @(
            "# Restore original owner"
            "`$Object = [ADSI]'LDAP://`$(DistinguishedName)'"
            "`$Owner = New-Object System.Security.Principal.NTAccount('`$(OriginalOwner)')"
            "`$ObjectSecurity = `$Object.ObjectSecurity"
            "`$ObjectSecurity.SetOwner(`$Owner)"
            "`$Object.CommitChanges()"
        )
    }
}
