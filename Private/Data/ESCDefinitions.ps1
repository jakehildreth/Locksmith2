# MAINTENANCE: When adding a new ESC entry here, you MUST also:
#   1. Add the technique name to the [ValidateSet(...)] in the appropriate Find-LS2Vulnerable* function:
#        - Template techniques  -> Public/Find-LS2VulnerableTemplate.ps1
#        - CA techniques        -> Public/Find-LS2VulnerableCA.ps1
#        - Object techniques    -> Public/Find-LS2VulnerableObject.ps1
#   2. Add the technique name to the matching $*Techniques array in Private/Initialize/Initialize-LS2Scan.ps1
#   3. Add the technique name to the $techniques array in Public/Invoke-Locksmith2.ps1
#   4. Add an elseif detection branch in the appropriate Find-LS2Vulnerable* function
$script:ESCDefinitions = data {
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

        ESC13  = @{
            # ESC13: Vulnerable Certificate Template - Group-Linked
            Technique          = 'ESC13'

            # A template is vulnerable when it can be used for authentication AND at least one of its
            # application policy OIDs (msPKI-Certificate-Policy) is linked to a universal group via
            # msDS-OIDToGroupLink on an msPKI-Enterprise-Oid AD object.
            Conditions         = @(
                @{ Property = 'AuthenticationEKUExist'; Value = $true }
                @{ Property = 'HasLinkedGroupOIDPolicy'; Value = $true }
            )

            # Properties to check for problematic enrollees
            EnrolleeProperties = @(
                'DangerousEnrollee'
                'LowPrivilegeEnrollee'
            )

            # Issue description template
            IssueTemplate      = @(
                "`$(IdentityReference) can enroll in the `$(TemplateName) template, which uses a Client Authentication EKU "
                "and has an application policy OID linked to the group `$(LinkedGroup) in Active Directory.`n`n"
                "If this certificate is used for authentication, the holder will silently gain the rights of the linked "
                "group. This group membership is not visible via standard AD enumeration tools.`n`n"
                "An attacker can exploit this by enrolling in the template and then using the resulting certificate to "
                "authenticate, gaining the privileges of the linked group without appearing in its member list.`n`n"
                "More info:`n"
                "  - https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53"
            )

            # Fix script template (quick mitigation — Manager Approval)
            FixTemplate        = @(
                "# Quick mitigation: Enable Manager Approval to require approval before certificate issuance"
                "`$Object = '`$(DistinguishedName)'"
                "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}"
                "# Long-term fix: remove the OID-to-group link from the msPKI-Enterprise-Oid object"
                "# Get-ADObject '<OID object DN>' | Set-ADObject -Clear msDS-OIDToGroupLink"
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

        ESC8   = @{
            # ESC8: NTLM Relay to AD CS HTTP Endpoints
            Technique      = 'ESC8'

            # EndpointBased signals Find-LS2VulnerableCA to use the per-endpoint branch
            EndpointBased  = $true

            # Issue text is built dynamically per endpoint in Find-LS2VulnerableCA.
            # These templates are used as fallback / documentation only.
            IssueTemplate  = @(
                "The web enrollment endpoint at `$(URL) is vulnerable to NTLM relay attacks.`n`n"
                "An attacker who can intercept network traffic (e.g., via responder, mitm6, or similar) "
                "can relay NTLM authentication to this endpoint and obtain a certificate on behalf of the "
                "intercepted account.`n`n"
                "More info:`n"
                "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
            )

            FixTemplate    = @(
                "# ESC8 Fix: require HTTPS with EPA and disable NTLM where possible.`n"
                "# 1. Enable EPA (Extended Protection for Authentication) on IIS.`n"
                "# 2. Disable NTLM authentication on the web enrollment site and use Kerberos only.`n"
                "# 3. If HTTP is enabled, redirect all traffic to HTTPS.`n"
                "# Reference: https://support.microsoft.com/kb/5005413"
            )

            RevertTemplate = @(
                "# ESC8 Revert: re-enable NTLM or HTTP as required by your environment.`n"
                "# Review IIS authentication settings on the CA host.`n"
                "# Reference: https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-server-certificate-autoenrollment"
            )
        }

        ESC15  = @{
            # ESC15: Schema v1 template with auth EKU — bypasses strong certificate mapping
            # (szOID_NTDS_CA_SECURITY_EXT is absent in schema v1 certificates)
            Technique          = 'ESC15'

            Conditions         = @(
                @{ Property = 'TemplateSchemaVersion'; Value = 1 }
                @{ Property = 'AuthenticationEKUExist'; Value = $true }
                @{ Property = 'ManagerApprovalNotRequired'; Value = $true }
                @{ Property = 'AuthorizedSignatureNotRequired'; Value = $true }
            )

            EnrolleeProperties = @(
                'DangerousEnrollee'
                'LowPrivilegeEnrollee'
            )

            IssueTemplate      = @(
                "`$(IdentityReference) can enroll in the `$(TemplateName) template, which uses a schema version 1 "
                "and a Client Authentication EKU.`n`n"
                "Schema v1 templates do not include the CA security extension (szOID_NTDS_CA_SECURITY_EXT) "
                "introduced by KB5014754. This means certificates issued from this template are not subject to "
                "strong certificate-to-account mapping enforcement, allowing an attacker to authenticate as any "
                "principal whose UPN or DNS name they can include in the Subject or SAN of the certificate.`n`n"
                "Until the template is upgraded to schema v2+, enabling Manager Approval is the recommended "
                "short-term mitigation to prevent unapproved enrollment.`n`n"
                "More info:`n"
                "  - https://support.microsoft.com/help/5014754"
            )

            FixTemplate        = @(
                "# Quick mitigation: Enable Manager Approval to require approval before certificate issuance"
                "`$Object = '`$(DistinguishedName)'"
                "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}"
                "# Long-term fix: supersede this template with a schema v2+ equivalent"
                "# See: https://www.gradenegger.eu/en/basics-replace-superseding-of-certificate-templates/"
            )

            RevertTemplate     = @(
                "# Disable Manager Approval"
                "`$Object = '`$(DistinguishedName)'"
                "Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}"
            )
        }

        Auditing = @{
            # Auditing: CA audit filter is not fully enabled (AuditFilter != 127)
            Technique      = 'Auditing'

            Conditions     = @(
                @{ Property = 'AuditingIncomplete'; Value = $true }
            )

            IssueTemplate  = @(
                "The Certification Authority `$(CAName) does not have full auditing enabled (AuditFilter=`$(AuditFilter)).`n`n"
                "All 7 audit categories (bitmask 127) should be enabled to ensure that certificate requests, "
                "revocations, and configuration changes are logged. Incomplete auditing makes it significantly "
                "harder to detect and investigate certificate-based attacks.`n`n"
                "More info:`n"
                "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
            )

            FixTemplate    = @(
                "# Enable all CA audit categories (bitmask 127)"
                "certutil -config `$(CAFullName) -setreg CA\AuditFilter 127"
                "# Restart Certificate Services for the change to take effect"
                "Restart-Service -Name CertSvc -Force"
            )

            RevertTemplate = @(
                "# Restore original AuditFilter value"
                "certutil -config `$(CAFullName) -setreg CA\AuditFilter `$(AuditFilter)"
                "# Restart Certificate Services"
                "Restart-Service -Name CertSvc -Force"
            )
        }

        SchemaV1 = @{
            # SchemaV1: Any enabled schema v1 template — informational hygiene finding
            Technique      = 'SchemaV1'

            Conditions     = @(
                @{ Property = 'TemplateSchemaVersion'; Value = 1 }
                @{ Property = 'Enabled'; Value = $true }
            )

            IssueTemplate  = @(
                "The certificate template `$(TemplateName) uses schema version 1.`n`n"
                "Schema v1 templates were introduced in Windows 2000 and lack several security features "
                "available in later schema versions. Certificates issued from schema v1 templates do not "
                "include the CA security extension (szOID_NTDS_CA_SECURITY_EXT), reducing their compatibility "
                "with strong certificate mapping requirements.`n`n"
                "Consider superseding this template with a schema v2+ equivalent."
            )

            FixTemplate    = @(
                "# Schema v1 templates cannot be upgraded in-place."
                "# Supersede this template by creating a new schema v2 (or later) template with equivalent settings,"
                "# then configure the old template to be superseded by the new one."
                "# See: https://www.gradenegger.eu/en/basics-replace-superseding-of-certificate-templates/"
            )

            RevertTemplate = @(
                "# No automated revert. Template schema version cannot be changed via script."
                "# If you superseded this template, re-enable the old template and remove the superseding relationship."
            )
        }
    }
}

# ============================================================================
# Scoring metadata for Set-LS2RiskRating
# Defined outside data{} because data{} only allows literals and restricted syntax.
# Keys are merged into $script:ESCDefinitions at load time.
# ============================================================================
$script:ESCScoringMetadata = @{
    ESC1   = @{
        BaseScore             = 0
        TechniqueBonus        = 1
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC5a', 'ESC5o')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $true
                RequiredObjectClass      = 'pKIEnrollmentService'
                OnlyEnabledMatches       = $false
            }
        )
    }
    ESC2   = @{
        BaseScore             = 0
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC5a', 'ESC5o')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $true
                RequiredObjectClass      = 'pKIEnrollmentService'
                OnlyEnabledMatches       = $false
            }
            @{
                RequiredTechniquePatterns = @('ESC15')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $false
                RequiredObjectClass      = ''
                OnlyEnabledMatches       = $true
            }
        )
    }
    ESC3c1 = @{
        BaseScore             = 0
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC5a', 'ESC5o')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $true
                RequiredObjectClass      = 'pKIEnrollmentService'
                OnlyEnabledMatches       = $false
            }
            @{
                RequiredTechniquePatterns = @('ESC15')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $false
                RequiredObjectClass      = ''
                OnlyEnabledMatches       = $true
            }
        )
    }
    ESC3c2 = @{
        BaseScore             = 0
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC5a', 'ESC5o')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $true
                RequiredObjectClass      = 'pKIEnrollmentService'
                OnlyEnabledMatches       = $false
            }
            @{
                RequiredTechniquePatterns = @('ESC3c1', 'ESC2')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $false
                RequiredObjectClass      = ''
                OnlyEnabledMatches       = $true
            }
        )
    }
    ESC4a  = @{
        BaseScore             = 0
        TechniqueBonus        = 1
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC5a', 'ESC5o')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $true
                RequiredObjectClass      = 'pKIEnrollmentService'
                OnlyEnabledMatches       = $false
            }
        )
    }
    ESC4o  = @{
        BaseScore             = 0
        TechniqueBonus        = 1
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $false
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC5a', 'ESC5o')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $true
                RequiredObjectClass      = 'pKIEnrollmentService'
                OnlyEnabledMatches       = $false
            }
        )
    }
    ESC5a  = @{
        BaseScore             = 0
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $false
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $true
        ObjectClassBonuses    = @{
            'certificationAuthority' = 2
            'pKIEnrollmentService'   = 2
            'computer'               = 2
            'msPKI-Enterprise-Oid'   = 1
            'container'              = 1
        }
        NtAuthBonus           = 2
        EndpointBonuses       = @{}
        CrossESCModifiers     = @()
    }
    ESC5o  = @{
        BaseScore             = 0
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $false
        ApplyPrincipalRisk    = $false
        ApplyObjectClassBonus = $true
        ObjectClassBonuses    = @{
            'certificationAuthority' = 2
            'pKIEnrollmentService'   = 2
            'computer'               = 2
            'msPKI-Enterprise-Oid'   = 1
            'container'              = 1
        }
        NtAuthBonus           = 2
        EndpointBonuses       = @{}
        CrossESCModifiers     = @()
    }
    ESC6   = @{
        BaseScore             = 3
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $false
        ApplyPrincipalRisk    = $false
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC9', 'ESC16')
                Bonus                    = 2
                BonusFromPrincipalRisk   = $false
                BonusCap                 = 2
                OnlyWhenDisabled         = $false
                RequiredObjectClass      = ''
                OnlyEnabledMatches       = $false
            }
        )
    }
    ESC7a  = @{
        BaseScore             = 3
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $false
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @()
    }
    ESC7m  = @{
        BaseScore             = 3
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $false
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @()
    }
    ESC8   = @{
        BaseScore             = 3
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $false
        ApplyPrincipalRisk    = $false
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{
            'HTTP'           = 2
            'HTTPS-NTLM'     = 2
            'HTTPS-Kerberos' = 1
        }
        CrossESCModifiers     = @()
    }
    ESC9   = @{
        BaseScore             = 0
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC5a', 'ESC5o')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $true
                RequiredObjectClass      = 'pKIEnrollmentService'
                OnlyEnabledMatches       = $false
            }
            @{
                RequiredTechniquePatterns = @('ESC6')
                Bonus                    = 2
                BonusFromPrincipalRisk   = $false
                BonusCap                 = 2
                OnlyWhenDisabled         = $false
                RequiredObjectClass      = ''
                OnlyEnabledMatches       = $false
            }
        )
    }
    ESC11  = @{
        BaseScore             = 3
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $false
        ApplyPrincipalRisk    = $false
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @()
    }
    ESC13  = @{
        BaseScore             = 0
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC5a', 'ESC5o')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $true
                RequiredObjectClass      = 'pKIEnrollmentService'
                OnlyEnabledMatches       = $false
            }
        )
    }
    ESC15  = @{
        BaseScore             = 0
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $true
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC5a', 'ESC5o')
                Bonus                    = 0
                BonusFromPrincipalRisk   = $true
                BonusCap                 = 2
                OnlyWhenDisabled         = $true
                RequiredObjectClass      = 'pKIEnrollmentService'
                OnlyEnabledMatches       = $false
            }
        )
    }
    ESC16  = @{
        BaseScore             = 3
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $false
        ApplyPrincipalRisk    = $false
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @(
            @{
                RequiredTechniquePatterns = @('ESC6')
                Bonus                    = 2
                BonusFromPrincipalRisk   = $false
                BonusCap                 = 2
                OnlyWhenDisabled         = $false
                RequiredObjectClass      = ''
                OnlyEnabledMatches       = $false
            }
        )
    }
    SchemaV1 = @{
        BaseScore             = 1
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $true
        ApplyPrincipalRisk    = $false
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @()
    }
    Auditing = @{
        BaseScore             = 3
        TechniqueBonus        = 0
        ApplyEnabledModifier  = $false
        ApplyPrincipalRisk    = $false
        ApplyObjectClassBonus = $false
        ObjectClassBonuses    = @{}
        NtAuthBonus           = 0
        EndpointBonuses       = @{}
        CrossESCModifiers     = @()
    }
}

# Merge scoring metadata into ESCDefinitions
foreach ($technique in $script:ESCScoringMetadata.Keys) {
    if ($script:ESCDefinitions.ContainsKey($technique)) {
        foreach ($scoringKey in $script:ESCScoringMetadata[$technique].Keys) {
            $script:ESCDefinitions[$technique][$scoringKey] = $script:ESCScoringMetadata[$technique][$scoringKey]
        }
    }
}
