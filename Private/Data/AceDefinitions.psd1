<#
.SYNOPSIS
Dangerous ACE Definitions for AD CS Security Auditing

.DESCRIPTION
This PowerShell Data File defines Active Directory permissions that are considered
dangerous when granted on AD CS objects (templates, CAs, containers, computer accounts).
These permissions enable various privilege escalation attacks by allowing principals to 
modify object settings to make them exploitable.

Key attack vectors by object class:
- Templates (pKICertificateTemplate): ESC1, ESC4 - Modify SAN/EKU/approval settings
- CAs (pKIEnrollmentService): ESC7 - Grant ManageCA/ManageCertificates rights
- Containers (container, certificationAuthority): ESC5 - Create vulnerable templates/CAs, modify NTAuthCertificates
- Computers (computer): ESC9, ESC10 - Modify CA host computer account settings

Each entry includes:
- Name: Descriptive name for the permission
- Rights: ActiveDirectoryRights value to match
- ObjectType: GUID for property-specific permissions ($null for generic rights)
- ApplicableToClasses: Array of objectClass/SchemaClassName values where this is dangerous
- Description: What the permission allows and why it's dangerous

.NOTES
ObjectType GUIDs for AD CS properties:

Template properties (pKICertificateTemplate):
- msPKI-Certificate-Name-Flag: ea1dddc4-60ff-416e-8cc0-17cee534bce7
- pKIExtendedKeyUsage: e0fa1e69-9b45-11d0-afdd-00c04fd930c9
- msPKI-Enrollment-Flag: 1ede2375-5dd4-4fca-b62f-75ff65cc1c21
- msPKI-RA-Signature: fc0a1e69-9b45-11d0-afdd-00c04fd930c9
- pKIMaxIssuingDepth: 281416d9-1968-4c91-b96d-6c6d8b7f3e8c
- msPKI-Template-Schema-Version: 0b9e865e-3b3b-11d2-90cc-00c04fd91ab1
- msPKI-Template-Minor-Revision: 0b9e865f-3b3b-11d2-90cc-00c04fd91ab1
- msPKI-Certificate-Application-Policy: c4e311fc-4e4d-11d1-ab54-00a0c91e9b45

CA properties (pKIEnrollmentService):
- certificateTemplates: d15b6a0e-94e5-4a82-8c1a-2765f5cf222f

Computer properties (computer):
- msDS-AllowedToActOnBehalfOfOtherIdentity: 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79
- servicePrincipalName: f3a64788-5306-11d1-a9c5-0000f80367c1
- userAccountControl: bf967a68-0de6-11d0-a285-00aa003049e2

Container properties (container, certificationAuthority):
- cACertificate: bf967932-0de6-11d0-a285-00aa003049e2

Universal:
- All properties: 00000000-0000-0000-0000-000000000000

.LINK
https://specterops.io/blog/2021/06/17/certified-pre-owned/

.LINK
ESC4: Vulnerable Certificate Template Access Control

.LINK
ESC5: Vulnerable PKI Object Access Control

.LINK
ESC7: Vulnerable Certificate Authority Access Control

.LINK
ESC9: No Security Extension (StrongCertificateBindingEnforcement = 0)

.LINK
ESC10: Weak Certificate Mapping (CertificateMappingMethods allows UPN)
#>

@{
    # Version of this data file format (for future compatibility)
    DataVersion   = '2.0'
    
    # Dangerous ACE definitions applicable across AD CS object types
    DangerousAces = @(
        # ============================================================================
        # Full Control / Ownership (Applies to ALL object classes)
        # ============================================================================
        
        @{
            Name                = 'GenericAll'
            Rights              = 'GenericAll'
            ObjectType          = $null
            ApplicableToClasses = @('pKICertificateTemplate', 'pKIEnrollmentService', 'certificationAuthority', 'container', 'computer')
            Description         = 'Full control over the object - can modify any setting, permissions, or ownership'
        }
        
        @{
            Name                = 'WriteDacl'
            Rights              = 'WriteDacl'
            ObjectType          = $null
            ApplicableToClasses = @('pKICertificateTemplate', 'pKIEnrollmentService', 'certificationAuthority', 'container', 'computer')
            Description         = 'Can modify the discretionary access control list (DACL) - grants ability to give self additional permissions'
        }
        
        @{
            Name                = 'WriteOwner'
            Rights              = 'WriteOwner'
            ObjectType          = $null
            ApplicableToClasses = @('pKICertificateTemplate', 'pKIEnrollmentService', 'certificationAuthority', 'container', 'computer')
            Description         = 'Can take ownership of the object - enables full control via ownership'
        }
        
        # ============================================================================
        # Broad Write Permissions (Applies to ALL object classes)
        # ============================================================================
        
        @{
            Name                = 'GenericWrite'
            Rights              = 'GenericWrite'
            ObjectType          = $null
            ApplicableToClasses = @('pKICertificateTemplate', 'pKIEnrollmentService', 'certificationAuthority', 'container', 'computer')
            Description         = 'Can write to most object properties - enables modification of dangerous configuration settings'
        }
        
        @{
            Name                = 'WriteProperty-AllProperties'
            Rights              = 'WriteProperty'
            ObjectType          = '00000000-0000-0000-0000-000000000000'
            ApplicableToClasses = @('pKICertificateTemplate', 'pKIEnrollmentService', 'certificationAuthority', 'container', 'computer')
            Description         = 'Can write to all properties on the object'
        }
        
        # ============================================================================
        # Template-Specific Properties (ESC4)
        # ============================================================================
        
        @{
            Name                = 'WriteProperty-CertificateNameFlag'
            Rights              = 'WriteProperty'
            ObjectType          = 'ea1dddc4-60ff-416e-8cc0-17cee534bce7'  # msPKI-Certificate-Name-Flag
            ApplicableToClasses = @('pKICertificateTemplate')
            Description         = 'Can modify msPKI-Certificate-Name-Flag - enables SAN specification (ESC1 enabler)'
        }
        
        @{
            Name                = 'WriteProperty-ExtendedKeyUsage'
            Rights              = 'WriteProperty'
            ObjectType          = 'e0fa1e69-9b45-11d0-afdd-00c04fd930c9'  # pKIExtendedKeyUsage
            ApplicableToClasses = @('pKICertificateTemplate')
            Description         = 'Can modify pKIExtendedKeyUsage - enables adding authentication EKUs'
        }
        
        @{
            Name                = 'WriteProperty-CertificateApplicationPolicy'
            Rights              = 'WriteProperty'
            ObjectType          = 'c4e311fc-4e4d-11d1-ab54-00a0c91e9b45'  # msPKI-Certificate-Application-Policy
            ApplicableToClasses = @('pKICertificateTemplate')
            Description         = 'Can modify msPKI-Certificate-Application-Policy - alternative method to add authentication EKUs'
        }
        
        @{
            Name                = 'WriteProperty-EnrollmentFlag'
            Rights              = 'WriteProperty'
            ObjectType          = '1ede2375-5dd4-4fca-b62f-75ff65cc1c21'  # msPKI-Enrollment-Flag
            ApplicableToClasses = @('pKICertificateTemplate')
            Description         = 'Can modify msPKI-Enrollment-Flag - can disable manager approval requirement'
        }
        
        @{
            Name                = 'WriteProperty-RASignature'
            Rights              = 'WriteProperty'
            ObjectType          = 'fc0a1e69-9b45-11d0-afdd-00c04fd930c9'  # msPKI-RA-Signature
            ApplicableToClasses = @('pKICertificateTemplate')
            Description         = 'Can modify msPKI-RA-Signature - can reduce authorized signature requirements'
        }
        
        @{
            Name                = 'WriteProperty-MaxIssuingDepth'
            Rights              = 'WriteProperty'
            ObjectType          = '281416d9-1968-4c91-b96d-6c6d8b7f3e8c'  # pKIMaxIssuingDepth
            ApplicableToClasses = @('pKICertificateTemplate')
            Description         = 'Can modify pKIMaxIssuingDepth - can enable subordinate CA certificate issuance (ESC5 enabler)'
        }
        
        @{
            Name                = 'WriteProperty-TemplateSchemaVersion'
            Rights              = 'WriteProperty'
            ObjectType          = '0b9e865e-3b3b-11d2-90cc-00c04fd91ab1'  # msPKI-Template-Schema-Version
            ApplicableToClasses = @('pKICertificateTemplate')
            Description         = 'Can modify msPKI-Template-Schema-Version - can upgrade template to access additional properties'
        }
        
        @{
            Name                = 'WriteProperty-TemplateMinorRevision'
            Rights              = 'WriteProperty'
            ObjectType          = '0b9e865f-3b3b-11d2-90cc-00c04fd91ab1'  # msPKI-Template-Minor-Revision
            ApplicableToClasses = @('pKICertificateTemplate')
            Description         = 'Can modify msPKI-Template-Minor-Revision - can trigger template republication'
        }
        
        # ============================================================================
        # CA-Specific Properties (ESC5a)
        # ============================================================================
        
        @{
            Name                = 'WriteProperty-certificateTemplates'
            Rights              = 'WriteProperty'
            ObjectType          = 'd15b6a0e-94e5-4a82-8c1a-2765f5cf222f'  # certificateTemplates
            ApplicableToClasses = @('pKIEnrollmentService')
            Description         = 'Can modify certificateTemplates attribute - can add vulnerable templates to CA publication list or remove security-critical templates'
        }
        
        # ============================================================================
        # Computer-Specific Properties (ESC5a)
        # ============================================================================
        
        @{
            Name                = 'WriteProperty-AllowedToActOnBehalfOfOtherIdentity'
            Rights              = 'WriteProperty'
            ObjectType          = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'  # msDS-AllowedToActOnBehalfOfOtherIdentity
            ApplicableToClasses = @('computer')
            Description         = 'Can modify msDS-AllowedToActOnBehalfOfOtherIdentity - enables resource-based constrained delegation attacks on CA host'
        }
        
        @{
            Name                = 'WriteProperty-ServicePrincipalName'
            Rights              = 'WriteProperty'
            ObjectType          = 'f3a64788-5306-11d1-a9c5-0000f80367c1'  # servicePrincipalName
            ApplicableToClasses = @('computer')
            Description         = 'Can modify servicePrincipalName - can add SPNs for Kerberoasting or impersonation attacks'
        }
        
        @{
            Name                = 'WriteProperty-UserAccountControl'
            Rights              = 'WriteProperty'
            ObjectType          = 'bf967a68-0de6-11d0-a285-00aa003049e2'  # userAccountControl
            ApplicableToClasses = @('computer')
            Description         = 'Can modify userAccountControl - can enable TRUSTED_FOR_DELEGATION or disable account security settings'
        }
        
        # ============================================================================
        # Container-Specific Properties (ESC5)
        # ============================================================================
        
        @{
            Name                = 'CreateChild-All'
            Rights              = 'CreateChild'
            ObjectType          = $null
            ApplicableToClasses = @('container')
            Description         = 'Can create child objects in the container - enables creation of new vulnerable certificate templates or CAs (ESC5)'
        }
        
        @{
            Name       = 'WriteProperty-cACertificate'
            Rights     = 'WriteProperty'
            ObjectType = 'bf967932-0de6-11d0-a285-00aa003049e2'
            ApplicableToClasses = @('certificationAuthority')
            Description         = 'Can modify cACertificate attribute - can add rogue CA certificates to NTAuthCertificates store for enterprise trust'
        }
    )
}
