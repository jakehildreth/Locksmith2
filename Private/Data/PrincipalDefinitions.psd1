<#
.SYNOPSIS
Security Principal Definitions for AD CS Security Auditing

.DESCRIPTION
This PowerShell Data File defines security principal patterns used to classify
identities in Active Directory Certificate Services security analysis.

Principal Categories:

1. SafePrincipals - High-privilege administrative groups expected to have broad permissions
   - Domain Admins, Enterprise Admins, SYSTEM, Domain Controllers, etc.
   - These are considered "safe" to have enrollment and modification permissions
   
2. DangerousPrincipals - Overly broad groups that should not have enrollment permissions
   - Everyone, Authenticated Users, Domain Users, Domain Computers, etc.
   - Grant to these represents privilege escalation risk
   
3. StandardOwners - Principals that should own AD CS objects
   - Similar to SafePrincipals but focused on ownership validation
   - Objects owned by non-standard principals may be vulnerable to ESC4-style attacks

Each array contains SIDs, NTAccount names, and regex patterns for matching.
Regex patterns (ending in $) enable matching entire SID families (e.g., -512$ matches all Domain Admins groups).

.NOTES
Common SID Suffixes:
- -500: Builtin Administrator account
- -512: Domain Admins group
- -516: Domain Controllers group
- -517: Cert Publishers group
- -518: Schema Admins group
- -519: Enterprise Admins group
- -521: Read-Only Domain Controllers group
- -526: Key Admins group
- -527: Enterprise Key Admins group
- -513: Domain Users group
- -515: Domain Computers group
- -544: Builtin Administrators group
- -545: Builtin Users group

Well-Known SIDs:
- S-1-0-0: NULL SID
- S-1-1-0: Everyone
- S-1-5-7: Anonymous Logon
- S-1-5-10: SELF
- S-1-5-11: Authenticated Users
- S-1-5-18: SYSTEM
- S-1-5-32-544: BUILTIN\Administrators
- S-1-5-32-545: BUILTIN\Users

.LINK
https://posts.specterops.io/certified-pre-owned-d95910965cd2

.LINK
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
#>

@{
    # Version of this data file format (for future compatibility)
    DataVersion         = '1.0'
    
    # ============================================================================
    # Safe Principals - High-privilege administrative groups
    # ============================================================================
    # These principals are considered safe/expected to have broad permissions
    # on AD CS objects. Used to filter out expected administrative access.
    
    SafePrincipals      = @(
        # Domain administrative groups
        '-512$'                                        # Domain Admins (all domains)
        '-519$'                                        # Enterprise Admins (forest root)
        '-518$'                                        # Schema Admins (forest root)
        '-517$'                                        # Cert Publishers
        '-526$'                                        # Key Admins
        '-527$'                                        # Enterprise Key Admins
        
        # Builtin administrative groups
        'S-1-5-32-544'                                 # BUILTIN\Administrators
        '-544$'                                        # Builtin Administrators (domain-specific)
        '-500$'                                        # Builtin Administrator account
        
        # System and service accounts
        'S-1-5-18'                                     # SYSTEM
        '-18$'                                         # SYSTEM (pattern match)
        'NT AUTHORITY\\SYSTEM'                         # SYSTEM (NTAccount format)
        
        # Domain controller groups
        '-516$'                                        # Domain Controllers
        '-521$'                                        # Read-Only Domain Controllers
        '-498$'                                        # Enterprise Domain Controllers
        'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS'  # Enterprise Domain Controllers (NTAccount)
        '-9$'                                          # Enterprise Read-Only Domain Controllers
        
        # Special identities
        'S-1-5-10'                                     # SELF
        'NT AUTHORITY\\SELF'                           # SELF (NTAccount format)
    )
    
    # ============================================================================
    # Dangerous Principals - Overly broad groups
    # ============================================================================
    # These principals represent overly permissive access that should not have
    # enrollment or modification permissions on AD CS objects. Indicates potential
    # privilege escalation vulnerabilities (ESC1, ESC2, ESC3, etc.).
    
    DangerousPrincipals = @(
        # NULL and universal access
        'S-1-0-0'                            # NULL SID
        'S-1-1-0'                            # Everyone
        'Everyone'                           # Everyone (NTAccount format)
        
        # Anonymous access
        'S-1-5-7'                            # Anonymous Logon
        'NT AUTHORITY\\ANONYMOUS LOGON'      # Anonymous Logon (NTAccount format)
        
        # Authenticated users (still too broad)
        'S-1-5-11'                           # Authenticated Users
        'NT AUTHORITY\\Authenticated Users'  # Authenticated Users (NTAccount format)
        
        # Builtin broad groups
        'S-1-5-32-545'                       # BUILTIN\Users
        'BUILTIN\\Users'                     # BUILTIN\Users (NTAccount format)
        
        # Domain-wide groups
        '-513$'                              # Domain Users (all domains)
        '-515$'                              # Domain Computers (all domains)
    )
    
    # ============================================================================
    # Standard Owners - Principals that should own AD CS objects
    # ============================================================================
    # These principals are expected to own certificate templates, CAs, and other
    # AD CS objects. Objects owned by other principals may be vulnerable to
    # ESC4-style attacks where the owner can modify security-critical settings.
    #
    # Per Microsoft best practices, AD CS objects should be owned exclusively by
    # Enterprise Admins to prevent privilege escalation through ownership modification.
    #
    # Note: The forest-specific Enterprise Admins SID will be dynamically added during
    # initialization to ensure only THIS forest's Enterprise Admins are considered standard.
    
    StandardOwners      = @(
        # Forest-specific Enterprise Admins SID will be added at runtime
        # Do not use regex patterns like -519$ as they would match Enterprise Admins from other forests
    )
}
