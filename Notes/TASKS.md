# ESC6, ESC7, and ESC11 Implementation Tasks

## Overview

This document outlines the tasks required to implement ESC6, ESC7, and ESC11 vulnerability detection in Locksmith2. The infrastructure for collecting the necessary data is already in place - we just need to create the detection and reporting functions.

### Current State

The project already collects the required data:
- **ESC6**: CA EditFlags are collected via `Set-CAEditFlags.ps1` (checks for `SANFlagEnabled` property)
- **ESC7**: CA Administrator and Certificate Manager roles are collected via `Set-CAAdministrator.ps1`, `Set-CACertificateManager.ps1`, and dangerous/low-privilege variants
- **ESC11**: CA InterfaceFlags are collected via `Set-CAInterfaceFlags.ps1` (checks for `RPCEncryptionNotRequired` property)

**What's Missing**: Vulnerability finding functions to detect and report these issues as LS2Issue objects.

---

## Implementation Tasks

### Task 1: Create Find-VulnerableCA.ps1

**Priority**: HIGH (Core detection function needed for all three ESC techniques)

**Location**: `Private/Find/Find-VulnerableCA.ps1`

**Description**: Create a new function to detect CA-level vulnerabilities, following the pattern established by `Find-VulnerableTemplates.ps1`.

**Requirements**:
- Accept `-Technique` parameter with ValidateSet: `'ESC6', 'ESC7', 'ESC11'`
- Load ESC definitions from `ESCDefinitions.psd1`
- Query `$script:AdcsObjectStore` for CA objects (pKIEnrollmentService)
- Filter CAs by conditions specified in the definition
- For ESC7: Iterate through admin/manager properties and create issues per principal
- Create `LS2Issue` objects with appropriate properties
- Store issues in `$script:IssueStore`
- Return issues to pipeline

**Key Differences from Find-VulnerableTemplates**:
1. Queries for CAs instead of templates: `$script:AdcsObjectStore.Values | Where-Object { $_.objectClass -contains 'pKIEnrollmentService' }`
2. ESC6 and ESC11 are configuration-based (no enrollee properties needed)
3. ESC7 requires iteration through role assignment properties (similar to enrollee iteration)
4. Uses `CAFullName` property instead of template name

**Function Signature**:
```powershell
function Find-VulnerableCA {
    <#
    .SYNOPSIS
        Identifies vulnerable AD CS Certification Authorities based on ESC technique definitions.

    .DESCRIPTION
        Reads ESC technique definitions from ESCDefinitions.psd1, queries the AdcsObjectStore
        for matching CAs, and generates issues for configuration problems or dangerous role assignments.

    .PARAMETER Technique
        ESC technique name to scan for (e.g., 'ESC6', 'ESC7', 'ESC11')

    .EXAMPLE
        Find-VulnerableCA -Technique ESC6

    .EXAMPLE
        Find-VulnerableCA -Technique ESC7

    .OUTPUTS
        LS2Issue objects for each vulnerability found
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ESC6', 'ESC7', 'ESC11')]
        [string]$Technique
    )

    # Implementation goes here
}
```

**Implementation Notes**:
- For ESC6/ESC11: Check conditions directly on CA object, create single issue per vulnerable CA
- For ESC7: Check AdminProperties array, iterate through dangerous/low-privilege arrays, create issue per problematic principal
- Issue variables to expand:
  - `$(CAName)`: CA common name
  - `$(CAFullName)`: Full CA name (SERVER\CA)
  - `$(IdentityReference)`: For ESC7, the principal with dangerous permissions
  - `$(RoleType)`: For ESC7, either "Administrators" or "Officers"

---

### Task 2: Add ESC6 Definition to ESCDefinitions.psd1

**Priority**: HIGH

**Location**: `Private/Data/ESCDefinitions.psd1`

**Description**: Add the ESC6 technique definition for detecting CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 enabled.

**Code to Add**:
```powershell
ESC6 = @{
    Technique = 'ESC6'
    
    # Conditions that CAs must match to be vulnerable
    Conditions = @(
        @{ Property = 'SANFlagEnabled'; Value = $true }
    )
    
    # Issue description template
    IssueTemplate = @(
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
    FixTemplate = @(
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
```

**Background**: ESC6 occurs when the CA-level flag EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled, which allows requesters to specify arbitrary Subject Alternative Names on ANY certificate request, regardless of template settings. This completely bypasses template-level SAN restrictions.

---

### Task 3: Add ESC11 Definition to ESCDefinitions.psd1

**Priority**: HIGH

**Location**: `Private/Data/ESCDefinitions.psd1`

**Description**: Add the ESC11 technique definition for detecting CAs that don't require RPC encryption.

**Code to Add**:
```powershell
ESC11 = @{
    Technique = 'ESC11'
    
    # Conditions that CAs must match to be vulnerable
    Conditions = @(
        @{ Property = 'RPCEncryptionNotRequired'; Value = $true }
    )
    
    # Issue description template
    IssueTemplate = @(
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
    FixTemplate = @(
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
```

**Background**: ESC11 occurs when a CA doesn't enforce RPC encryption (IF_ENFORCEENCRYPTICERTREQUEST flag is disabled). This allows NTLM relay attacks where an attacker can relay authentication to the CA and request certificates on behalf of the victim.

---

### Task 4: Add ESC7 Definition to ESCDefinitions.psd1

**Priority**: HIGH (More complex than ESC6/ESC11)

**Location**: `Private/Data/ESCDefinitions.psd1`

**Description**: Add the ESC7 technique definition for detecting dangerous CA Administrator and Certificate Manager role assignments.

**Code to Add**:
```powershell
ESC7 = @{
    Technique = 'ESC7'
    
    # Properties to check for problematic CA administrators/managers
    AdminProperties = @(
        'DangerousCAAdministrator'
        'LowPrivilegeCAAdministrator'
        'DangerousCACertificateManager'
        'LowPrivilegeCACertificateManager'
    )
    
    # Issue description template for CA Administrators
    IssueTemplateCAAdmin = @(
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
    
    # Issue description template for Certificate Managers
    IssueTemplateCertManager = @(
        "`$(IdentityReference) has Certificate Manager rights on `$(CAName).`n`n"
        "Certificate Managers can approve/deny certificate requests and revoke certificates. "
        "This principal should not have these rights.`n`n"
        "An attacker with these rights can approve malicious certificate requests that would "
        "normally require manager approval.`n`n"
        "More info:`n"
        "  - https://posts.specterops.io/certified-pre-owned-d95910965cd2"
    )
    
    # Remediation requires manual review
    FixTemplate = @(
        "# Remove CA Administrator/Certificate Manager role"
        "# For CA Administrators:"
        "certutil -config `$(CAFullName) -delreg ca\\Security\\Roles\\Administrators\\`$(IdentityReference)"
        "# For Certificate Managers:"
        "certutil -config `$(CAFullName) -delreg ca\\Security\\Roles\\Officers\\`$(IdentityReference)"
        "# Restart Certificate Services"
        "Restart-Service -Name CertSvc -Force"
        "# NOTE: Review whether this principal needs these rights before removing"
    )
    
    # Revert template
    RevertTemplate = @(
        "# Re-add CA Administrator/Certificate Manager role"
        "# For CA Administrators:"
        "certutil -config `$(CAFullName) -setreg ca\\Security\\Roles\\Administrators\\`$(IdentityReference) +ManageCA"
        "# For Certificate Managers:"
        "certutil -config `$(CAFullName) -setreg ca\\Security\\Roles\\Officers\\`$(IdentityReference) +ManageCertificates"
        "# Restart Certificate Services"
        "Restart-Service -Name CertSvc -Force"
    )
}
```

**Background**: ESC7 occurs when dangerous or low-privilege principals have CA Administrator or Certificate Manager rights. These roles can approve certificate requests, modify CA configuration, and perform other sensitive operations.

**Implementation Notes for Find-VulnerableCA**:
- Check each of the four AdminProperties arrays
- For each SID in the arrays, create a separate issue
- Determine role type from property name (Administrator vs Manager)
- Use appropriate issue template based on role type
- Expand `$(RoleType)` to either "Administrators" or "Officers" for fix script

---

### Task 5: Update Invoke-Locksmith2.ps1

**Priority**: HIGH

**Location**: `Public/Invoke-Locksmith2.ps1`

**Description**: Add vulnerability scans for ESC6, ESC7, and ESC11 to the main orchestration function.

**Code to Add** (after line 202, after ESC9 scan):
```powershell
Write-Verbose "Checking for ESC6 (CA EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled)..."
[array]$ESC6Issues = Find-VulnerableCA -Technique ESC6

# Count total ESC6 issues
$esc6Count = 0
foreach ($dn in $script:IssueStore.Keys) {
    if ($script:IssueStore[$dn].ContainsKey('ESC6')) {
        $esc6Count += $script:IssueStore[$dn]['ESC6'].Count
    }
}
Write-Verbose "Found $esc6Count ESC6 issue(s)"

Write-Verbose "Checking for ESC7 (Vulnerable CA Access Control)..."
[array]$ESC7Issues = Find-VulnerableCA -Technique ESC7

# Count total ESC7 issues
$esc7Count = 0
foreach ($dn in $script:IssueStore.Keys) {
    if ($script:IssueStore[$dn].ContainsKey('ESC7')) {
        $esc7Count += $script:IssueStore[$dn]['ESC7'].Count
    }
}
Write-Verbose "Found $esc7Count ESC7 issue(s)"

Write-Verbose "Checking for ESC11 (CA RPC Encryption Not Required)..."
[array]$ESC11Issues = Find-VulnerableCA -Technique ESC11

# Count total ESC11 issues
$esc11Count = 0
foreach ($dn in $script:IssueStore.Keys) {
    if ($script:IssueStore[$dn].ContainsKey('ESC11')) {
        $esc11Count += $script:IssueStore[$dn]['ESC11'].Count
    }
}
Write-Verbose "Found $esc11Count ESC11 issue(s)"
```

**Location**: Insert after the ESC9 vulnerability scan (around line 202)

---

### Task 6: Update LS2AdcsObject Class (Optional Enhancement)

**Priority**: MEDIUM (Nice to have, not required)

**Location**: `Classes/LS2AdcsObject.ps1`

**Description**: Consider adding a `IsCertificationAuthority()` method to the LS2AdcsObject class for consistency with `IsCertificateTemplate()`.

**Code to Add**:
```powershell
[bool] IsCertificationAuthority() {
    return $this.objectClass -contains 'pKIEnrollmentService'
}
```

**Usage in Find-VulnerableCA**:
```powershell
$allCAs = $script:AdcsObjectStore.Values | Where-Object { $_.IsCertificationAuthority() }
```

**Alternative** (if not adding method):
```powershell
$allCAs = $script:AdcsObjectStore.Values | Where-Object { $_.objectClass -contains 'pKIEnrollmentService' }
```

---

### Task 7: Testing

**Priority**: HIGH

**Description**: Validate the implementation against a lab environment with known ESC6, ESC7, and ESC11 vulnerabilities.

**Test Cases**:

1. **ESC6 Testing**:
   - Enable EDITF_ATTRIBUTESUBJECTALTNAME2 on a test CA
   - Run `Invoke-Locksmith2` and verify ESC6 issue is detected
   - Verify issue description, fix script, and revert script are correct
   - Test fix script to ensure flag is disabled correctly

2. **ESC7 Testing**:
   - Add a test user to CA Administrators role: `certutil -config SERVER\CA -setreg ca\Security\Roles\Administrators\DOMAIN\TestUser +ManageCA`
   - Add a test user to Certificate Managers role: `certutil -config SERVER\CA -setreg ca\Security\Roles\Officers\DOMAIN\TestUser +ManageCertificates`
   - Run `Invoke-Locksmith2` and verify ESC7 issues are detected for both roles
   - Verify separate issues are created for each dangerous principal
   - Test that dangerous principals (Everyone, Authenticated Users, etc.) are detected
   - Test that low-privilege custom principals are detected

3. **ESC11 Testing**:
   - Disable IF_ENFORCEENCRYPTICERTREQUEST on test CA: `certutil -config SERVER\CA -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST`
   - Restart Certificate Services
   - Run `Invoke-Locksmith2` and verify ESC11 issue is detected
   - Verify issue description, fix script, and revert script are correct
   - Test fix script to ensure flag is enabled correctly

4. **Integration Testing**:
   - Run full scan with multiple ESC types enabled
   - Verify IssueStore structure is correct
   - Verify counts are accurate
   - Verify verbose output is helpful

---

## Implementation Order

1. **Task 2**: Add ESC6 definition (easiest, single condition check)
2. **Task 3**: Add ESC11 definition (similar to ESC6)
3. **Task 4**: Add ESC7 definition (most complex, role-based)
4. **Task 1**: Create Find-VulnerableCA.ps1 (core function, needs all definitions)
5. **Task 5**: Update Invoke-Locksmith2.ps1 (wire up detection)
6. **Task 6**: Optional class enhancement
7. **Task 7**: Testing and validation

---

## Technical Notes

### Issue Store Structure

For CA issues, the IssueStore key should be the CA's Distinguished Name:
```powershell
$script:IssueStore[$ca.distinguishedName][$technique] += $issue
```

### LS2Issue Properties for CA Issues

CA-based issues should populate:
- `Technique`: 'ESC6', 'ESC7', or 'ESC11'
- `Forest`: Forest where CA is located
- `Name`: CA common name (cn property)
- `DistinguishedName`: CA's DN
- `CAFullName`: SERVER\CA format (for certutil commands)
- `Issue`: Expanded issue description
- `Fix`: Expanded fix script
- `Revert`: Expanded revert script

For ESC7 specifically, also populate:
- `IdentityReference`: Principal with dangerous permissions
- `IdentityReferenceSID`: SID of the principal
- `ActiveDirectoryRights`: Not applicable for CA roles, can be empty or "CAAdministrator"/"CertificateManager"

### Variable Expansion in Templates

When creating issues, expand these variables in the template strings:
- `$(CAName)`: `$ca.cn` or `$ca.Properties['cn'][0]`
- `$(CAFullName)`: `$ca.CAFullName` from AdcsObjectStore
- `$(IdentityReference)`: From PrincipalStore name resolution
- `$(RoleType)`: "Administrators" or "Officers" based on property being checked

Example:
```powershell
$issueText = $issueTemplate `
    -replace '\$\(CAName\)', $caName `
    -replace '\$\(CAFullName\)', $caFullName
```

### Error Handling

- Silently skip CAs without required properties (e.g., missing CAFullName)
- Log verbose messages for skipped CAs
- Use try/catch blocks around SID/principal resolution
- Continue processing remaining CAs if one fails

---

## References

- [SpecterOps Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [ESC11 Blog Post](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d)
- [Existing Find-VulnerableTemplates.ps1](../Private/Find/Find-VulnerableTemplates.ps1)
- [ESCDefinitions.psd1](../Private/Data/ESCDefinitions.psd1)
- [LS2Issue Class](../Classes/LS2Issue.ps1)

---

## Status

- [ ] Task 1: Create Find-VulnerableCA.ps1
- [ ] Task 2: Add ESC6 definition
- [ ] Task 3: Add ESC11 definition
- [ ] Task 4: Add ESC7 definition
- [ ] Task 5: Update Invoke-Locksmith2.ps1
- [ ] Task 6: Optional class enhancement
- [ ] Task 7: Testing and validation

**Created**: December 22, 2025  
**Target Completion**: TBD  
**Assigned To**: TBD
