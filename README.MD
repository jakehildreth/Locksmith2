![The Locksmith 2 logo features the word "locksmith" followed by the number "2" in a bold, blocky pixelated font. The design uses a gradient color scheme transitioning from light lavender on the left through pink tones to coral/orange on the right, set against a dark purple background with a rectangular border. The retro-digital aesthetic gives the logo a modern yet approachable feel, suggesting a tool that makes security management accessible and straightforward. The "2" indicates this is the second version of the Locksmith tool.](Images/Locksmith2.png)
# Find and Fix Active Directory Certificate Services (AD CS) Security Misconfigurations

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/Locksmith2.svg)](https://www.powershellgallery.com/packages/Locksmith2)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/jakehildreth/Locksmith2)


## Overview

Locksmith 2 is a comprehensive PowerShell module for auditing Active Directory Certificate Services (AD CS) infrastructure. It identifies security misconfigurations across certificate templates, certification authorities, and PKI infrastructure objects based on established ESC (Escalation) techniques.

Built for AD administrators, security professionals, and penetration testers, Locksmith 2 provides:

- **Automated vulnerability scanning** for ESC1-ESC16 techniques
- **Detailed remediation scripts** for each discovered issue
- **Granular cmdlets** for targeted security assessments
- **Comprehensive reporting** with human-readable output
- **Educational resources** explaining each vulnerability

Locksmith 2 represents the next generation in the Locksmith line of open-source AD CS security tooling, improving upon the original with better code organization, enhanced reporting, and deeper risk analysis.

## Features

- [x] Scan certificate templates for ESC vulnerabilities
- [x] Audit certification authorities for ESC vulnerabilities
- [x] Check PKI infrastructure objects for ESC vulnerabilities
- [x] Generate PowerShell remediation scripts
- [ ] Generate PowerShell scripts to revert remediations (partial)
- [x] Support for non-domain-joined systems
- [x] Object output
- [x] HTML dashboard output
- [x] In-dashboard export to CSV, Excel, PDF
- [ ] Interactive TUI for guided remediation

## Installation

### From PowerShell Gallery
```powershell
Install-Module -Name Locksmith2 -Scope CurrentUser -Force
```

### From Source

```powershell
git clone https://github.com/jakehildreth/Locksmith2.git
cd Locksmith2
Import-Module .\Locksmith2.psd1
```

## Quick Start

```powershell
# Interactive mode - prompts for forest and credentials
Invoke-Locksmith2

# Specify credentials
$cred = Get-Credential
Invoke-Locksmith2 -Forest 'contoso.com' -Credential $cred

# Targeted scanning for specific techniques
Find-LS2VulnerableTemplate -Technique ESC1
Find-LS2VulnerableCA -Technique ESC6

# Analyze which principals have the most exploitable paths
Find-LS2RiskyPrincipal -Top 10

# Inspect results
$stores = Get-LS2Stores
$stores.IssueStore['ESC1']
```

## Supported ESC Techniques

| Technique | Description | Target Objects | Sub-techniques |
|-----------|-------------|----------------|----------------|
| **ESC1** | Misconfigured Certificate Templates | Templates | — |
| **ESC2** | Certificate SubCA Abuse | Templates | — |
| **ESC3** | Enrollment Agent Restrictions | Templates | ESC3c1, ESC3c2 |
| **ESC4** | Vulnerable Access Control | Templates | ESC4a (ACL), ESC4o (owner) |
| **ESC5** | Vulnerable PKI Object Access Control | Infrastructure Objects | ESC5a (ACL), ESC5o (owner) |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled | CAs | — |
| **ESC7** | Vulnerable CA Administrator/Manager Roles | CAs | ESC7a (admin), ESC7m (manager) |
| **ESC8** | Vulnerable Web Enrollment Endpoints | CAs | — |
| **ESC9** | Weak Certificate Mappings | Templates | — |
| **ESC11** | Missing RPC Encryption | CAs | — |
| **ESC13** | Group-Linked OID Application Policy | Templates | — |
| **ESC16** | Disabled CRL/AIA Security Extensions | CAs | — |

For detailed information on ESC techniques, see [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) by SpecterOps.

## cmdlet Reference

### Primary Functions

#### `Invoke-Locksmith2`

Performs comprehensive AD CS security audit scanning for all known ESC vulnerabilities.

```powershell
Invoke-Locksmith2 [-Forest <String>] [-Credential <PSCredential>] [-Mode <Int>]
                  [-SkipVersionCheck] [-SkipPowerShellCheck]
                  [-ExpandGroups] [-Rescan]
# -Mode values:
#   (omit)  = return LS2Issue objects to the pipeline (default)
#   0       = Emulates Mode 0/no parameters from the original Locksmith: output issues to console as table
#   1       = Emulates Mode 1 from the original Locksmith: output issues + fix scripts to console as list
```

#### `Find-LS2VulnerableTemplate`

Scans certificate templates for specific ESC vulnerabilities.

```powershell
Find-LS2VulnerableTemplate -Technique <String>
# Supported: ESC1, ESC2, ESC3c1, ESC3c2, ESC4a, ESC4o, ESC9, ESC13
```

Returns: LS2Issue objects for programmatic use

#### `Find-LS2VulnerableCA`

Scans certification authorities for configuration issues and dangerous role assignments.

```powershell
Find-LS2VulnerableCA -Technique <String>
# Supported: ESC6, ESC7a, ESC7m, ESC8, ESC11, ESC16
```

Returns: LS2Issue objects for programmatic use

#### `Find-LS2VulnerableObject`

Scans PKI infrastructure objects (containers, computer accounts) for security issues.

```powershell
Find-LS2VulnerableObject -Technique <String>
# Supported: ESC5a, ESC5o
```

Returns: LS2Issue objects for programmatic use

#### `Get-LS2Stores`

Returns internal data stores populated during audits for inspection and analysis.

```powershell
Get-LS2Stores [-Name <String>]
# Valid -Name values: PrincipalStore, AdcsObjectStore, DomainStore, IssueStore,
#                     SafePrincipals, DangerousPrincipals, StandardOwners
# Omit -Name to return all stores.
```

Returns:
- **PrincipalStore**: Resolved principals by SID
- **AdcsObjectStore**: AD CS objects with security properties
- **DomainStore**: Domain information
- **IssueStore**: Discovered vulnerabilities by technique
- **SafePrincipals**: Acceptable high-privilege SIDs
- **DangerousPrincipals**: Risky broad-access SIDs
- **StandardOwners**: Acceptable owner SIDs for AD CS objects

#### `Set-LS2Forest`

Sets the target forest for scanning. Useful for running multiple scans or using Find-LS2Vulnerable* functions independently.

```powershell
Set-LS2Forest -Forest <String>
```

#### `Set-LS2Credential`

Sets credentials for AD queries. Useful for running multiple scans or using Find-LS2Vulnerable* functions independently.

```powershell
Set-LS2Credential -Credential <PSCredential>
```

#### `Find-LS2RiskyPrincipal`

Pivots from configuration-centric to principal-centric risk analysis. Aggregates vulnerabilities by individual principal to show which users or service accounts have the highest AD CS exposure.

```powershell
Find-LS2RiskyPrincipal [-Technique <String>] [-MinimumIssueCount <Int>] [-Top <Int>] [-Rescan]
```

Returns: PSCustomObject with Principal, IssueCount, Techniques, VulnerableObjects, Issues

#### `New-LS2Dashboard`

Generates an interactive HTML dashboard from current scan results. PSWriteHTML is included (vendored) — no separate install needed.

```powershell
New-LS2Dashboard [-FilePath <String>] [-Show] [-ExpandGroups] [-Online]
```

Returns: HTML file at the specified path. Run `Invoke-Locksmith2` or `Find-LS2Vulnerable*` first to populate the store.

## Requirements

- **PowerShell**: 5.1+
- **Permissions**: Read access to Active Directory Configuration partition
- **Network**: Connectivity to domain controller LDAP/GC ports (389, 3268)
- **Credentials**: Domain user or computer account

## Contributing

Locksmith 2 is "Open Source, acknowledged contribution", this means that any contribution will have to be discussed with the Maintainers before being submitted.

1. Open an issue and discuss your proposed change
2. Fork the repository
3. Write some code following PowerShell best practices and existing code style
4. Write clear commit messages using conventional commits
5. Submit a pull request
6. Request a review from @jakehildreth



### Acknowledgments

- **SpecterOps** for groundbreaking AD CS research ([Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2))
- Original **Locksmith** contributors and community
- **Sam Erde** (@SamErde) for significant code contributions

## Related Projects

- [Locksmith](https://github.com/jakehildreth/Locksmith) - Original AD CS audit tool
- [Certify](https://github.com/GhostPack/Certify) - C# offensive AD CS toolkit
- [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) - PowerShell PKI auditing
- [Certipy](https://github.com/ly4k/Certipy) - Python-based AD CS toolkit

## Disclaimer

Locksmith 2 is provided for legitimate security assessment and defensive purposes only. Users are responsible for obtaining proper authorization before running security audits. The authors are not responsible for misuse or damage caused by this tool.

## License

MIT License w/Commons Clause - see [LICENSE](LICENSE) file for details.

---

Made with 💜 by [Jake Hildreth](https://jakehildreth.com)
