![The Locksmith 2 logo features the word "locksmith" followed by the number "2" in a bold, blocky pixelated font. The design uses a gradient color scheme transitioning from light lavender on the left through pink tones to coral/orange on the right, set against a dark purple background with a rectangular border. The retro-digital aesthetic gives the logo a modern yet approachable feel, suggesting a tool that makes security management accessible and straightforward. The "2" indicates this is the second version of the Locksmith tool.](Images/Locksmith2.png)
# Locksmith 2

> Find and fix Active Directory Certificate Services (AD CS) security misconfigurations

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/Locksmith2.svg)](https://www.powershellgallery.com/packages/Locksmith2)
[![License](https://img.shields.io/github/license/jakehildreth/Locksmith2)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)

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

- [x] Scan certificate templates (ESC1, ESC2, ESC3, ESC4, ESC9)
- [x] Audit certification authorities (ESC6, ESC7, ESC11, ESC16)
- [x] Check PKI infrastructure objects (ESC5)
- [x] Generate PowerShell remediation scripts
- [x] Support for non-domain-joined systems
- [x] Caching for improved performance
- [x] Object output
- [ ] HTML/CSV/PDF/Excel output
- [ ] Interactive TUI for guided remediation

## Installation

### From PowerShell Gallery (Not yet!)

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

# Inspect results
$stores = Get-LS2Stores
$stores.IssueStore['ESC1']
```

## Supported ESC Techniques

| Technique | Description | Target Objects |
|-----------|-------------|----------------|
| **ESC1** | Misconfigured Certificate Templates | Templates |
| **ESC2** | Certificate SubCA Abuse | Templates |
| **ESC3** | Enrollment Agent Restrictions | Templates |
| **ESC4** | Vulnerable Access Control | Templates |
| **ESC5** | Vulnerable PKI Object Access Control | Infrastructure Objects |
| **ESC6** | EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled | CAs |
| **ESC7** | Vulnerable CA Administrator/Manager Roles | CAs |
| **ESC9** | Weak Certificate Mappings | Templates |
| **ESC11** | Missing RPC Encryption | CAs |
| **ESC16** | Disabled CRL/AIA Security Extensions | CAs |

For detailed information on ESC techniques, see [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) by SpecterOps.

## cmdlet Reference

### Primary Functions

#### `Invoke-Locksmith2`

Performs comprehensive AD CS security audit scanning for all known ESC vulnerabilities.

```powershell
Invoke-Locksmith2 [-Forest <String>] [-Credential <PSCredential>] 
                  [-SkipVersionCheck] [-SkipPowerShellCheck] [-SkipForestCheck]
```

#### `Find-LS2VulnerableTemplate`

Scans certificate templates for specific ESC vulnerabilities.

```powershell
Find-LS2VulnerableTemplate -Technique <String>
# Supported: ESC1, ESC2, ESC3c1, ESC3c2, ESC4a, ESC4o, ESC9
```

Returns: LS2Issue objects for programmatic use

#### `Find-LS2VulnerableCA`

Scans certification authorities for configuration issues and dangerous role assignments.

```powershell
Find-LS2VulnerableCA -Technique <String>
# Supported: ESC6, ESC7, ESC11, ESC16
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
Get-LS2Stores
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

## Requirements

- **PowerShell**: 5.1 or higher (Windows PowerShell)
- **Permissions**: Read access to Active Directory Configuration partition
- **Network**: Connectivity to domain controller LDAP/GC ports (389, 3268)
- **Credentials**: Domain user or computer account

## Contributing

Locksmith 2 is "Open Source, acknowledged contribution", this means that any contribution will have to be discussed with the Maintainers before being submitted.

1. Open an issue and discuss your proposed change.
2. Fork the repository
4. Write some code following PowerShell best practices and existing code style
5. Write clear commit messages using conventional commits
6. Submit a pull request
7. Request a review from @jakehildreth

## Credits

**Author**: Jake Hildreth ([@jakehildreth](https://github.com/jakehildreth))  
**Website**: [locksmith.ad](https://locksmith.ad) | [jakehildreth.com](https://jakehildreth.com)  
**License**: MIT

### Acknowledgments

- **SpecterOps** for groundbreaking AD CS research ([Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2))
- **Will Schroeder** and **Lee Christensen** for ESC technique taxonomy
- Original **Locksmith** contributors and community
- **Sam Erde** for significant code contributions

## Related Projects

- [Locksmith](https://github.com/TrimarcJake/Locksmith) - Original AD CS audit tool
- [Certify](https://github.com/GhostPack/Certify) - C# offensive AD CS toolkit
- [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) - PowerShell PKI auditing
- [Certipy](https://github.com/ly4k/Certipy) - Python-based AD CS toolkit

## Disclaimer

Locksmith 2 is provided for legitimate security assessment and defensive purposes only. Users are responsible for obtaining proper authorization before running security audits. The authors are not responsible for misuse or damage caused by this tool.

## Support

- **Issues**: [GitHub Issues](https://github.com/jakehildreth/Locksmith2/issues)
- **Social**: [@horse@infosec.exchange](https://infosec.exchange/@horse) (Mastodon)
- **Support**: [Ko-fi](https://ko-fi.com/jakehildreth)

## License

MIT License - see [LICENSE](License) file for details.

---

**Made with ❤️ by [Jake Hildreth](https://jakehildreth.com)**  
*Making identity security suck a little less*
