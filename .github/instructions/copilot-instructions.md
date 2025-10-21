# GitHub Copilot Instructions for Locksmith2

## Project Overview

**Locksmith 2** is an Active Directory Certificate Services (AD CS) security toolkit designed for AD Admins, Defensive Security Professionals, and Security Researchers. It's the next generation of the Locksmith PowerShell module, focused on detecting and remediating AD CS security vulnerabilities.

### Key Goals
- Detect AD CS security vulnerabilities (ESC1-8, 11, 13, 15, 16, and more)
- Provide automated and guided remediation with revert capabilities
- Offer risk ratings and contextual guidance for decision-making
- Support both interactive TUI and headless automation modes
- Maintain compatibility with PowerShell 5.1 and 7.4+

## Development Standards

### Language & Version
- **Primary Language:** PowerShell
- **Target Version:** PowerShell 7.4 LTS (minimum 5.1 for headless mode)
- **Compatible Editions:** Desktop and Core

### Code Style

#### PowerShell Best Practices
- Use approved verbs (Get, Set, New, Remove, Find, Invoke, etc.)
- Follow verb-noun naming: `Verb-LS2Noun` (e.g., `Find-LS2VulnerableTemplate`)
- Use PascalCase for function names, parameters, and variables
- Always include comment-based help with `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, and `.OUTPUTS`
- Use `[CmdletBinding()]` for advanced functions
- Use proper parameter attributes: `[Parameter()]`, type constraints, validation attributes
- Support pipeline input where appropriate
- Use `Write-Verbose` for diagnostic messages
- In advanced functions with `[CmdletBinding()]`, prefer `$PSCmdlet.WriteError()` over `Write-Error` for non-terminating errors
- In advanced functions with `[CmdletBinding()]`, prefer `$PSCmdlet.ThrowTerminatingError()` over `throw` for terminating errors
- Always use `#requires` statements for module/version dependencies

**Note:** See `PowerShell.copilot-instructions.md` for detailed PowerShell-specific guidelines and patterns.

#### Error Handling
- Implement excellent error handling - never show "Not applicable" or "Not available"
- Provide meaningful error messages with context
- Include suggested solutions in error messages
- Use try/catch blocks appropriately
- Fail gracefully with informative messages

#### Comments & Documentation
- Add inline comments for complex logic
- Document WHY, not WHAT (code should be self-documenting)
- Include examples in comment-based help
- Link to relevant Microsoft docs or security advisories where applicable

### Module Structure

```
Locksmith2/
├── .github/
│   └── instructions/
├── Build/
│   └── Build-Module.ps1
├── Private/           # Internal functions not exported
├── Public/            # Exported functions
├── Locksmith2.psd1    # Module manifest
├── Locksmith2.psm1    # Root module
├── README.MD
├── CHANGELOG.MD
├── License
└── Tasks.md
```

### Function Organization
- **Public/** - Functions exported to users (cmdlets)
- **Private/** - Internal helper functions (not exported)
- All functions should be in separate `.ps1` files
- File names must match function names exactly

### Dependencies

#### Core PowerShell Modules (Required)
- Microsoft.PowerShell.Utility
- Microsoft.PowerShell.Archive
- Microsoft.PowerShell.Management
- Microsoft.PowerShell.Security
- PowerShellGet
- CimCmdlets

#### Third-Party Modules (Bundle with distribution)
- PSSQLite
- PwshSpectreConsole (for TUI)
- PSWriteHTML (for HTML output)
- PSCertutil

**IMPORTANT:** All third-party modules must be includable in distribution (check licenses).

### Cmdlet Naming Convention

All public cmdlets should follow this pattern:
- Prefix: Use standard PowerShell verb
- Noun: Use `LS2` + descriptive noun
- Examples:
  - `Find-LS2VulnerableTemplate`
  - `Find-LS2VulnerableObject`
  - `Find-LS2VulnerableCA`
  - `Invoke-LS2` (main entry point)

### Detection & Remediation Patterns

#### Detection Functions
```powershell
function Find-LS2Something {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Server
    )
    
    # 1. Validate prerequisites
    # 2. Retrieve data from AD/ADCS
    # 3. Analyze for vulnerabilities
    # 4. Calculate risk rating
    # 5. Return structured objects with:
    #    - Title
    #    - Description
    #    - Risk rating
    #    - Affected objects
    #    - Remediation guidance
}
```

#### Remediation Functions
```powershell
function Repair-LS2Something {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Issue,
        
        [Parameter()]
        [switch]$WhatIf
    )
    
    # 1. Validate fix is applicable
    # 2. Show operational impact analysis
    # 3. Provide multiple remediation options with risk
    # 4. Prompt for confirmation (if not -Force)
    # 5. Apply fix
    # 6. Create revert code/instructions
    # 7. Return result object
}
```

### Output Objects

All detection functions should return consistent objects:
```powershell
[PSCustomObject]@{
    IssueType = 'ESC1'
    Title = 'Template allows SAN specification'
    Description = 'Detailed description...'
    RiskRating = 'Critical'
    RiskScore = 95
    RiskCalculation = @{...}
    AffectedObject = 'CN=Template,CN=...'
    RemediationOptions = @(...)
    EducationalLinks = @(...)
}
```

### Testing

#### Unit Tests
- Write unit tests for all public and complex private functions
- Use Pester for testing framework
- Mock external dependencies (AD, ADCS)
- Test edge cases and error conditions
- Target >80% code coverage

#### Integration Tests
- Test against lab environments
- Test multi-domain and multi-forest scenarios
- Test with various Windows Server versions
- Validate both PowerShell 5.1 and 7.4

### Security Considerations

- **Never implement automatic attacks** - This is a defensive tool only
- Validate all user input
- Use `-WhatIf` and `-Confirm` for destructive operations
- Log all remediation actions
- Securely handle credentials when needed
- Follow principle of least privilege

### Performance

- Use efficient .NET-native AD/LDAP queries. Do not use RSAT functionality.
- Implement pagination for large result sets (PageSize = 1000)
- Cache configuration data when appropriate
- Avoid unnecessary object conversions
- Use `Where-Object` and `Select-Object` efficiently

### Git Workflow

- Commit messages should be clear and descriptive
- Use conventional commits format: `type(scope): message`
  - Types: feat, fix, docs, style, refactor, test, chore
  - Example: `feat(detection): add ESC13 detection`
- Keep commits atomic and focused
- Update CHANGELOG.MD for user-facing changes

### Compatibility Notes

#### PowerShell 5.1 vs 7.4
- Test null coalescing operators (5.1 doesn't support)
- Test ternary operators (5.1 doesn't support)
- Use compatible string interpolation
- Headless mode must work in 5.1 without third-party modules

#### Cross-Platform
- Use platform-agnostic paths when possible
- Prefer `Get-CimInstance` over `Get-WmiObject`
- Avoid Windows-specific commands in cross-platform code

## Current Development Priorities

See `Tasks.md` for the complete prioritized task list. Current focus areas:

1. **Phase 1: Foundation & Core Value**
   - Module infrastructure
   - Core ESC detections
   - Output formats and risk ratings

2. **Phase 2: Remediation & Usability**
   - Remediation system
   - Interactive health checks
   - Configuration management

## Resources

- [AD CS Security Advisories](https://github.com/GhostPack/Certify)
- [Original Locksmith](https://github.com/TrimarcJake/Locksmith)
- [ESC Vulnerability Reference](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Microsoft AD CS Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/)

## Questions or Clarifications

When implementing features:
1. Check the PRD (`/product/Product Requirements/Locksmith 2/PRD.md`) for requirements
2. Refer to `Tasks.md` for priorities
3. Follow existing patterns in the codebase
4. Ask for clarification if requirements are ambiguous

## Common Patterns to Follow

### ADSI/LDAP Queries
```powershell
# Use existing Get-AdcsObjects pattern
$rootDSE = [ADSI]"LDAP://RootDSE"
$configNC = $rootDSE.configurationNamingContext
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
$searcher.PageSize = 1000
```

### CIM Queries
```powershell
# Prefer Get-CimInstance over WMIC or Get-WmiObject
Get-CimInstance -ClassName SoftwareLicensingService | 
    Select-Object -Property PropertyName
```

### Verbose Output
```powershell
Write-Verbose "Processing: $objectName"
Write-Verbose "Found $count items"
```

### Progressive Operations
```powershell
Write-Progress -Activity "Scanning templates" -Status "$current of $total" -PercentComplete $percent
```

---

**Last Updated:** October 21, 2025
**Module Version:** 2025.10.19
**Maintainer:** Jake Hildreth (@jakehildreth)
