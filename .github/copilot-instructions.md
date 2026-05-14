---
applyTo: '**'
---

# GitHub Copilot Instructions for Locksmith2

> **Priority order:** Code Style > TDD Workflow > Detection Pattern > Module Structure > Git Workflow

## Project Overview

**Locksmith2** is an AD CS security scanner for AD Admins, Defensive Security Professionals, and Security Researchers. It detects and remediates AD CS vulnerabilities (ESC techniques) in Active Directory environments.

Detected techniques (as of 2026.5.14): `ESC1`, `ESC2`, `ESC3c1`, `ESC3c2`, `ESC4a`, `ESC4o`, `ESC5a`, `ESC5o`, `ESC6`, `ESC7a`, `ESC7m`, `ESC8`, `ESC9`, `ESC11`, `ESC13`, `ESC15`, `ESC16`, `Auditing`, `SchemaV1`

**Compatibility:** All code must run in both PS 5.1 and PS 7.x. Never use PS 7-only syntax (`??`, `?:`, named hashtables in class properties, etc.). When in doubt, test in `powershell.exe` (5.1) first.

---

## Code Style

See [instructions/PowersHell.instructions.md](instructions/PowersHell.instructions.md) for detailed PS guidelines. Key rules:

- **Braces:** OTBS — opening brace on same line
- **Indentation:** 4 spaces
- **Casing:** PascalCase for functions/params/public vars; camelCase for private vars
- **No aliases** in scripts (`Get-ChildItem` not `gci`, `Where-Object` not `?`, etc.)
- **Quotes:** single for literals, double for string expansion
- **Continuation:** splatting over backtick
- **CmdletBinding:** `[CmdletBinding()]` on all advanced functions
- **Errors:** `$PSCmdlet.WriteError()` over `Write-Error`; `$PSCmdlet.ThrowTerminatingError()` over `throw`
- **ShouldProcess** for any function that modifies system state
- **Output:** return objects, not text; `PSCustomObject` preferred; `Write-Host` only for UI
- **Pipeline:** `ValueFromPipeline`, Begin/Process/End blocks where appropriate
- **Help:** comment-based help on all public functions — `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.OUTPUTS`, `.NOTES`
- **PS 5.1 compatibility:** no null-coalescing (`??`), no ternary (`?:`), no `[nullable]<T>` shorthand

---

## Module Structure

```
Locksmith2/
├── .github/instructions/        # Copilot instructions
├── Build/                       # Build scripts
├── Classes/                     # PS class definitions (loaded via ScriptsToProcess)
│   ├── LS2AdcsObject.ps1        # Main data class for all AD CS objects
│   ├── LS2Issue.ps1             # Issue/finding class
│   └── LS2Principal.ps1        # Principal/identity class
├── Private/
│   ├── Convert/                 # SID/NTAccount/identity conversion
│   ├── Data/                    # ESCDefinitions.ps1, DangerousAces.ps1, etc.
│   ├── Get/                     # LDAP/ADSI query functions
│   ├── Initialize/              # Store initialization (Initialize-LS2Scan, etc.)
│   ├── New/                     # Factory functions
│   ├── Set/                     # Property enrichment functions (Set-CA*, Set-Template*)
│   ├── Test/                    # Boolean test functions
│   ├── UI/                      # Display/formatting
│   └── Utility/                 # General helpers
├── Public/                      # Exported cmdlets
│   ├── Find-LS2VulnerableCA.ps1
│   ├── Find-LS2VulnerableTemplate.ps1
│   ├── Find-LS2VulnerableObject.ps1
│   ├── Find-LS2RiskyPrincipal.ps1
│   ├── Invoke-Locksmith2.ps1
│   ├── New-LS2Dashboard.ps1
│   ├── Get-LS2Stores.ps1
│   └── Set-LS2Forest.ps1
├── Tests/                       # Pester test files (mirror Private/Public structure)
├── Locksmith2.psd1
└── Locksmith2.psm1
```

**One function per file. File name must match function name exactly.**

---

## Data-Driven Detection Pattern

All ESC/technique definitions live in `Private/Data/ESCDefinitions.ps1` using a PowerShell `data {}` constrained language block.

### ESCDefinitions.ps1 structure

```powershell
$script:ESCDefinitions = data {
    @{
        ESC1 = @{
            Technique      = 'ESC1'
            Conditions     = @(
                @{ Property = 'SomeProperty'; Value = $true }
                @{ Property = 'AnotherProperty'; Value = $false }
            )
            EnrolleeProperties = @('DangerousEnrollee')  # optional
            IssueTemplate  = 'Description with $(TemplateName) or $(CAFullName) placeholders'
            FixTemplate    = 'certutil -config $(CAFullName) ...'
            RevertTemplate = 'certutil -config $(CAFullName) ...'
        }
    }
}
```

**Variable expansion in templates:** `$(PropertyName)` — expanded at issue-generation time using the object's property values.

### Adding a new technique — required changes checklist

When adding any new technique, update ALL of these:

1. **`Private/Data/ESCDefinitions.ps1`** — add the technique entry
2. **`Public/Find-LS2VulnerableTemplate.ps1`** or **`Find-LS2VulnerableCA.ps1`** — add to `[ValidateSet(...)]` and to the `$templateTechniques`/`$caTechniques` array; add a new `elseif` branch only if it needs non-standard logic (most techniques use the generic condition-based path)
3. **`Private/Initialize/Initialize-LS2Scan.ps1`** — add to `$templateTechniques` or `$caTechniques` array
4. **`Public/Invoke-Locksmith2.ps1`** — add to `$techniques` array
5. **`Tests/Private/Data/ESCDefinitions.Tests.ps1`** — add to `$RequiredTechniques`, `$TechniquesWithConditions` (if applicable), and `$AllTechniques`

### Non-standard branches

Most techniques use the generic condition-based detection path. Only add a new `elseif` branch in a Find function when:
- The technique has no `Conditions` (e.g., ESC4a, ESC5a — ACL-based)
- The issue object is built differently (e.g., SchemaV1 — no `IdentityReference`)

---

## TDD Workflow (RED-GREEN-REFACTOR)

**Tests come before implementation. Always.**

### Workflow

1. Write failing tests (RED) — confirm they fail for the right reason
2. Implement just enough to make them pass (GREEN) — confirm 0 failures
3. Refactor if needed — re-confirm GREEN

### Running Pester

**NEVER run Pester interactively** — it hangs VS Code. Always write results to a file then read them:

```powershell
# Run (in fresh process when class files changed)
powershell.exe -NoProfile -Command "& {
    Import-Module Pester -MinimumVersion 5.0 -Force
    Set-Location 'c:\...\Locksmith2'
    `$cfg = [PesterConfiguration]::Default
    `$cfg.Run.Path = 'Tests'
    `$cfg.Output.Verbosity = 'Detailed'
    `$cfg.Run.PassThru = `$true
    `$r = Invoke-Pester -Configuration `$cfg
    `$r | Export-Clixml 'Ignore\pester-out.xml' -Force
}"

# Read results
$r = Import-Clixml 'Ignore\pester-out.xml'
"Total:$($r.TotalCount) Passed:$($r.PassedCount) Failed:$($r.FailedCount)"
$r.Failed | ForEach-Object { "$($_.ExpandedName) -- $($_.ErrorRecord.Exception.Message)" }
```

**Always run in BOTH `powershell.exe` (PS 5.1) and `pwsh` (PS 7).**

### PS 5.1 class cache gotcha

After modifying any file in `Classes/`, PS 5.1 caches the old type definition. Run tests in a **fresh** `powershell.exe -NoProfile` process to pick up changes.

### Test file patterns

```
Tests/
├── Classes/           # LS2AdcsObject.Tests.ps1, etc.
├── Private/
│   ├── Data/          # ESCDefinitions.Tests.ps1
│   └── Set/           # Set-CAAuditFilter.Tests.ps1, etc.
├── Public/            # Find-LS2Vulnerable*.Tests.ps1, etc.
└── Shared/
    └── TestHelpers.psm1   # New-MockLS2AdcsObject and other helpers
```

File naming: `FunctionName.Tests.ps1`, placed next to the tested code or in `Tests/`.

Import pattern at top of each test file:
```powershell
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
}
BeforeAll {
    $ModuleRoot = Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent
    Import-Module (Join-Path $ModuleRoot 'Locksmith2.psd1') -Force -ErrorAction Stop
    Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force
}
```

### Pester conventions

- **InModuleScope 'Locksmith2'** for testing private functions and `$script:` variables
- **AAA pattern:** Arrange / Act / Assert — one assertion per `It` block when practical
- **Context blocks** for scenario grouping
- **-ForEach / -TestCases** for data-driven tests
- **External command stubs:** if mocking a command from an external module (e.g., `Get-PSCAuditFilter` from PSCertutil), define a stub in `BeforeAll` inside `InModuleScope` so Pester can intercept it:

```powershell
InModuleScope 'Locksmith2' {
    BeforeAll {
        if (-not (Get-Command Get-PSCAuditFilter -ErrorAction SilentlyContinue)) {
            function script:Get-PSCAuditFilter { param([string]$CAFullName) $null }
        }
    }
}
```

---

## Versioning

**CalVer only** — format `yyyy.M.dHHmm` (e.g., `2026.5.141345`). Never SemVer.

Update `Locksmith2.psd1` `ModuleVersion` with the CalVer timestamp on every release.

---

## Git Workflow

- **Never run `git commit` or `git push` without explicit user approval**
- After approval: commit, then push immediately, then draft a PR title + description
- Current working branch: `feat/esc13-detection`

### Conventional commits

```
type(scope): short message

- bullet 1: what changed
- bullet 2: why / what it detects
- bullet 3: files modified
- bullet 4: additional context
(max 5 bullets)
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Good examples:
```
feat(detection): add ESC15 detection for schema v1 + auth EKU open enrollment

- add ESC15 to ESCDefinitions.ps1 (schema v1 + auth EKU + no manager approval)
- add ESC15 to Find-LS2VulnerableTemplate ValidateSet and $templateTechniques
- add ESC15 to Initialize-LS2Scan and Invoke-Locksmith2 technique arrays
- uses generic enrollee-based detection path; no new Find branch required
```

```
fix(tests): add Get-PSCAuditFilter stub to isolate PSCertutil dependency

- add BeforeAll stub in Set-CAAuditFilter.Tests.ps1 inside InModuleScope
- prevents CommandNotFoundException in fresh PS process without PSCertutil loaded
- all 285 tests now pass in both PS 5.1 and PS 7
```

---

## Common Patterns

### Creating a mock LS2AdcsObject in tests

Use `New-MockLS2AdcsObject` from TestHelpers.psm1:
```powershell
$template = New-MockLS2AdcsObject -Properties @{
    objectClass            = @('top', 'pKICertificateTemplate')
    SchemaClassName        = 'pKICertificateTemplate'
    TemplateSchemaVersion  = 1
    Enabled                = $true
    AuthenticationEKUExist = $true
}
```

### Script-scoped stores

All object stores are `$script:`-scoped inside the module. Reset them in test `BeforeEach`:
```powershell
BeforeEach {
    $script:IssueStore = @{}
    $script:AdcsObjectStore = @{}
    $script:PrincipalStore = @{}
}
```

### ADSI/LDAP queries

```powershell
$rootDSE = [ADSI]'LDAP://RootDSE'
$configNC = $rootDSE.configurationNamingContext
$searcher = [System.DirectoryServices.DirectorySearcher]::new()
$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
$searcher.PageSize = 1000
```

Prefer `.NET`-native ADSI/LDAP over RSAT cmdlets. Never use `Get-WmiObject`; use `Get-CimInstance`.

---

## Resources

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Original Locksmith](https://github.com/TrimarcJake/Locksmith)
- [Gradenegger on Schema V1](https://www.gradenegger.eu/?p=2076)
- [Microsoft AD CS Docs](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/)

---

**Last Updated:** 2026.5.14
**Module Version:** 2026.5.141345 (approx)
**Maintainer:** Jake Hildreth (@jakehildreth)
