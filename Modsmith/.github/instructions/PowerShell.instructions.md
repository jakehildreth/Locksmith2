---
applyTo: '**/*.ps1,**/*.psm1'
description: 'PowerShell cmdlet and scripting best practices based on Microsoft guidelines'
---

# PowerShell Cmdlet Development Guidelines

This guide provides PowerShell-specific instructions to help GitHub Copilot generate idiomatic,
safe, and maintainable scripts. It aligns with Microsoft's PowerShell cmdlet development guidelines.

## Naming Conventions

- **Verb-Noun Format:**
  - Use approved PowerShell verbs (Get-Verb)
  - Use singular nouns
  - PascalCase for both verb and noun
  - Avoid special characters and spaces

- **Parameter Names:**
  - Use PascalCase
  - Choose clear, descriptive names
  - Use singular form unless always multiple
  - Follow PowerShell standard names

- **Variable Names:**
  - Use PascalCase for public variables
  - Use camelCase for private variables
  - Avoid abbreviations
  - Use meaningful names

- **Alias Avoidance:**
  - Use full cmdlet names
  - Avoid using aliases in scripts (e.g., use Get-ChildItem instead of gci)
  - Document any custom aliases
  - Use full parameter names

## Parameter Design

- **Standard Parameters:**
  - Use common parameter names (`Path`, `Name`, `Force`)
  - Follow built-in cmdlet conventions
  - Document parameter purpose

- **Type Selection:**
  - Use common .NET types
  - Implement proper validation
  - Consider ValidateSet for limited options
  - Enable tab completion where possible

- **Switch Parameters:**
  - Use [switch] for boolean flags
  - Default to $false when omitted

## Pipeline and Output

- **Pipeline Input:**
  - Use `ValueFromPipeline` for direct object input
  - Use `ValueFromPipelineByPropertyName` for property mapping
  - Implement Begin/Process/End blocks for pipeline handling

- **Output Objects:**
  - Return rich objects, not formatted text
  - Use PSCustomObject for structured data
  - Avoid Write-Host for data output

- **PassThru Pattern:**
  - Default to no output for action cmdlets
  - Implement `-PassThru` switch for object return

## Error Handling and Safety

- **ShouldProcess Implementation:**
  - Use `[CmdletBinding(SupportsShouldProcess = $true)]`
  - Set appropriate `ConfirmImpact` level
  - Call `$PSCmdlet.ShouldProcess()` for system changes

- **Message Streams:**
  - `Write-Verbose` for operational details with `-Verbose`
  - `Write-Warning` for warning conditions
  - Avoid `Write-Host` except for user interface text

- **Error Handling Pattern:**
  - Use try/catch blocks for error management
  - In advanced functions with `[CmdletBinding()]`:
    - Prefer `$PSCmdlet.WriteError()` over `Write-Error`
    - Prefer `$PSCmdlet.ThrowTerminatingError()` over `throw`
    - Construct proper ErrorRecord objects

## Documentation and Style

- **Comment-Based Help:** Include for all public functions:
  - `.SYNOPSIS` Brief description
  - `.DESCRIPTION` Detailed explanation
  - `.EXAMPLE` sections with practical usage
  - `.PARAMETER` descriptions
  - `.OUTPUTS` Type of output returned
  - `.NOTES` Additional information

- **Consistent Formatting:**
  - Use proper indentation (4 spaces)
  - Opening braces on same line as statement
  - Closing braces on new line
  - PascalCase for function and parameter names

- **Avoid Aliases:** Use full cmdlet names in scripts
