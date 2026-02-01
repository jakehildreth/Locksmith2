# Modsmith

> A PowerShell module for managing and modifying Active Directory objects with security in mind

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)

## Overview

Modsmith is a PowerShell module designed to help Active Directory administrators manage and modify AD objects safely and efficiently. Built following PowerShell best practices and Microsoft's cmdlet development guidelines, Modsmith provides a collection of well-structured, pipeline-aware cmdlets for common AD administration tasks.

## Features

- [x] PowerShell 5.1+ and PowerShell Core support
- [x] Cross-platform compatibility (Windows, Linux, macOS where applicable)
- [x] Pipeline-aware cmdlets with proper Begin/Process/End blocks
- [x] Comprehensive comment-based help
- [x] Error handling with proper ErrorRecord objects
- [x] WhatIf and Confirm support for system-changing operations
- [ ] Comprehensive test coverage
- [ ] Extended AD object manipulation cmdlets

## Installation

### From PowerShell Gallery

```powershell
Install-Module -Name Modsmith -Scope CurrentUser -Force
```

### From Source

```powershell
git clone https://github.com/jakehildreth/Modsmith.git
cd Modsmith
Import-Module .\Modsmith.psd1
```

## Quick Start

```powershell
# Import the module
Import-Module Modsmith

# Get help for available cmdlets
Get-Command -Module Modsmith

# Get detailed help for a specific cmdlet
Get-Help Get-ModsmithObject -Full
```

## Examples

```powershell
# Example usage will be added as cmdlets are developed
```

## Requirements

- PowerShell 5.1 or higher
- Windows PowerShell or PowerShell Core

## Contributing

Contributions are welcome! Please ensure all code follows:

- PowerShell best practices
- Approved PowerShell verbs (Get-Verb)
- Comment-based help for all functions
- Proper error handling with ErrorRecord objects
- WhatIf/Confirm support for system-changing operations

## License

MIT License w/Commons Clause - see [LICENSE](LICENSE) file for details.

---

Made with 💜 by [Jake Hildreth](https://jakehildreth.com)
