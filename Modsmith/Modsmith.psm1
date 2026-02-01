#Requires -Version 5.1

<#
.SYNOPSIS
    Modsmith PowerShell Module

.DESCRIPTION
    A PowerShell module for managing and modifying Active Directory objects with security in mind.
    Provides cmdlets for common AD administration tasks following PowerShell best practices.

.NOTES
    Author: Jake Hildreth
    Company: Gilmour Technologies Ltd
    Version: 2026.2.1
#>

# Get public and private function definition files
$publicFunctions = @(Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue)
$privateFunctions = @(Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue)

# Dot source the files
foreach ($import in @($publicFunctions + $privateFunctions)) {
    try {
        . $import.FullName
        Write-Verbose "Imported function from $($import.FullName)"
    } catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $publicFunctions.BaseName

Write-Verbose "Modsmith module loaded successfully"
