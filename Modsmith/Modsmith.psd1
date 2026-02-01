@{
    AliasesToExport      = @()
    Author               = 'Jake Hildreth'
    CmdletsToExport      = @()
    CompanyName          = 'Gilmour Technologies Ltd'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2026 Jake Hildreth, Gilmour Technologies Ltd. All rights reserved.'
    Description          = 'A PowerShell module for managing and modifying Active Directory objects with security in mind'
    FunctionsToExport    = @('*')
    GUID                 = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    ModuleVersion        = '2026.2.1'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security')
            ProjectUri                 = 'https://github.com/jakehildreth/Modsmith'
            RequireLicenseAcceptance   = $false
            Tags                       = @('Modsmith', 'ActiveDirectory', 'AD', 'Security', 'Administration', 'Windows')
        }
    }
    RequiredModules      = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security')
    RootModule           = 'Modsmith.psm1'
}
