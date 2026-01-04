@{
    AliasesToExport      = @('*')
    Author               = 'Jake Hildreth'
    CmdletsToExport      = @()
    CompanyName          = 'Gilmour Technologies Ltd'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2025 - 2026. All rights reserved.'
    Description          = 'An AD CS toolkit for AD Admins, Defensive Security Professionals, and Filthy Red Teamers'
    FunctionsToExport    = @('*')
    GUID                 = 'e32f7d0d-2b10-4db2-b776-a193958e3d69'
    ModuleVersion        = '2026.1.1'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Archive', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security', 'PowerShellGet', 'CimCmdlets')
            ProjectUri                 = 'https://github.com/jakehildreth/Locksmith2'
            RequireLicenseAcceptance   = $false
            Tags                       = @('Locksmith', 'Locksmith2', 'ActiveDirectory', 'ADCS', 'CA', 'Certificate', 'CertificateAuthority', 'CertificateServices', 'PKI', 'X509', 'Windows')
        }
    }
    RequiredModules      = @(@{
            Guid          = '357478c8-bec5-4ee3-bc2e-21d2357b2dd1'
            ModuleName    = 'PSCertutil'
            ModuleVersion = '0.0.2'
        }, 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Archive', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security', 'PowerShellGet', 'CimCmdlets')
    RootModule           = 'Locksmith2.psm1'
    ScriptsToProcess     = @('Classes\LS2Principal.ps1', 'Classes\LS2AdcsObject.ps1')
}