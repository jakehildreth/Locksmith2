@{
    AliasesToExport      = @('*')
    Author               = 'Jake Hildreth'
    CmdletsToExport      = @()
    CompanyName          = 'Gilmour Technologies Ltd'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2025 - 2025. All rights reserved.'
    Description          = 'An AD CS toolkit for AD Admins, Defensive Security Professionals, and Filthy Red Teamers'
    FunctionsToExport    = @('*')
    GUID                 = 'e32f7d0d-2b10-4db2-b776-a193958e3d69'
    ModuleVersion        = '2025.11.23.0549'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ExternalModuleDependencies = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Archive', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security', 'PowerShellGet', 'CimCmdlets')
            ProjectUri                 = 'https://github.com/jakehildreth/Locksmith2'
            RequireLicenseAcceptance   = $false
            Tags                       = @('Locksmith', 'Locksmith2', 'ActiveDirectory', 'ADCS', 'CA', 'Certificate', 'CertificateAuthority', 'CertificateServices', 'PKI', 'X509', 'Windows')
        }
    }
    RequiredModules      = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Archive', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security', 'PowerShellGet', 'CimCmdlets')
    RootModule           = 'Locksmith2.psm1'
}