param (
    # A CalVer string if you need to manually override the default yyyy.M.dHHmm version string.
    [string]$CalVer,
    # A prerelease tag to append to the module version (e.g., 'alpha', 'beta', 'rc1').
    [string]$Prerelease,
    [switch]$PublishToPSGallery,
    [string]$PSGalleryAPIPath,
    [string]$PSGalleryAPIKey,
    # When present, creates a GitHub release and attaches the vendored artefact as a zip asset.
    [switch]$PublishToGitHub,
    # GitHub personal access token for creating releases. Used in CI via a secret environment variable.
    [string]$GitHubAPIKey,
    # Path to a file containing the GitHub personal access token. Used for local developer workflows.
    [string]$GitHubAPIPath,
    # GitHub owner (user or organization) for release publishing. Defaults to 'jakehildreth'.
    [string]$GitHubOwner = 'jakehildreth',
    # GitHub repository name for release publishing. Defaults to 'Locksmith2'.
    [string]$GitHubRepository = 'Locksmith2'
)

# The VS Code PowerShell Extension pre-loads PSScriptAnalyzer into the host
# process. PSPublishModule imports PSScriptAnalyzer internally, and loading a
# second copy of its assembly into the same appdomain throws an assembly-already-
# loaded error. Re-invoke in a clean pwsh -NoProfile child process to avoid it.
if ($Host.Name -eq 'Visual Studio Code Host' -or
    $null -ne [System.AppDomain]::CurrentDomain.GetAssemblies().Where({
            $_.GetName().Name -eq 'Microsoft.Windows.PowerShell.ScriptAnalyzer'
        }, 'First')[0]) {
    Write-Host 'Re-invoking in a clean pwsh process to avoid PSScriptAnalyzer assembly conflict...'
    $passThrough = @('-NoProfile', '-File', $PSCommandPath)
    if ($CalVer) { $passThrough += '-CalVer'; $passThrough += $CalVer }
    if ($Prerelease) { $passThrough += '-Prerelease'; $passThrough += $Prerelease }
    if ($PublishToPSGallery) { $passThrough += '-PublishToPSGallery' }
    if ($PSGalleryAPIPath) { $passThrough += '-PSGalleryAPIPath'; $passThrough += $PSGalleryAPIPath }
    if ($PSGalleryAPIKey) { $passThrough += '-PSGalleryAPIKey'; $passThrough += $PSGalleryAPIKey }
    if ($PublishToGitHub) { $passThrough += '-PublishToGitHub' }
    if ($GitHubAPIKey) { $passThrough += '-GitHubAPIKey'; $passThrough += $GitHubAPIKey }
    if ($GitHubAPIPath) { $passThrough += '-GitHubAPIPath'; $passThrough += $GitHubAPIPath }
    if ($PSBoundParameters.ContainsKey('GitHubOwner')) { $passThrough += '-GitHubOwner'; $passThrough += $GitHubOwner }
    if ($PSBoundParameters.ContainsKey('GitHubRepository')) { $passThrough += '-GitHubRepository'; $passThrough += $GitHubRepository }
    & pwsh @passThrough
    exit $LASTEXITCODE
}

if (Get-Module -Name 'PSPublishModule' -ListAvailable) {
    Write-Verbose 'PSPublishModule is installed.'
} else {
    Write-Verbose 'PSPublishModule is not installed. Attempting installation.'
    try {
        Install-Module -Name Pester -AllowClobber -Scope CurrentUser -SkipPublisherCheck -Force
        Install-Module -Name PSScriptAnalyzer -AllowClobber -Scope CurrentUser -Force
        Install-Module -Name PSPublishModule -MaximumVersion 2.0.27 -AllowClobber -Scope CurrentUser -Force
    } catch {
        Write-Error "PSPublishModule installation failed. $_"
    }
}

# Update-Module -Name PSPublishModule
Import-Module -Name PSPublishModule -Force

# Ensure vendored dependencies are available so PSPublishModule can resolve
# function calls to their source module during analysis (required for
# New-ConfigurationModuleSkip -IgnoreModuleName to match correctly).
foreach ($depName in @('PSWriteHTML', 'PSCertutil')) {
    if (-not (Get-Module -Name $depName -ListAvailable)) {
        Write-Host "Installing $depName for build-time analysis..."
        Install-Module -Name $depName -Scope CurrentUser -Force -AllowClobber
    }
}

$CopyrightYear = if ($Calver) { $CalVer.Split('.')[0] } else { (Get-Date -Format yyyy) }

Build-Module -ModuleName 'Locksmith2' {
    # Usual defaults as per standard module
    # Always use 3-part CalVer: yyyy.M.dHHmm (e.g., 2026.4.70225)
    # Prerelease builds append -pre to the version string.
    $moduleVersion = if ($CalVer) { $CalVer } else { (Get-Date -Format 'yyyy.M.dHHmm') }
    $Manifest = [ordered] @{
        ModuleVersion        = $moduleVersion
        CompatiblePSEditions = @('Desktop', 'Core')
        GUID                 = 'e32f7d0d-2b10-4db2-b776-a193958e3d69'
        Author               = 'Jake Hildreth'
        CompanyName          = 'Gilmour Technologies Ltd'
        Copyright            = "(c) 2024 - $CopyrightYear. All rights reserved."
        Description          = 'An AD CS toolkit for AD Admins, Defensive Security Professionals, and Filthy Red Teamers'
        ProjectUri           = 'https://github.com/jakehildreth/Locksmith2'
        PowerShellVersion    = '5.1'
        Tags                 = @('Locksmith', 'Locksmith2', 'ActiveDirectory', 'ADCS', 'CA', 'Certificate', 'CertificateAuthority', 'CertificateServices', 'PKI', 'X509', 'Windows')
    }
    if ($Prerelease) {
        $Manifest['Prerelease'] = $Prerelease
    }
    New-ConfigurationManifest @Manifest

    New-ConfigurationModule -Type ExternalModule -Name @(
        'Microsoft.PowerShell.Utility',
        'Microsoft.PowerShell.Archive',
        'Microsoft.PowerShell.Management',
        'Microsoft.PowerShell.Security',
        'PowerShellGet'
    )
    # CimCmdlets is intentionally omitted from ExternalModule. It is Windows-only and
    # auto-loads on Windows when Get-CimInstance is called. Listing it here breaks the
    # build on macOS/Linux where the module does not exist.

    # Add approved modules, that can be used as a dependency, but only when specific function from those modules is used
    # And on that time only that function and dependant functions will be copied over
    # Keep in mind it has it's limits when "copying" functions such as it should not depend on DLLs or other external files
    #New-ConfigurationModule -Type ApprovedModule -Name 'PSSharedGoods', 'PSWriteColor', 'Connectimo', 'PSUnifi', 'PSWebToolbox', 'PSMyPassword'

    # New-ConfigurationModule -Type ApprovedModule -Name @(
    #     'PSWriteHTML', 'PSCertutil'
    # )

    #New-ConfigurationModuleSkip -IgnoreFunctionName 'Invoke-Formatter', 'Find-Module' -IgnoreModuleName 'platyPS'

    # New-ConfigurationModuleSkip -IgnoreFunctionName @(
    #     'Format-HTML',                
    #     'Optimize-HTML',              
    #     'Compare-TwoArrays',          
    #     'IsNumeric',                  
    #     'IsOfType',                   
    #     'Select-Unique'
    # ) 

    New-ConfigurationModuleSkip -IgnoreModuleName 'PSWriteHtml', 'PSCertutil' -IgnoreFunctionName 'Get-CimInstance'

    $ConfigurationFormat = [ordered] @{
        RemoveComments                              = $false

        PlaceOpenBraceEnable                        = $true
        PlaceOpenBraceOnSameLine                    = $true
        PlaceOpenBraceNewLineAfter                  = $true
        PlaceOpenBraceIgnoreOneLineBlock            = $false

        PlaceCloseBraceEnable                       = $true
        PlaceCloseBraceNewLineAfter                 = $true
        PlaceCloseBraceIgnoreOneLineBlock           = $false
        PlaceCloseBraceNoEmptyLineBefore            = $true

        UseConsistentIndentationEnable              = $true
        UseConsistentIndentationKind                = 'space'
        UseConsistentIndentationPipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
        UseConsistentIndentationIndentationSize     = 4

        UseConsistentWhitespaceEnable               = $true
        UseConsistentWhitespaceCheckInnerBrace      = $true
        UseConsistentWhitespaceCheckOpenBrace       = $true
        UseConsistentWhitespaceCheckOpenParen       = $true
        UseConsistentWhitespaceCheckOperator        = $true
        UseConsistentWhitespaceCheckPipe            = $true
        UseConsistentWhitespaceCheckSeparator       = $true

        AlignAssignmentStatementEnable              = $true
        AlignAssignmentStatementCheckHashtable      = $true

        UseCorrectCasingEnable                      = $true
    }
    # format PSM1 files when merging into a single file
    # enable formatting is not required as Configuration is provided
    # New-ConfigurationFormat -ApplyTo 'OnMergePSM1' -Sort None @ConfigurationFormat
    # format PSM1 files within the module
    # enable formatting is required to make sure that formatting is applied (with default settings)
    New-ConfigurationFormat -ApplyTo 'DefaultPSM1' -EnableFormatting -Sort None
    # when creating PSD1 use special style without comments and with only required parameters
    # DefaultPSD1 is intentionally excluded: PSPublishModule rewrites the source PSD1 during the
    # build and produces mixed CRLF/LF endings, which causes PSScriptAnalyzer to throw.
    New-ConfigurationFormat -ApplyTo 'OnMergePSD1' -PSD1Style 'Minimal'

    # configuration for documentation, at the same time it enables documentation processing
    New-ConfigurationDocumentation -Enable:$false -StartClean -UpdateWhenNew -PathReadme 'Docs\Readme.md' -Path 'Docs'
    New-ConfigurationImportModule -ImportSelf -ImportRequiredModules

    New-ConfigurationBuild -Enable:$true -SignModule:$false -DeleteTargetModuleBeforeBuild -MergeModuleOnBuild -MergeFunctionsFromApprovedModules -DoNotAttemptToFixRelativePaths -UseWildcardForFunctions

    New-ConfigurationArtefact -Type Unpacked -Enable -Path "$PSScriptRoot\..\Artefacts\Unpacked" #-RequiredModulesPath "$PSScriptRoot\..\Artefacts\Modules"
}

# NOTE: Publishing is intentionally NOT configured inside Build-Module {}.
# PSPublishModule's Publish-Module call uses -Name (resolves from PSModulePath),
# which publishes the pre-vendoring copy of the module and excludes PSWriteHTML
# and PSCertutil. We publish via -Path after vendoring instead (see below).

# ── Post-build: vendor deps and optionally publish from artefact path ─────────
# Vendoring and publishing are deliberately deferred until after Build-Module {}
# so that Publish-Module -Path sees the fully patched artefact directory.
. "$PSScriptRoot\Invoke-LS2PostBuildPublish.ps1"

$postBuildParams = @{
    ArtefactRoot       = Join-Path $PSScriptRoot '..\Artefacts\Unpacked\Locksmith2'
    PublishToPSGallery = $PublishToPSGallery
    PublishToGitHub    = $PublishToGitHub
}
if ($PSGalleryAPIKey) { $postBuildParams['PSGalleryAPIKey'] = $PSGalleryAPIKey }
if ($PSGalleryAPIPath) { $postBuildParams['PSGalleryAPIPath'] = $PSGalleryAPIPath }
if ($GitHubAPIKey) { $postBuildParams['GitHubAPIKey'] = $GitHubAPIKey }
if ($GitHubAPIPath) { $postBuildParams['GitHubAPIPath'] = $GitHubAPIPath }
if ($PSBoundParameters.ContainsKey('GitHubOwner')) { $postBuildParams['GitHubOwner'] = $GitHubOwner }
if ($PSBoundParameters.ContainsKey('GitHubRepository')) { $postBuildParams['GitHubRepository'] = $GitHubRepository }
if ($Prerelease) { $postBuildParams['Prerelease'] = $Prerelease }

Invoke-LS2PostBuildPublish @postBuildParams
