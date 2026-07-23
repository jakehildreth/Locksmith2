function Invoke-LS2PostBuildPublish {
    <#
    .SYNOPSIS
    Vendors PSWriteHTML and PSCertutil into the unpacked artefact and optionally publishes to PSGallery and GitHub.

    .DESCRIPTION
    Copies pinned versions of PSWriteHTML and PSCertutil into the Modules\ subfolder of the
    unpacked artefact, patches NestedModules in the PSD1, then — if requested — publishes
    directly from the artefact path so that the vendored dependencies are included.

    Publishing via -Path bypasses PSModulePath, ensuring what ships to PSGallery matches
    exactly what is in the artefact directory rather than whatever PSPublishModule installed
    into the local module store during the build phase.

    When a GitHub token is supplied and publishing is enabled, the vendored unpacked artefact
    is compressed into a zip and attached to a GitHub release. This ensures the GitHub release
    asset contains the same vendored dependencies as the PSGallery publish.

    .PARAMETER ArtefactRoot
    Full path to the unpacked module artefact directory (contains Locksmith2.psd1).

    .PARAMETER PublishToPSGallery
    When present, publishes the module to PSGallery after vendoring.

    .PARAMETER PSGalleryAPIKey
    NuGet API key in clear text. Used when running in CI via a secret environment variable.

    .PARAMETER PSGalleryAPIPath
    Path to a file containing the NuGet API key. Used for local developer workflows.

    .PARAMETER PublishToGitHub
    When present, creates a GitHub release and attaches the vendored artefact as a zip asset.

    .PARAMETER GitHubAPIKey
    GitHub personal access token in clear text. Used when running in CI via a secret environment variable.

    .PARAMETER GitHubAPIPath
    Path to a file containing the GitHub personal access token. Used for local developer workflows.

    .PARAMETER GitHubOwner
    GitHub owner (user or organization) for release publishing. Defaults to 'jakehildreth'.

    .PARAMETER GitHubRepository
    GitHub repository name for release publishing. Defaults to 'Locksmith2'.

    .PARAMETER Prerelease
    Prerelease tag appended to the module version. When present, the GitHub release is marked as a prerelease.

    .PARAMETER GitHubSha
    Commit SHA to use as the GitHub release target_commitish. Defaults to `$env:GITHUB_SHA`. GitHub releases are only allowed when this value is provided.

    .EXAMPLE
    Invoke-LS2PostBuildPublish -ArtefactRoot '.\Artefacts\Unpacked\Locksmith2' -PublishToPSGallery -PSGalleryAPIKey $env:PSGALLERY_KEY -GitHubAPIKey $env:GITHUB_TOKEN

    .EXAMPLE
    Invoke-LS2PostBuildPublish -ArtefactRoot '.\Artefacts\Unpacked\Locksmith2' -PublishToPSGallery -PSGalleryAPIPath 'C:\Secrets\psgallery.txt' -GitHubAPIPath 'C:\Secrets\github.txt'

    .OUTPUTS
    None. Writes host/verbose messages only.

    .NOTES
    Pinned vendor versions are defined inside this function. Bump them here when updating deps.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ArtefactRoot,

        [Parameter()]
        [switch]$PublishToPSGallery,

        [Parameter()]
        [string]$PSGalleryAPIKey,

        [Parameter()]
        [string]$PSGalleryAPIPath,

        [Parameter()]
        [switch]$PublishToGitHub,

        [Parameter()]
        [string]$GitHubAPIKey,

        [Parameter()]
        [string]$GitHubAPIPath,

        [Parameter()]
        [string]$GitHubOwner = 'jakehildreth',

        [Parameter()]
        [string]$GitHubRepository = 'Locksmith2',

        [Parameter()]
        [string]$Prerelease,

        [Parameter()]
        [string]$GitHubSha = $env:GITHUB_SHA
    )

    # ── Resolve actual module root (PSPublishModule may nest it) ───────────────
    $resolvedPsd1 = Get-ChildItem -Path $ArtefactRoot -Filter 'Locksmith2.psd1' -Recurse -File |
        Sort-Object FullName |
        Select-Object -First 1
    if (-not $resolvedPsd1) {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new("Could not find Locksmith2.psd1 under $ArtefactRoot"),
            'ManifestNotFound',
            [System.Management.Automation.ErrorCategory]::ObjectNotFound,
            $ArtefactRoot
        )
        $PSCmdlet.WriteError($errorRecord)
        return
    }
    $moduleRoot = $resolvedPsd1.Directory.FullName

    # ── Vendor dependencies ────────────────────────────────────────────────────
    if (-not $PSCmdlet.ShouldProcess($moduleRoot, 'Vendor dependencies into artefact')) {
        return
    }

    Write-Host ''
    Write-Host '[i] Vendoring dependencies into artefact' -ForegroundColor Cyan

    $modulesTarget = Join-Path $moduleRoot 'Modules'
    New-Item -ItemType Directory -Path $modulesTarget -Force | Out-Null

    $vendorVersions = [ordered] @{
        PSWriteHTML = '1.41.0'
        PSCertutil  = '0.0.3'
    }

    $nestedEntries = @()
    foreach ($depName in $vendorVersions.Keys) {
        $pinned = $vendorVersions[$depName]
        $saveParams = @{
            Name  = $depName
            Path  = $modulesTarget
            Force = $true
        }
        if ($pinned) { $saveParams['RequiredVersion'] = $pinned }
        $versionLabel = if ($pinned) { " $pinned" } else { ' (latest)' }
        Write-Host "   [>] Saving $depName$versionLabel from PSGallery..." -ForegroundColor Yellow
        Save-Module @saveParams

        $ver = (Get-ChildItem (Join-Path $modulesTarget $depName) |
            Sort-Object Name -Descending |
            Select-Object -First 1).Name
        Write-Host "   [+] Vendored $depName $ver" -ForegroundColor Green
        $nestedEntries += "Modules\$depName\$ver\$depName.psm1"
    }

    $psd1 = $resolvedPsd1.FullName
    Update-ModuleManifest -Path $psd1 -NestedModules $nestedEntries
    Write-Host "[+] Locksmith2.psd1 patched - NestedModules = $($nestedEntries -join ', ')" -ForegroundColor Green

    # ── Publish from artefact path (not from PSModulePath) ────────────────────
    # region PSGallery
    if ($PublishToPSGallery) {
        Write-Host ''
        Write-Host '[i] Publishing to PSGallery' -ForegroundColor Cyan

        if ($PSGalleryAPIKey) {
            $apiKey = $PSGalleryAPIKey
        } elseif ($PSGalleryAPIPath) {
            $apiKey = Get-Content -Path $PSGalleryAPIPath -ErrorAction Stop -Encoding UTF8 |
                Select-Object -First 1
        } else {
            Write-Host '[x] -PublishToPSGallery specified but neither -PSGalleryAPIKey nor -PSGalleryAPIPath was provided.' -ForegroundColor Red
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('-PublishToPSGallery was specified but neither -PSGalleryAPIKey nor -PSGalleryAPIPath was provided.'),
                'MissingPSGalleryCredential',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $PSCmdlet.MyInvocation
            )
            $PSCmdlet.WriteError($errorRecord)
        }

        if ($apiKey -and $PSCmdlet.ShouldProcess($moduleRoot, 'Publish-Module to PSGallery')) {
            Write-Host "   [>] Calling Publish-Module -Path $moduleRoot" -ForegroundColor Yellow
            $publishParams = @{
                Path        = $moduleRoot
                NuGetApiKey = $apiKey
                Repository  = 'PSGallery'
                Force       = $true
                ErrorAction = 'Stop'
            }
            Publish-Module @publishParams
            Write-Host '[+] Published Locksmith2 to PSGallery successfully' -ForegroundColor Green
        }
    }

    # region GitHub Release
    if (-not $PublishToGitHub) {
        return
    }

    if (-not ($GitHubAPIKey -or $GitHubAPIPath)) {
        Write-Host '[x] -PublishToGitHub specified but neither -GitHubAPIKey nor -GitHubAPIPath was provided.' -ForegroundColor Red
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new('-PublishToGitHub was specified but neither -GitHubAPIKey nor -GitHubAPIPath was provided.'),
            'MissingGitHubCredential',
            [System.Management.Automation.ErrorCategory]::InvalidArgument,
            $PSCmdlet.MyInvocation
        )
        $PSCmdlet.WriteError($errorRecord)
        return
    }

    if ([string]::IsNullOrEmpty($GitHubSha)) {
        Write-Host '[x] -PublishToGitHub was specified but -GitHubSha was not provided and $env:GITHUB_SHA is not set. GitHub releases must be created from GitHub Actions.' -ForegroundColor Red
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.Exception]::new('-PublishToGitHub was specified but -GitHubSha was not provided and $env:GITHUB_SHA is not set. GitHub releases must be created from GitHub Actions.'),
            'MissingGitHubSha',
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $PSCmdlet.MyInvocation
        )
        $PSCmdlet.WriteError($errorRecord)
        return
    }

    Write-Host ''
    Write-Host '[i] Creating GitHub release' -ForegroundColor Cyan

    if ($GitHubAPIKey) {
        $gitHubToken = $GitHubAPIKey
    } else {
        $gitHubToken = Get-Content -Path $GitHubAPIPath -ErrorAction Stop -Encoding UTF8 |
            Select-Object -First 1
    }

    $moduleVersion = (Import-PowerShellDataFile -Path $psd1).ModuleVersion
    $releaseTag = if ($Prerelease) { "$moduleVersion-$Prerelease" } else { $moduleVersion }
    $releaseName = "Locksmith2 $releaseTag"
    $zipName = "Locksmith2-$releaseTag.zip"
    $zipPath = Join-Path (Split-Path $moduleRoot -Parent) $zipName
    $releaseUri = "https://api.github.com/repos/$GitHubOwner/$GitHubRepository/releases"

    if (-not $PSCmdlet.ShouldProcess($releaseUri, 'Create GitHub release')) {
        return
    }

    if (Test-Path $zipPath) {
        Remove-Item -Path $zipPath -Force
    }

    $stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
    $stagingPath = Join-Path $stagingRoot 'Locksmith2'
    New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
    Get-ChildItem -Path $moduleRoot | Copy-Item -Destination $stagingPath -Recurse -Force

    Write-Host "   [>] Compressing vendored artefact to $zipName" -ForegroundColor Yellow
    Compress-Archive -Path $stagingPath -DestinationPath $zipPath -Force
    Write-Host "   [+] Release zip created at $zipPath" -ForegroundColor Green

    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue

    $releaseBody = "Locksmith2 release $releaseTag"
    $releaseData = @{
        tag_name               = $releaseTag
        target_commitish       = $GitHubSha
        name                   = $releaseName
        body                   = $releaseBody
        draft                  = $false
        prerelease             = [bool]$Prerelease
        generate_release_notes = $true
    } | ConvertTo-Json

    $headers = @{
        Authorization          = "Bearer $gitHubToken"
        Accept                 = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
    }

    Write-Host "   [>] Creating GitHub release $releaseTag" -ForegroundColor Yellow
    try {
        $release = Invoke-RestMethod -Uri $releaseUri -Method Post -Headers $headers -Body $releaseData -ContentType 'application/json'
        Write-Host "   [+] GitHub release created" -ForegroundColor Green

        $uploadUri = $release.upload_url -replace '{\?name,[^}]*}', "?name=$zipName"
        Write-Host "   [>] Uploading $zipName to GitHub release" -ForegroundColor Yellow
        Invoke-RestMethod -Uri $uploadUri -Method Post -Headers $headers -InFile $zipPath -ContentType 'application/zip' | Out-Null
        Write-Host "   [+] Uploaded $zipName to GitHub release" -ForegroundColor Green
    } catch {
        Write-Host "   [x] GitHub release creation failed: $_" -ForegroundColor Red
        $PSCmdlet.WriteError($_)
    }
}
# endregion
