function Invoke-LS2PostBuildPublish {
    <#
    .SYNOPSIS
    Vendors PSWriteHTML and PSCertutil into the unpacked artefact and optionally publishes to PSGallery.

    .DESCRIPTION
    Copies pinned versions of PSWriteHTML and PSCertutil into the Modules\ subfolder of the
    unpacked artefact, patches NestedModules in the PSD1, then — if requested — publishes
    directly from the artefact path so that the vendored dependencies are included.

    Publishing via -Path bypasses PSModulePath, ensuring what ships to PSGallery matches
    exactly what is in the artefact directory rather than whatever PSPublishModule installed
    into the local module store during the build phase.

    .PARAMETER ArtefactRoot
    Full path to the unpacked module artefact directory (contains Locksmith2.psd1).

    .PARAMETER PublishToPSGallery
    When present, publishes the module to PSGallery after vendoring.

    .PARAMETER PSGalleryAPIKey
    NuGet API key in clear text. Used when running in CI via a secret environment variable.

    .PARAMETER PSGalleryAPIPath
    Path to a file containing the NuGet API key. Used for local developer workflows.

    .EXAMPLE
    Invoke-LS2PostBuildPublish -ArtefactRoot '.\Artefacts\Unpacked\Locksmith2' -PublishToPSGallery -PSGalleryAPIKey $env:PSGALLERY_KEY

    .EXAMPLE
    Invoke-LS2PostBuildPublish -ArtefactRoot '.\Artefacts\Unpacked\Locksmith2' -PublishToPSGallery -PSGalleryAPIPath 'C:\Secrets\psgallery.txt'

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
        [string]$PSGalleryAPIPath
    )

    # ── Vendor dependencies ────────────────────────────────────────────────────
    $modulesTarget = Join-Path $ArtefactRoot 'Modules'
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
        Write-Host "Saving $depName$(if ($pinned) { " $pinned" } else { ' (latest)' }) from PSGallery..."
        Save-Module @saveParams

        $ver = (Get-ChildItem (Join-Path $modulesTarget $depName) |
            Sort-Object Name -Descending |
            Select-Object -First 1).Name
        Write-Host "Vendored $depName $ver."
        $nestedEntries += "Modules\$depName\$ver\$depName.psm1"
    }

    $psd1 = Join-Path $ArtefactRoot 'Locksmith2.psd1'
    Update-ModuleManifest -Path $psd1 -NestedModules $nestedEntries
    Write-Host "Locksmith2.psd1 patched: NestedModules = $($nestedEntries -join ', ')"

    # ── Publish from artefact path (not from PSModulePath) ────────────────────
    if (-not $PublishToPSGallery) {
        return
    }

    if ($PSGalleryAPIKey) {
        $apiKey = $PSGalleryAPIKey
    } elseif ($PSGalleryAPIPath) {
        $apiKey = Get-Content -Path $PSGalleryAPIPath -ErrorAction Stop -Encoding UTF8 |
            Select-Object -First 1
    } else {
        Write-Error '-PublishToPSGallery was specified but neither -PSGalleryAPIKey nor -PSGalleryAPIPath was provided.'
        return
    }

    if ($PSCmdlet.ShouldProcess($ArtefactRoot, 'Publish-Module to PSGallery')) {
        $publishParams = @{
            Path        = $ArtefactRoot
            NuGetApiKey = $apiKey
            Repository  = 'PSGallery'
            Force       = $true
            ErrorAction = 'Stop'
        }
        Publish-Module @publishParams
        Write-Host "Published Locksmith2 to PSGallery from $ArtefactRoot"
    }
}
