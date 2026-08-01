function Install-GitHooks {
    <#
        .SYNOPSIS
        Installs tracked git hooks into the local .git/hooks directory.

        .DESCRIPTION
        Copies hook scripts from the tracked .githooks directory into .git/hooks and
        ensures they are executable. Run this once after cloning the repository.

        .PARAMETER HookName
        Optional. The name of a specific hook to install. Defaults to installing all
        tracked hooks.

        .INPUTS
        None

        .OUTPUTS
        None

        .EXAMPLE
        .\Build\Install-GitHooks.ps1

        Installs all tracked git hooks.

        .EXAMPLE
        .\Build\Install-GitHooks.ps1 -HookName pre-commit

        Installs only the pre-commit hook.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter()]
        [string]$HookName
    )

    #requires -Version 5.1

    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $sourceDir = Join-Path $repoRoot '.githooks'
    $targetDir = Join-Path $repoRoot '.git\hooks'

    if (-not (Test-Path $sourceDir)) {
        Write-Error "Tracked hooks directory not found: $sourceDir"
        return
    }

    if (-not (Test-Path $targetDir)) {
        Write-Error "Git hooks directory not found: $targetDir"
        return
    }

    $hooks = if ($HookName) {
        $specificSource = Join-Path $sourceDir $HookName
        if (-not (Test-Path $specificSource)) {
            Write-Error "Hook not found: $specificSource"
            return
        }
        @(Get-Item -Path $specificSource)
    } else {
        Get-ChildItem -Path $sourceDir -File
    }

    foreach ($hook in $hooks) {
        $targetPath = Join-Path $targetDir $hook.Name
        if ($PSCmdlet.ShouldProcess($targetPath, 'Install git hook')) {
            Copy-Item -Path $hook.FullName -Destination $targetPath -Force
            Write-Verbose "Installed git hook: $($hook.Name)"
        }
    }
}

Install-GitHooks @args
