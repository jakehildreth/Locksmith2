# Resolve module version at runtime

Status: closed
Labels: wayfinder:research
Assignees:

## Question

What is the most reliable way for `New-LS2Dashboard` to obtain the running Locksmith2 module version (including any prerelease tag) at runtime, and does this differ between the development directory load, the PSGallery-installed module, and the GitHub-packed zip?

## Resolution

Use the existing `Get-Module -Name Locksmith2` call in `New-LS2Dashboard` and read:

- `$module.Version` for the CalVer version string.
- `$module.PrivateData.PSData.Prerelease` for the optional prerelease tag.

This works identically across development, PSGallery, and GitHub zip deployments because all scenarios load the same manifest. See the full findings in [research/01-resolve-module-version.md](../../research/01-resolve-module-version.md).

## Comments

- 2026-08-03: Research complete. No scenario-specific logic required.
