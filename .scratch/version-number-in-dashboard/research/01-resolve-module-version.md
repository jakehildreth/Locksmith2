# Runtime Module Version Resolution for New-LS2Dashboard

**Ticket:** [Resolve module version at runtime](../issues/01-resolve-module-version.md)  
**Status:** Research Complete  
**Date:** 2026-08-03

## Summary

The most reliable way to obtain the running Locksmith2 module version at runtime is via the `Get-Module` cmdlet, retrieving both `Version` and `PrivateData.PSData.Prerelease`. This works identically for development directory loads, PSGallery-installed modules, and GitHub-packed zips — no scenario-specific logic is required.

## Findings

### Manifest structure

Source: `Locksmith2.psd1`

- `ModuleVersion` is always present (CalVer: `yyyy.M.dHHmm`).
- `PrivateData.PSData.Prerelease` is optional and only set during build when `-Prerelease` is passed to `Build-Module.ps1`.

### Current New-LS2Dashboard usage

Source: `Public/New-LS2Dashboard.ps1` (line 171)

`New-LS2Dashboard` already calls `Get-Module -Name Locksmith2` to locate the logo image. The same call can provide the version.

Accessible properties on the returned `PSModuleInfo` object:

- `$module.Version` — `System.Version` object, always available.
- `$module.PrivateData.PSData.Prerelease` — prerelease tag, works in PS 5.1 and PS 7.x.

### Recommended pattern

```powershell
$module = Get-Module -Name Locksmith2 -ErrorAction SilentlyContinue
if ($null -eq $module) {
    $versionString = 'Version unavailable'
} else {
    $versionString = $module.Version.ToString()
    $prerelease = try { $module.PrivateData.PSData.Prerelease } catch { $null }
    if ($prerelease) {
        $versionString = "$versionString-$prerelease"
    }
}
```

This pattern:

- Works in PS 5.1 and PS 7.x without version checks.
- Handles stable releases (no prerelease key) and prereleases uniformly.
- Requires no scenario detection (dev / PSGallery / GitHub zip all load the same manifest).

### Edge cases

| Case | Handling |
|------|----------|
| Module not found | Display `Version unavailable` |
| Prerelease missing | Display version only |
| PrivateData malformed | Use `try`/`catch` or `2>$null` to avoid errors |

## Recommendation

Use the pattern above. Reuse the existing `Get-Module -Name Locksmith2` call in `New-LS2Dashboard` rather than adding a separate helper function, because the version is only needed in one place.

## Sources

- `Locksmith2.psd1` — manifest version and prerelease declaration.
- `Build/Build-Module.ps1` — conditional prerelease injection at build time.
- `Public/New-LS2Dashboard.ps1` — existing `Get-Module` usage for logo loading.
- Microsoft PowerShell docs: `Get-Module`, `PSModuleInfo`.
