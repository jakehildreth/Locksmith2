# ADR-0001: Convert Private/Data .psd1 Files to .ps1 for PSM1 Embedding

## Status

Accepted

## Context

Locksmith2 uses three data definition files stored in `Private/Data/`:

- `AceDefinitions.psd1`
- `ESCDefinitions.psd1`
- `PrincipalDefinitions.psd1`

These files are loaded at runtime via `Import-PowerShellDataFile` using relative paths
resolved from `$PSScriptRoot`. This works correctly during development, where the folder
structure is preserved.

The project uses [PSPublishModule](https://github.com/EvotecIT/PSPublishModule) (v2.0.27)
to build a merged `.psm1`/`.psd1` artefact for distribution. PSPublishModule provides
`New-ConfigurationInformation -IncludeAll 'Private\Data'` specifically to include
non-.ps1 files in the build output. However, in practice these `.psd1` files do not
appear in the unpacked or packed artefacts produced by the build, making the published
module non-functional.

After the merge, `$PSScriptRoot` resolves to the module root, not the original source
subfolder, so the relative paths used to load the data files would break regardless of
whether the files were present.

## Decision

Convert the three `.psd1` data files to `.ps1` files. Each file will assign its data
to a `$script:`-scoped variable using a PowerShell `data` block rather than returning a
bare hashtable. PSPublishModule merges all `.ps1` files from `Private/` into the compiled
`.psm1`, so the data will be embedded at build time and available to all functions without
any file I/O at runtime.

The `data` block is a PowerShell language construct that enforces the same literal-only
restriction as `Import-PowerShellDataFile` — variable references, expressions, and arbitrary
commands are rejected at parse time. This preserves the data-only guarantee that `.psd1`
provided.

All call sites that use `Import-PowerShellDataFile` to load these definitions will be
updated to reference the corresponding `$script:` variable directly.

The `.psd1` source files will be deleted once all call sites are updated and the build
is verified.

## Consequences

[+] Data definitions are embedded in the compiled module — no runtime file path dependency.
[+] Published module works correctly when installed from the PSGallery.
[+] Eliminates `Import-PowerShellDataFile` overhead on every function call.
[+] `New-ConfigurationInformation -IncludeAll 'Private\Data'` can be removed from Build-Module.ps1.
[!] Data definitions are no longer editable without rebuilding the module.
[+] PowerShell `data` blocks in the `.ps1` files enforce the same literal-only restriction as
    `Import-PowerShellDataFile`, preserving the data-only guarantee of `.psd1`.
