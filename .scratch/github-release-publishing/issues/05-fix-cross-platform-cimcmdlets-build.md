# 05 — Fix cross-platform build by removing CimCmdlets from required modules

**What to build:** `Build-Module.ps1` completes successfully on macOS and Linux without failing because `CimCmdlets` cannot be imported.

**Blocked by:** None — can start immediately.

**Status:** completed

- [x] Remove `CimCmdlets` from `New-ConfigurationModule -Type ExternalModule` in `Build-Module.ps1`.
- [x] Remove `CimCmdlets` from `RequiredModules` in `Locksmith2.psd1`.
- [x] Remove `CimCmdlets` from `ExternalModuleDependencies` in `Locksmith2.psd1` `PrivateData.PSData`.
- [x] Document that `Get-CimInstance` auto-loads `CimCmdlets` on Windows and is unavailable on macOS/Linux.
- [x] Run `Build-Module.ps1` on macOS and verify it completes the PSPublishModule build phase.
