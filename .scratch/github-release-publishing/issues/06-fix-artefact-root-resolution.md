# 06 — Fix artefact root resolution in post-build publishing

**What to build:** `Invoke-LS2PostBuildPublish` finds the actual unpacked module folder regardless of how deeply PSPublishModule nests it under `Artefacts/Unpacked/`.

**Blocked by:** None — can start immediately.

**Status:** completed

- [x] Resolve the module root by searching for `Locksmith2.psd1` under the provided `-ArtefactRoot` path instead of assuming it is the immediate parent of the manifest.
- [x] Keep the public `-ArtefactRoot` parameter stable so callers do not need to change.
- [x] Update unit tests to cover both the flat layout and the nested layout.
- [x] Run `Build-Module.ps1` on macOS and verify the vendoring step patches the manifest without an `Update-ModuleManifest` warning.
