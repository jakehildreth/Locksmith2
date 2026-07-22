# 04 — Remove unused Packed artefact

**What to build:** The build no longer wastes time producing a Packed artefact that nobody uses.

**Blocked by:** None — can start immediately, but sequencing after 03 avoids ADR churn.

**Status:** completed

- [x] Remove the commented `New-ConfigurationArtefact -Type Packed` line from `Build-Module.ps1`.
- [x] Update the `Invoke-LS2PostBuildPublish` success message from "Packed artefact" to "Release zip".
- [x] Verify the build still produces the `-Type Unpacked` artefact and the GitHub release zip.
- [x] Run build tests and confirm they pass.
