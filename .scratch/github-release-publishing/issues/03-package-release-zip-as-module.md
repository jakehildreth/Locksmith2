# 03 — Package GitHub release zip as installable PowerShell module

**What to build:** The GitHub release zip extracts into a folder named `Locksmith2/`, ready to drop into a `Modules/` directory.

**Blocked by:** 01 — Decouple GitHub release publishing with `-PublishToGitHub`

**Status:** completed

- [x] Stage the vendored unpacked artefact under a temporary `Locksmith2/` parent folder before compression.
- [x] Compress that parent folder so the extracted archive has `Locksmith2/` at its root.
- [x] Clean up the temporary staging folder after upload or failure.
- [x] Update `Docs/ADR/0004-github-release-publishing-strategy.md` to describe the module-folder zip layout.
- [x] Add unit tests verifying the zip path includes the top-level `Locksmith2/` folder.
