# 01 — Decouple GitHub release publishing with `-PublishToGitHub`

**What to build:** A maintainer can run the build and ask for a GitHub release without also asking for PSGallery publishing, and vice versa.

**Blocked by:** None — can start immediately.

**Status:** completed

- [x] Add `[switch]$PublishToGitHub` to `Build-Module.ps1` and pass it through to `Invoke-LS2PostBuildPublish`.
- [x] Add `[switch]$PublishToGitHub` to `Invoke-LS2PostBuildPublish`.
- [x] Move the GitHub release region out from under the PSGallery gate so PSGallery and GitHub publishing run independently.
- [x] Fail loudly when `-PublishToGitHub` is set but neither `-GitHubAPIKey` nor `-GitHubAPIPath` is provided.
- [x] Update `.github/workflows/publish.yml` to pass `-PublishToGitHub` in both release and prerelease steps.
- [x] Update `Docs/ADR/0004-github-release-publishing-strategy.md` to describe the decoupled parameter design.
- [x] Add or extend unit tests covering independent release creation and missing-token failure.
