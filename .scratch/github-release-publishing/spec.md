# GitHub Release Publishing Refinement

Status: ready-for-agent

## Problem Statement

The current GitHub release publishing strategy for Locksmith2 couples release creation to PSGallery publishing, uses a flat zip layout that does not match PowerShell module folder conventions, and allows local developer runs to accidentally create releases against the wrong commitish. The build also generates a Packed artefact via PSPublishModule that is no longer used. These issues make the release pipeline harder to reason about, harder to install from, and slightly riskier to run locally.

## Solution

Decouple GitHub release publishing from PSGallery publishing, remove the unused Packed artefact, repackage the release zip so it contains a top-level `Locksmith2/` module folder, and refuse to create GitHub releases outside GitHub Actions.

## User Stories

1. As a maintainer, I want GitHub release creation to be controlled by its own switch, so that I can publish a release asset without being forced to publish to PSGallery at the same time.
2. As a maintainer, I want PSGallery publishing and GitHub release publishing to be independent, so that a failure in one does not silently block the other.
3. As an air-gapped user, I want the GitHub release zip to extract into a folder named `Locksmith2/`, so that I can drop it into a `Modules/` directory and have PowerShell resolve it correctly.
4. As a CI consumer, I want the release asset to contain the same vendored `PSWriteHTML` and `PSCertutil` dependencies that ship to PSGallery, so that the two distribution channels are equivalent.
5. As a maintainer, I want the build to refuse to create a GitHub release when run locally, so that I do not accidentally publish a release from my laptop tied to the default branch instead of the current commit.
6. As a maintainer, I want missing GitHub credentials to fail loudly when release publishing is requested, so that silent skips do not leave me thinking a release was created.
7. As a maintainer, I want the PSPublishModule Packed artefact removed from the build, so that the only packed output is the one the GitHub release step produces.
8. As a maintainer, I want the workflow to pass the new `-PublishToGitHub` switch when running in GitHub Actions, so that releases continue to be created automatically.
9. As a maintainer, I want existing PSGallery publishing tests to keep passing, so that the refactor does not regress proven behavior.
10. As a maintainer, I want tests that verify the new GitHub publishing behavior, so that the refactored logic is protected from future regressions.

## Implementation Decisions

- Remove `New-ConfigurationArtefact -Type Packed` from `Build-Module.ps1`; the Packed artefact is no longer needed because the GitHub release zip is produced from the vendored unpacked artefact.
- Add a `[switch]$PublishToGitHub` parameter to `Invoke-LS2PostBuildPublish` and to the `Build-Module.ps1` passthrough.
- Decouple the GitHub release region from the PSGallery region so each can succeed or fail independently.
- Require `($GitHubAPIKey -or $GitHubAPIPath)` when `-PublishToGitHub` is set; otherwise fail loudly.
- Require `$env:GITHUB_SHA` when `-PublishToGitHub` is set; otherwise fail loudly so local runs cannot create releases.
- Create the zip by staging the vendored artefact under a temporary `Locksmith2/` parent folder, then compressing that parent folder, so the extracted archive matches PowerShell's module folder convention.
- Update `.github/workflows/publish.yml` to pass `-PublishToGitHub` alongside `-GitHubAPIKey` in both the release and prerelease build steps.
- Update `Docs/ADR/0004-github-release-publishing-strategy.md` to reflect the decoupled design, the repackaged zip, and the CI-only guard.

## Testing Decisions

- Extend `Tests/Build/Invoke-LS2PostBuildPublish.Tests.ps1` to cover the new behavior.
- Add tests verifying that `-PublishToGitHub` creates a release even when `-PublishToPSGallery` is not set.
- Add tests verifying that missing GitHub token with `-PublishToGitHub` fails loudly.
- Add tests verifying that missing `$env:GITHUB_SHA` with `-PublishToGitHub` fails loudly.
- Add tests verifying that `Compress-Archive` is called with a path that includes a top-level `Locksmith2/` folder.
- Keep the existing PSGallery vendoring and publishing tests unchanged except where the parameter set shifts.
- Use mocks for `Save-Module`, `Update-ModuleManifest`, `Publish-Module`, `Compress-Archive`, and `Invoke-RestMethod` to keep tests fast and offline.

## Out of Scope

- Generating release notes via AI or curated `CHANGELOG.md`; GitHub's auto-generated release notes remain sufficient.
- Adding branch detection inside `Invoke-LS2PostBuildPublish`; branch-based prerelease semantics stay in the workflow caller.
- Re-enabling the commented-out Pester test gate in the workflow; manual pre-push testing remains the process.
- Changing how vendored dependency versions are pinned.
- End-to-end tests against real PSGallery or GitHub.

## Further Notes

- The current release tag format is `{ModuleVersion}` for stable releases and `{ModuleVersion}-{Prerelease}` for prereleases. This does not change.
- The `generate_release_notes` flag remains enabled on GitHub release creation.
