# 02 — Make GitHub releases CI-only

**What to build:** A local run with `-PublishToGitHub` cannot accidentally create a release tied to the default branch.

**Blocked by:** 01 — Decouple GitHub release publishing with `-PublishToGitHub`

**Status:** completed

- [x] Refuse to create a GitHub release when `-PublishToGitHub` is set but the commit SHA is missing.
- [x] Add a `-GitHubSha` parameter to `Invoke-LS2PostBuildPublish` that defaults to `$env:GITHUB_SHA` for testability and GitHub Actions compatibility.
- [x] Update `Docs/ADR/0004-github-release-publishing-strategy.md` to document the CI-only guard.
- [x] Add unit tests verifying the local-run refusal and the success path when a SHA is provided.
