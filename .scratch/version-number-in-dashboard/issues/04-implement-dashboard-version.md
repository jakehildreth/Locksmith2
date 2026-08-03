# Implement dashboard version display

Status: open
Labels: wayfinder:task
Assignees:

## Question

What is the implementation change required to add the agreed version string to the dashboard header and footer, and how should it be tested?

## Context

All prerequisite decisions are resolved:

- [Resolve module version at runtime](01-resolve-module-version.md) — Use `Get-Module -Name Locksmith2`, read `Version` and `PrivateData.PSData.Prerelease`.
- [Footer placement in PSWriteHTML](02-footer-pswritehtml.md) — Use `New-HTMLFooter` with `New-HTMLText -Alignment right`.
- [Version string format and fallback](03-version-format-and-fallback.md) — Display `2026.8.30507-pre`; omit the field entirely if resolution fails.

## Acceptance criteria

1. In `Public/New-LS2Dashboard.ps1`, resolve the module version string once near the existing `Get-Module` call.
2. Insert the version into the header line between "Computer" and "Generated":
   `Forest: X  |  User: Y  |  Computer: Z  |  Version: V  |  Generated: T`
3. If version resolution fails, omit the `Version:` segment entirely (no fallback text).
4. Add or update tests for `New-LS2Dashboard` to verify the version string appears in the generated HTML.

## Comments

- 2026-08-03: Ready for implementation.
