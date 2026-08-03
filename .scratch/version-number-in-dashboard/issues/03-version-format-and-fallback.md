# Version string format and fallback

Status: closed
Labels: wayfinder:grilling
Assignees:

## Question

What exact string should be displayed for the version (e.g., `2026.8.30507`, `2026.8.30507-pre`, `Locksmith 2 v2026.8.30507-pre`), and what should appear if the version cannot be resolved at runtime?

## Resolution

- Display the CalVer version plus the prerelease tag when present: `2026.8.30507-pre`.
- If the version cannot be resolved at runtime, omit the version field entirely from both the header and the footer rather than showing fallback text.

## Comments

- 2026-08-03: Decision made by user.
