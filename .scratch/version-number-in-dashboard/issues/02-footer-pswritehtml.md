# Footer placement in PSWriteHTML

Status: closed
Labels: wayfinder:research
Assignees:

## Question

How should a bottom-right footer be added to a PSWriteHTML dashboard, and what is the recommended way to align text to the bottom-right of the page?

## Resolution

Use `New-HTMLFooter` inside the `New-HTML` script block, with `New-HTMLText -Alignment right` for bottom-right alignment. The footer renders as a semantic `<footer>` tag at the end of the document body and is unaffected by the `-Online` switch. See the full findings in [research/02-footer-pswritehtml.md](../../research/02-footer-pswritehtml.md).

## Comments

- 2026-08-03: Research complete. Right-aligned text inside `New-HTMLFooter` satisfies the requirement.
