# Security Policy

## Supported versions

Security fixes are prioritized for the latest published Locksmith2 release and
the current `main` branch. If you are using an older release, upgrade to the
latest release before reporting unless the issue is specific to the upgrade
path.

## Reporting a vulnerability

Do not report security vulnerabilities in public GitHub issues, discussions, or
pull requests.

Email vulnerability reports to <security@gilmour.ltd>. Include as much of the
following information as you can safely share:

- The Locksmith2 version or commit SHA.
- The affected command, function, scan, or remediation path.
- The operating system and PowerShell versions used.
- A clear description of the security impact.
- Minimal reproduction steps, sample output, or logs with secrets and sensitive
  environment details removed.
- Whether the issue is already being exploited or publicly discussed.

The maintainers will review the report, coordinate follow-up privately, and
publish public details after a fix or mitigation is available when disclosure is
appropriate.

## Handling sensitive AD CS data

Locksmith2 output can include names, distinguished names, SIDs, certificate
authority details, and remediation commands from an Active Directory
environment. Remove organization-specific or sensitive values before sharing
logs, screenshots, generated scripts, CSV files, dashboards, or command output
publicly.
