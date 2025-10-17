# Locksmith 2 - MVP Task Checklist

This checklist contains all tasks required to complete the Minimum Viable Product (MVP) for Locksmith 2, based on the PRD.md requirements marked with (M).

## 1. Testing Infrastructure

- [ ] Create comprehensive unit test suite (detections, remediation, risk ratings, output, health checks, configuration, cmdlets)
- [ ] Implement integration tests for end-to-end workflows and multi-domain scenarios
- [ ] Test integration with AD/ADCS environments

## 2. Core Detections

- [ ] Implement all ESC vulnerability detections (ESC1-8, 11, 13, 15, 16)
- [ ] Implement auditing configuration detection (including missing GPOs, CA and template audit settings)
- [ ] Implement robust error handling (no "Not applicable/available" messages, meaningful errors with context, fallback methods)

## 3. Remediation System

- [ ] Implement fix code for all ESC vulnerabilities and auditing issues with multiple remediation options showing relative risk
- [ ] Build interactive guidance system with CA database queries for issuance frequency analysis and contextual decision support
- [ ] Implement revert functionality for all fixes (both automated and manual instructions)

## 4. Risk Rating System

- [ ] Implement per-issue risk rating system with calculation algorithm (like LS1)
- [ ] Include risks from other misconfigurations and ACL-based principal abuse in calculations
- [ ] Display per-issue risk calculations in output

## 5. Output Formats

- [ ] Design and implement PowerShell object schema (detections, remediations, risk ratings) that is pipeline-friendly
- [ ] Implement TUI/Console output using PwshSpectreConsole with color theming (dark/light themes, auto-theming for PS 5.1 and 7+ schemes)

## 6. Interactive Health Check

- [ ] Implement PowerShell version check (warn if < 7.4)
- [ ] Implement module dependency check (detect and offer installation for PSSQLite, PwshSpectreConsole, PSWriteHTML, PSCertutil)
- [ ] Implement user privilege check (detect AD admin status, warn about check limitations)
- [ ] Implement forest-joined status check with interactive prompts for remote forest access and credentials

## 7. Configuration & Documentation

- [ ] Implement JSON configuration system (schema design, file creation/reading/validation, runtime parameter override)
- [ ] Create title and description for each issue type

## 8. Headless Mode

- [ ] Ensure PowerShell 5.1 compatibility with no 3rd party module dependencies for headless mode
- [ ] Implement `Invoke-LS2` cmdlet with pipeline-friendly object output

## 9. Core Cmdlets

- [ ] Implement all cmdlets: `Find-LS2VulnerableTemplate`, `Find-LS2VulnerableObject`, `Find-LS2VulnerableCA`, `Find-LS2MostAbusableTemplate`, `Find-LS2MostDangerousPrincipal`, `Find-LS2DangerousCombination`, `Invoke-LS2`
- [ ] Write complete help documentation with examples for all cmdlets

## 10. Module Infrastructure

- [ ] Organize module structure and update manifest (.psd1) and root module (.psm1) with proper function exports
- [ ] Bundle all third-party modules (PSSQLite, PwshSpectreConsole, PSWriteHTML, PSCertutil) in distribution
- [ ] Update Build-Module.ps1 with version management and dependency checking

## 11. Documentation

- [ ] Create/update user documentation (README.md with MVP features, installation guide, quick start guide, troubleshooting guide)
- [ ] Create developer documentation (code architecture, testing procedures, contribution guidelines, build process)

## 12. Quality Assurance

- [ ] Perform comprehensive testing in lab environment (all detections, remediations, revert operations, health checks, error handling)
- [ ] Test on all supported platforms (Windows Server 2016/2019/2022, Windows 10/11) and in multi-domain/multi-forest environments
- [ ] Test in both PowerShell 5.1 and 7.4 with graceful degradation verification

## 13. Release Preparation

- [ ] Complete code review, performance testing, and security review
- [ ] Update CHANGELOG.MD and create release notes
- [ ] Publish to PowerShell Gallery and create GitHub release with updated documentation links

---

## Progress Tracking

**Total MVP Tasks:** 26
**Completed:** 0
**In Progress:** 0
**Remaining:** 26

**Last Updated:** October 16, 2025
