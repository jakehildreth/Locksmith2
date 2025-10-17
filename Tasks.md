# Locksmith 2 - MVP Task Checklist

This checklist contains all tasks required to complete the Minimum Viable Product (MVP) for Locksmith 2, based on the PRD.md requirements marked with (M).

**Tasks are prioritized by impact and dependencies.**

---

## Phase 1: Foundation & Core Value (Highest Priority)

### 1. Module Infrastructure
**Impact: Critical** - Foundation for everything else
- [ ] Organize module structure and update manifest (.psd1) and root module (.psm1) with proper function exports
- [ ] Bundle all third-party modules (PSSQLite, PwshSpectreConsole, PSWriteHTML, PSCertutil) in distribution
- [ ] Update Build-Module.ps1 with version management and dependency checking

### 2. Core Detections
**Impact: Critical** - The primary value proposition
- [ ] Implement all ESC vulnerability detections (ESC1-8, 11, 13, 15, 16)
- [ ] Implement auditing configuration detection (including missing GPOs, CA and template audit settings)
- [ ] Implement robust error handling (no "Not applicable/available" messages, meaningful errors with context, fallback methods)

### 3. Output Formats
**Impact: Critical** - Users need to see detection results
- [ ] Design and implement PowerShell object schema (detections, remediations, risk ratings) that is pipeline-friendly
- [ ] Implement TUI/Console output using PwshSpectreConsole with color theming (dark/light themes, auto-theming for PS 5.1 and 7+ schemes)

### 4. Risk Rating System
**Impact: High** - Helps users prioritize what to fix
- [ ] Implement per-issue risk rating system with calculation algorithm (like LS1)
- [ ] Include risks from other misconfigurations and ACL-based principal abuse in calculations
- [ ] Display per-issue risk calculations in output

### 5. Core Cmdlets
**Impact: High** - Primary user interface
- [ ] Implement all cmdlets: `Find-LS2VulnerableTemplate`, `Find-LS2VulnerableObject`, `Find-LS2VulnerableCA`, `Find-LS2MostAbusableTemplate`, `Find-LS2MostDangerousPrincipal`, `Find-LS2DangerousCombination`, `Invoke-LS2`
- [ ] Write complete help documentation with examples for all cmdlets

---

## Phase 2: Remediation & Usability (High Priority)

### 6. Remediation System
**Impact: High** - Enables users to fix issues, not just find them
- [ ] Implement fix code for all ESC vulnerabilities and auditing issues with multiple remediation options showing relative risk
- [ ] Build interactive guidance system with CA database queries for issuance frequency analysis and contextual decision support
- [ ] Implement revert functionality for all fixes (both automated and manual instructions)

### 7. Interactive Health Check
**Impact: High** - Prevents user frustration and support burden
- [ ] Implement PowerShell version check (warn if < 7.4)
- [ ] Implement module dependency check (detect and offer installation for PSSQLite, PwshSpectreConsole, PSWriteHTML, PSCertutil)
- [ ] Implement user privilege check (detect AD admin status, warn about check limitations)
- [ ] Implement forest-joined status check with interactive prompts for remote forest access and credentials

### 8. Configuration & Documentation
**Impact: Medium-High** - Improves user experience and reduces repetitive input
- [ ] Implement JSON configuration system (schema design, file creation/reading/validation, runtime parameter override)
- [ ] Create title and description for each issue type

### 9. Headless Mode
**Impact: Medium-High** - Enables automation and enterprise adoption
- [ ] Ensure PowerShell 5.1 compatibility with no 3rd party module dependencies for headless mode
- [ ] Implement `Invoke-LS2` cmdlet with pipeline-friendly object output

---

## Phase 3: Quality & Documentation (Medium Priority)

### 10. Testing Infrastructure
**Impact: Medium** - Ensures quality and enables confident refactoring
- [ ] Create comprehensive unit test suite (detections, remediation, risk ratings, output, health checks, configuration, cmdlets)
- [ ] Implement integration tests for end-to-end workflows and multi-domain scenarios
- [ ] Test integration with AD/ADCS environments

### 11. Quality Assurance
**Impact: Medium** - Validates the product works in real-world scenarios
- [ ] Perform comprehensive testing in lab environment (all detections, remediations, revert operations, health checks, error handling)
- [ ] Test on all supported platforms (Windows Server 2016/2019/2022, Windows 10/11) and in multi-domain/multi-forest environments
- [ ] Test in both PowerShell 5.1 and 7.4 with graceful degradation verification

### 12. Documentation
**Impact: Medium** - Enables adoption and contribution
- [ ] Create/update user documentation (README.md with MVP features, installation guide, quick start guide, troubleshooting guide)
- [ ] Create developer documentation (code architecture, testing procedures, contribution guidelines, build process)

---

## Phase 4: Launch (Final Priority)

### 13. Release Preparation
**Impact: Medium** - Makes the product available to users
- [ ] Complete code review, performance testing, and security review
- [ ] Update CHANGELOG.MD and create release notes
- [ ] Publish to PowerShell Gallery and create GitHub release with updated documentation links

---

## Progress Tracking

**Total MVP Tasks:** 13
**Phase 1 (Foundation & Core Value):** 5 tasks
**Phase 2 (Remediation & Usability):** 4 tasks
**Phase 3 (Quality & Documentation):** 3 tasks
**Phase 4 (Launch):** 1 task

**Completed:** 0
**In Progress:** 0
**Remaining:** 13

---

## Priority Rationale

### Why This Order?

**Phase 1** focuses on the minimum to deliver core value:
- Module infrastructure must come first (foundation)
- Core detections are the primary value proposition
- Output is needed to see results
- Risk ratings help users prioritize
- Cmdlets provide the user interface

**Phase 2** makes the tool truly useful:
- Remediation turns findings into action
- Health checks prevent common user issues
- Configuration improves UX
- Headless mode enables enterprise adoption

**Phase 3** ensures quality and enables growth:
- Testing validates everything works
- QA catches real-world issues
- Documentation enables adoption

**Phase 4** ships it:
- Release preparation gets it to users

**Last Updated:** October 16, 2025
