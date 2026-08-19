# ESC5a CA-Host Self-Permission False Positive

Status: wayfinder:map

GitHub: [#99 — ESC5a false positive: CA host computer account rights on its own CA object](https://github.com/jakehildreth/Locksmith2/issues/99) (raised by @thedxt)

## Destination

ESC5a (Vulnerable PKI Object Access Control) no longer reports findings where the dangerous principal is a CA host's own computer account (e.g., `DOMAIN\CA-HOST01$`) holding rights on its own CA object (`pKIEnrollmentService`). This is normal, expected self-management; a CA host legitimately needs access to its own CA object.

## Notes

- Domain: ESC5a detection (`Private/Data/ESCDefinitions.ps1` — `EditorProperties: DangerousEditor, LowPrivilegeEditor`), ACL evaluation in `Private/Set/` enrichment functions, `Find-LS2VulnerableObject`, `LS2AdcsObject`.
- ESC5a has no `Conditions`; detection iterates `DangerousEditor`/`LowPrivilegeEditor` pre-calculated by `Set-*` functions — so suppression must happen at enrichment time or in the Find function's ACL loop, not in the data definition.
- The CA's host computer account is resolvable via the CA's `dNSHostName` (or the `CN=<host>,CN=Computers,...` reference) on the `pKIEnrollmentService` object.
- Distinct from GitHub #3, which covers false positives from *inherited, expected* ACEs (Exchange, Entra Connect) on CA host objects. This map covers only the principal-is-the-CA-host-itself case.
- Computer-account matching must handle both `DOMAIN\HOST$` NTAccount form and SID form, since `IdentityReference` representation varies.

## Decisions so far

- Suppress in the `Set-*` enrichment (`Set-DangerousEditor`, `Set-LowPrivilegeEditor`), own-CA only: skip ACEs where the ACE's IdentityReference SID equals the object's own `ComputerPrincipal`. Rationale: one guard per shared function fixes all consumers (Find functions, dashboard, risk scoring) at once; `ComputerPrincipal` (host computer SID) is already populated by `Set-CAComputerPrincipal` earlier in the pipeline, so no new lookup infrastructure is needed.
- Scope is own-CA only. A CA host account with write rights on a *different* CA object remains a finding.
- Non-CA objects (templates, containers) are unaffected — they have no `ComputerPrincipal`, so the guard is a null check.

## Not yet specified

- Test coverage: unit tests with mock ACEs where `IdentityReference` is the CA host account in both NTAccount and SID forms.

## Out of scope

- Other ESC5a false-positive classes (inherited expected ACEs — GitHub #3).
- ESC5o or other ESC5x variants.
- Changes to the ESC5a IssueTemplate/FixTemplate wording.
