# AuditFilter Query Failure False Positive

Status: implemented (2026-08-20), pending PS 5.1 test run on Windows

GitHub: [#92 — AuditFilter detection Possible Bug](https://github.com/jakehildreth/Locksmith2/issues/92) (raised by @thedxt)

## Destination

Locksmith2 distinguishes "auditing is disabled/incomplete" from "could not determine auditing state." When the AuditFilter query fails (certutil error, CA unreachable, RPC blocked, permissions), the `Auditing` technique must not fire, and the user should be able to tell the query failed rather than infer auditing is fine.

## Notes

- Domain: `Private/Set/Set-CAAuditFilter.ps1` (queries AuditFilter via PSCertutil's `Get-PSCAuditFilter`), `Classes/LS2AdcsObject.ps1` (`[Nullable[int]]$AuditFilter`, `[bool]$AuditingIncomplete`), `Private/Data/ESCDefinitions.ps1` (`Auditing` technique, condition `AuditingIncomplete -eq $true`).
- Failure modes in `Set-CAAuditFilter` today, all silent (Verbose only):
  - `Get-PSCAuditFilter` throws → caught, property untouched.
  - Returns `$null` or object without `AuditFilter` → skipped.
  - No `CAFullName` on the object → skipped.
- `AuditingIncomplete` is non-nullable `[bool]` on the class, so "never queried" and "queried, auditing fine" share one value (`$false`). The detection condition cannot distinguish failure from clean.
- Reporter's symptom implies `AuditingIncomplete` ends up `$true` on query failure in their environment; needs a repro trace to find which path sets it (stale store value, partial read, or upstream default). Regardless of the exact trigger, the missing tri-state is the root design gap.

## Decisions so far

- **Root cause (confirmed by mock repro):** `AuditingIncomplete` was the only one of the four certutil-backed detection properties declared non-nullable `[bool]`. Query failure left `$false`, indistinguishable from "queried, auditing complete." The other three (`SANFlagEnabled`, `RPCEncryptionNotRequired`, `SecurityExtensionDisabled`) were already `[Nullable[bool]]`.
- **Tri-state shape:** `[Nullable[bool]]`, `$null` = unknown/never queried. Matches existing class conventions (`ManagerApprovalNotRequired`, `AuthorizedSignatureNotRequired`, `SecurityExtensionDisabled`). No companion `*Queried` flag — `$null` carries the signal.
- **Detection condition unchanged:** the generic evaluator (`Find-LS2VulnerableCA.ps1`, `$propertyValue -ne $condition.Value`) already fails to match `$null -eq $true`, so `ESCDefinitions.ps1` needed no edit. Verified by a new Find-level test: CA with `AuditingIncomplete = $null` emits no `Auditing` issue.
- **Failure paths set `$null` explicitly** (not just "leave untouched") in all four cmdlets, so a stale value from a rescan cannot survive a failed query.
- **`Set-CADisableExtensionList` catch block was broken independently:** inside `catch`, `$_` is the ErrorRecord, so `$_.DisableExtensionList = $null` threw on the ErrorRecord. The catch had never worked. Fixed by capturing the CA object in `$caObject` before the try — the pattern the other three cmdlets already used; those three were also converted from `$_` to `$caObject` inside try/catch for the same latent reason.
- **Failed query stays silent** (Verbose only) — no new informational finding type. The fix is that failure ≠ finding; surfacing "couldn't check CA X" to the user is a possible follow-up, not required by #92.
- **ESC11 semantics preserved:** `IF_ENFORCEENCRYPTICERTREQUEST` absent from a *successful* InterfaceFlags result still yields `RPCEncryptionNotRequired = $true` (flag genuinely not set on the CA). Only query failure yields `$null`.

## Not yet specified

_Nothing — implemented 2026-08-20._

## Out of scope

- Changes to the `Auditing` IssueTemplate/FixTemplate wording.
- PSCertutil module changes.
- Surfacing query failures as informational findings.

## Implementation (2026-08-20)

- `Classes/LS2AdcsObject.ps1` — `AuditingIncomplete` → `[Nullable[bool]]`.
- `Private/Set/Set-CAAuditFilter.ps1` — `$null` on throw and empty-result paths.
- `Private/Set/Set-CAEditFlags.ps1` — `$null` on throw and empty-result paths.
- `Private/Set/Set-CAInterfaceFlags.ps1` — `$null` on throw and empty-result paths.
- `Private/Set/Set-CADisableExtensionList.ps1` — fixed `$_`-is-ErrorRecord catch bug; `$null` on throw path.
- `Tests/Shared/TestHelpers.psm1` — mock default `AuditingIncomplete = $null`.
- Tests added: failure-path (throw + null-result) contexts in all four `Set-CA*` test files; PSCertutil stub added to `Set-CADisableExtensionList.Tests.ps1`; Find-level `$null` regression test in `Find-LS2VulnerableCA.Tests.ps1`.
- Verified: 56/56 targeted tests pass in pwsh 7.6.5; full suite 2138/238-fail where the 238 are pre-existing macOS platform failures identical on unmodified `main` (no `System.DirectoryServices`/`Get-CimInstance`/Windows Principal APIs). PS 5.1 leg **not run locally** (no `powershell.exe` on macOS) — must be run on Windows before merge.
