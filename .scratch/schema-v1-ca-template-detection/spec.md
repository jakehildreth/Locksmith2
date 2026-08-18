# Schema V1 CA Template Detection

Status: wayfinder:map

GitHub: [#98 — SchemaV1: don't recommend supersession for CA-shaped templates](https://github.com/jakehildreth/Locksmith2/issues/98) (raised by @thedxt)

## Destination

Locksmith2 distinguishes CA-shaped schema v1 certificate templates from end-entity schema v1 templates and emits a remediation message appropriate to each. CA-shaped schema v1 templates are not recommended to be superseded like end-entity templates because supersession has not been observed to work reliably for CA templates in live environments.

## Notes

- Domain: AD CS certificate templates, schema v1 detection (`SchemaV1` technique), `LS2AdcsObject`, template enrichment functions (`Private/Set/`), `Find-LS2VulnerableTemplate`.
- Reliable CA-template signal: `pKIDefaultKeySpec -eq 2` (`AT_SIGNATURE`). This is already read into `LS2AdcsObject`.
- `pKIMaxIssuingDepth` and `pKICriticalExtensions` were considered and rejected as primary signals:
  - `pKIMaxIssuingDepth` is `-1` by default on CA templates but can be set to a concrete value, so a `-1`-only check would miss custom values.
  - `pKICriticalExtensions` contents depend on which extensions are marked critical and vary by schema version/admin action, so they do not reliably indicate a CA template.
- The `SchemaV1` technique currently recommends superseding the template with a schema v2+ equivalent. That guidance is appropriate for end-entity templates but should be replaced or qualified for CA-shaped templates.

## Decisions so far

- Add a new `IsCATemplate` property ([bool], defaults `$false`) to `LS2AdcsObject`. Rationale: every synthetic property in the class (`Enabled`, `AuthenticationEKUExist`, `DangerousEditor`, etc.) is declared on the class and set by a `Set-*` function — computed inline in Find functions is not an established pattern, and PS class properties cannot be ad-hoc added later without `Add-Member` hacks.
- Wire enrichment via a new `Set-IsCATemplate` function in `Private/Set/`, inserted into the existing template pipeline in `Initialize-AdcsObjectStore`. Rationale: one-function-per-file rule, matches the `Set-TemplateEnabled` precedent, and keeps Find functions data-only. Implementation: `$_.IsCATemplate = ($_.pKIDefaultKeySpec -eq 2)` for template objects.
- Do NOT change SchemaV1 `Conditions`. The property does not affect which templates match the technique — CA-shaped schema v1 templates are still findings, just with different remediation text. Branching belongs in the Find function/issue text, not the data Conditions.
- Find function: in the SchemaV1 branch of `Find-LS2VulnerableTemplate`, select Issue/Fix/Revert text based on `$template.IsCATemplate`. Since `ESCDefinitions.ps1` holds one IssueTemplate per technique, add a sibling key (e.g. `CAOverride = @{ IssueTemplate = ...; FixTemplate = ...; RevertTemplate = ... }`) inside the SchemaV1 entry rather than a new top-level technique — keeps the technique list clean and the data-driven pattern intact.

## Not yet specified

- Test coverage: unit tests for `Set-IsCATemplate` and `Find-LS2VulnerableTemplate` SchemaV1 branch for both CA and non-CA schema v1 templates.

### CA-shaped wording decision

Leave the CA template in place. Issue text states that replacing SubCA certificates requires planning and testing rather than simple supersession; Fix script contains no supersession instructions — awareness/documentation only.

## Out of scope

- Changing detection for non-schema-v1 templates.
- Adding new ESC techniques.
- Modifying the dashboard.
