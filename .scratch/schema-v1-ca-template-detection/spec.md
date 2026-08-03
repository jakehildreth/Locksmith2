# Schema V1 CA Template Detection

Status: wayfinder:map

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

_None recorded yet._

## Not yet specified

- Exact wording of the CA-shaped schema v1 template issue/fix/revert text.
- Whether to add a new computed property (`IsCATemplate`) to `LS2AdcsObject` or compute it inline in `Find-LS2VulnerableTemplate`.
- Where to wire the enrichment (existing `Set-*` pipeline vs. a new `Set-IsCATemplate` function).
- Test coverage: unit tests for `Set-IsCATemplate` (if created) and `Find-LS2VulnerableTemplate` SchemaV1 branch for both CA and non-CA schema v1 templates.

## Out of scope

- Changing detection for non-schema-v1 templates.
- Adding new ESC techniques.
- Modifying the dashboard.
