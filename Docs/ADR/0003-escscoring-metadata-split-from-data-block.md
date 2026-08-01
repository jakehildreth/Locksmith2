# ADR-0003: Separate ESC Scoring Metadata from the ESCDefinitions data{} Block

## Status

Accepted

## Context

`Private/Data/ESCDefinitions.ps1` defines configuration for all 19 ESC vulnerability
techniques using a PowerShell `data { }` statement. The `data` statement provides a
constrained execution environment — it restricts the expression types allowed inside
it to prevent accidental side effects (no function calls, no complex expressions, only
literals, `if`/`elseif`/`else`, and a small whitelist of `ConvertFrom-StringData` calls).

When implementing the risk-rating engine (feat/risk-rating), each technique entry
required new scoring keys:

- `BaseScore` (int)
- `TechniqueBonus` (int)
- `ApplyEnabledModifier` (bool)
- `ApplyPrincipalRisk` (bool)
- `ApplyObjectClassBonus` (bool)
- `ObjectClassBonuses` (hashtable)
- `NtAuthBonus` (int)
- `EndpointBonuses` (hashtable)
- `CrossESCModifiers` (array of hashtables)

The deeply nested `CrossESCModifiers` structure requires arrays of hashtables with
nested arrays (e.g., `RequiredTechniquePatterns = @('ESC5a', 'ESC5o')`). While
these values are technically literals, the `data {}` block's constrained mode is
strict enough that adding this depth of nesting inline created fragility and
maintenance risk as the block grew.

## Decision

Define scoring metadata in a separate `$script:ESCScoringMetadata` hashtable (a plain
`@{ }` expression outside the `data {}` block), keyed by technique name (e.g.,
`'ESC1'`, `'ESC5a'`). After the `data {}` block populates `$script:ESCDefinitions`,
a merge loop copies all scoring keys from `$script:ESCScoringMetadata` into the
corresponding entries in `$script:ESCDefinitions`.

All callers see a unified `$script:ESCDefinitions['ESC1']` entry that contains both
detection/remediation keys (from `data {}`) and scoring keys (from the merge). The
split is a load-time implementation detail — it is invisible to the rest of the module.

The alternative — collapsing `data {}` into a plain `@{ }` — was explicitly rejected.
The `data {}` block provides a meaningful constraint that protects the detection and
remediation content from inadvertent side effects. Removing it to accommodate scoring
keys would erode that safety net for the wrong reason.

## Consequences

[+] The `data {}` block retains its constrained-mode guarantees for all
    detection/remediation content, reducing the risk of accidental side effects.
[+] Scoring metadata is grouped together in one place, making it easy to review and
    audit all 19 technique scores as a table.
[+] The merge loop is the only coupling between the two structures; adding a new
    scoring key requires updating `$script:ESCScoringMetadata` entries only.
[!] A developer unfamiliar with the pattern may be confused by `$script:ESCDefinitions`
    containing keys not visible inside the `data {}` block. The merge loop and this
    ADR serve as the canonical explanation.
[!] Technique names must be consistent between the `data {}` block keys and the
    `$script:ESCScoringMetadata` keys. A typo in one will silently leave the scoring
    keys absent for that technique. Tests in `Tests/Private/Data/ESCDefinitions.Tests.ps1`
    validate that every known technique has all required scoring keys present.
