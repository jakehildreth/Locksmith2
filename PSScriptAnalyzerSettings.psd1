@{
    # Rules excluded by design for the Locksmith2 codebase.
    # Each exclusion is documented with its rationale below.
    ExcludeRules = @(

        # Set-*, New-*, Update-*, and similar internal functions are pipeline enrichment helpers,
        # not user-facing cmdlets. Adding ShouldProcess/ConfirmImpact would break their pipeline
        # pass-through pattern and is inappropriate for internal object-property setters.
        'PSUseShouldProcessForStateChangingFunctions'

        # Module domain language intentionally uses plural nouns as domain terms:
        # IssueStore, PrincipalStore, AdcsObjectStore, DomainStore, Flags, Definitions, Connections.
        # These are established naming conventions throughout the module.
        'PSUseSingularNouns'

        # Source files are saved as UTF-8 without BOM by design. A BOM can cause issues in
        # some editors, CI systems, and when files are concatenated. Encoding is managed
        # consistently across the project without the BOM marker.
        'PSUseBOMForUnicodeEncodedFile'

        # Write-Host is used intentionally in UI/display functions (Show-Logo,
        # Get-RootDSE diagnostics, Set-LS2Credential prompts, New-LS2Dashboard status) where
        # output must go directly to the console and must NOT be captured in the pipeline.
        'PSAvoidUsingWriteHost'

        # Null comparisons are correct in context. Left-hand null ($null -eq $x) is the
        # recommended PowerShell idiom and is used intentionally where present.
        'PSPossibleIncorrectComparisonWithNull'

        # Parameters flagged as unused are consumed via pipeline binding, advanced function
        # parameter sets, or dynamic dispatch patterns that PSSA cannot statically trace.
        'PSReviewUnusedParameter'

        # Variables flagged as assigned-but-unused are declared for pattern consistency,
        # iterative development placeholders, or to capture outputs from cmdlets whose
        # side-effects are the intent (e.g. pipeline passthrough assignments).
        'PSUseDeclaredVarsMoreThanAssignments'
    )
}
