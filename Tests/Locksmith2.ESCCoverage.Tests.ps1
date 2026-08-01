#requires -Version 5.1
# Tests that every technique in ESCDefinitions is wired up in all the places it needs to be,
# and that no ValidateSet member is orphaned from ESCDefinitions.
# Reads source files directly - no module import required.
#
# NOTE ON PESTER V5 SCOPING: variables set in a Describe body are only available during
# Discovery. It body code runs during the Run phase and cannot see those variables unless
# they are embedded in the -ForEach hashtable. All test cases are therefore built as
# hashtables that carry their own data, so the It body only uses $_ or named hash keys.

Describe 'ESC Definition Coverage' -Tag 'Unit' {

    # ---------- parse source files (Discovery phase) ----------

    $moduleRoot = Split-Path -Parent $PSScriptRoot

    $definitionsContent = Get-Content (Join-Path $moduleRoot 'Private\Data\ESCDefinitions.ps1') -Raw
    $templateContent    = Get-Content (Join-Path $moduleRoot 'Public\Find-LS2VulnerableTemplate.ps1') -Raw
    $caContent          = Get-Content (Join-Path $moduleRoot 'Public\Find-LS2VulnerableCA.ps1') -Raw
    $objectContent      = Get-Content (Join-Path $moduleRoot 'Public\Find-LS2VulnerableObject.ps1') -Raw
    $scanContent        = Get-Content (Join-Path $moduleRoot 'Private\Initialize\Initialize-LS2Scan.ps1') -Raw
    $invokeContent      = Get-Content (Join-Path $moduleRoot 'Public\Invoke-Locksmith2.ps1') -Raw

    $definedTechniques = [regex]::Matches($definitionsContent, "Technique\s*=\s*'(ESC\w+)'") |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

    $extractValidateSet = {
        param([string]$fileContent)
        $vsMatch = [regex]::Match($fileContent, '\[ValidateSet\(([^)]+)\)\]')
        if ($vsMatch.Success) {
            @([regex]::Matches($vsMatch.Groups[1].Value, "'(ESC[^']+)'") |
                ForEach-Object { $_.Groups[1].Value })
        } else { @() }
    }

    $templateValidated = & $extractValidateSet $templateContent
    $caValidated       = & $extractValidateSet $caContent
    $objectValidated   = & $extractValidateSet $objectContent
    $allValidated      = $templateValidated + $caValidated + $objectValidated

    $scanTechniques = @([regex]::Matches($scanContent, "'(ESC\w+)'") |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)

    $invokeMatch = [regex]::Match($invokeContent, '(?s)\$techniques\s*=\s*@\(([^)]+)\)')
    $invokeTechniques = @(if ($invokeMatch.Success) {
        [regex]::Matches($invokeMatch.Groups[1].Value, "'(ESC\w+)'") |
            ForEach-Object { $_.Groups[1].Value }
    })

    # ---------- build test-case hashtables (data baked in at Discovery time) ----------

    # Each hashtable key becomes a named variable inside the It body.
    $validateSetCases = $definedTechniques | ForEach-Object {
        @{
            Technique        = $_
            AllValidated     = $allValidated
            TemplateValidated = $templateValidated
            CAValidated      = $caValidated
            ObjectValidated  = $objectValidated
        }
    }

    $scanCases = $definedTechniques | ForEach-Object {
        @{ Technique = $_; ScanTechniques = $scanTechniques }
    }

    $invokeCases = $definedTechniques | ForEach-Object {
        @{ Technique = $_; InvokeTechniques = $invokeTechniques }
    }

    $templateReverseCases = $templateValidated | ForEach-Object {
        @{ Technique = $_; DefinedTechniques = $definedTechniques }
    }
    $caReverseCases = $caValidated | ForEach-Object {
        @{ Technique = $_; DefinedTechniques = $definedTechniques }
    }
    $objectReverseCases = $objectValidated | ForEach-Object {
        @{ Technique = $_; DefinedTechniques = $definedTechniques }
    }

    # ---------- tests ----------

    Context 'Every defined technique appears in exactly one Find-LS2Vulnerable* ValidateSet' {
        It '<Technique> is in a Find-LS2Vulnerable* ValidateSet' -ForEach $validateSetCases {
            $AllValidated | Should -Contain $Technique -Because "$Technique must be reachable via a Find-LS2Vulnerable* -Technique parameter"
        }

        It '<Technique> is not assigned to multiple Find-LS2Vulnerable* functions' -ForEach $validateSetCases {
            $count = 0
            if ($TemplateValidated -contains $Technique) { $count++ }
            if ($CAValidated       -contains $Technique) { $count++ }
            if ($ObjectValidated   -contains $Technique) { $count++ }
            $count | Should -BeLessOrEqual 1 -Because "$Technique should belong to exactly one Find-LS2Vulnerable* function"
        }
    }

    Context 'No ValidateSet member is orphaned from ESCDefinitions' {
        It 'Find-LS2VulnerableTemplate ValidateSet member <Technique> exists in ESCDefinitions' -ForEach $templateReverseCases {
            $DefinedTechniques | Should -Contain $Technique -Because "$Technique is in ValidateSet but missing from ESCDefinitions"
        }

        It 'Find-LS2VulnerableCA ValidateSet member <Technique> exists in ESCDefinitions' -ForEach $caReverseCases {
            $DefinedTechniques | Should -Contain $Technique -Because "$Technique is in ValidateSet but missing from ESCDefinitions"
        }

        It 'Find-LS2VulnerableObject ValidateSet member <Technique> exists in ESCDefinitions' -ForEach $objectReverseCases {
            $DefinedTechniques | Should -Contain $Technique -Because "$Technique is in ValidateSet but missing from ESCDefinitions"
        }
    }

    Context 'Every defined technique is scanned by Initialize-LS2Scan' {
        It '<Technique> is in an Initialize-LS2Scan technique array' -ForEach $scanCases {
            $ScanTechniques | Should -Contain $Technique -Because "$Technique must be in Initialize-LS2Scan so Invoke-Locksmith2 triggers it"
        }
    }

    Context 'Every defined technique appears in Invoke-Locksmith2 reporting list' {
        It '<Technique> is in Invoke-Locksmith2 $techniques' -ForEach $invokeCases {
            $InvokeTechniques | Should -Contain $Technique -Because "$Technique must be in the verbose issue count loop in Invoke-Locksmith2"
        }
    }
}
