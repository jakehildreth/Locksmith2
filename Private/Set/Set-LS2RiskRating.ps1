function Set-LS2RiskRating {
    <#
    .SYNOPSIS
        Computes and assigns risk ratings to a collection of LS2Issue objects.
    .DESCRIPTION
        Performs a data-driven two-pass scoring algorithm:
          Pass 1 - Per-issue: BaseScore + TechniqueBonus + EnabledModifier +
                   PrincipalRisk + ObjectClassBonus + NtAuthBonus + EndpointBonus
          Pass 2 - Cross-ESC: applies cross-technique modifiers based on related
                   issues in the same forest
        Clamps minimum score to 0, then maps to RiskName:
          <=1 Informational | 2 Low | 3 Medium | 4 High | >=5 Critical
        Mutates each LS2Issue in place; returns nothing.
    .PARAMETER Issues
        Array of LS2Issue objects to score.
    .EXAMPLE
        $allIssues = Get-FlattenedIssues
        Set-LS2RiskRating -Issues $allIssues
    .OUTPUTS
        None. Modifies LS2Issue objects in place.
    .NOTES
        Scoring metadata is defined in Private/Data/ESCDefinitions.ps1 as
        $script:ESCScoringMetadata, merged into $script:ESCDefinitions at load.
        Principal definitions are in Private/Data/PrincipalDefinitions.ps1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [LS2Issue[]]$Issues
    )

    if ($Issues.Count -eq 0) { return }

    $rawValues   = @{}
    $scoreTrails = @{}

    # ---- Pass 1: Per-issue scoring (no cross-ESC) --------------------------------- #
    foreach ($issue in $Issues) {
        $def = $script:ESCDefinitions[$issue.Technique]
        if ($null -eq $def) {
            $rawValues[$issue]   = 0
            $scoreTrails[$issue] = [System.Collections.Generic.List[string]]::new()
            continue
        }

        $riskValue   = $def.BaseScore
        $riskScoring = [System.Collections.Generic.List[string]]::new()
        $riskScoring.Add("BaseScore: $($def.BaseScore)")

        # TechniqueBonus
        if ($def.TechniqueBonus -gt 0) {
            $riskValue += $def.TechniqueBonus
            $riskScoring.Add("TechniqueBonus: +$($def.TechniqueBonus)")
        }

        # EnabledModifier
        if ($def.ApplyEnabledModifier) {
            if ($issue.Enabled -eq $true) {
                $riskValue += 1
                $riskScoring.Add('Enabled: +1')
            } elseif ($issue.Enabled -eq $false) {
                $riskValue -= 2
                $riskScoring.Add('Disabled: -2')
            }
        }

        # PrincipalRisk
        if ($def.ApplyPrincipalRisk) {
            $principalBonus = Get-PrincipalRiskBonus `
                -IdentityReferenceSID   $issue.IdentityReferenceSID `
                -IdentityReferenceClass $issue.IdentityReferenceClass
            $riskValue += $principalBonus.Score
            foreach ($lbl in $principalBonus.Labels) { $riskScoring.Add($lbl) }
        }

        # ObjectClassBonus
        if ($def.ApplyObjectClassBonus) {
            $objectClass = if ($null -ne $issue.ObjectClass) { $issue.ObjectClass } else { '' }
            if ($def.ObjectClassBonuses.ContainsKey($objectClass)) {
                $objBonus = $def.ObjectClassBonuses[$objectClass]
                $riskValue += $objBonus
                $riskScoring.Add("ObjectClass($objectClass): +$objBonus")
            }
            if ($null -ne $issue.DistinguishedName -and $issue.DistinguishedName -like '*NtAuthCertificates*') {
                $riskValue += $def.NtAuthBonus
                $riskScoring.Add("NtAuthCertificates: +$($def.NtAuthBonus)")
            }
        }

        # EndpointBonus
        if ($def.EndpointBonuses.Count -gt 0 -and
            $null -ne $issue.EndpointAttackVector -and
            $issue.EndpointAttackVector -ne '') {
            if ($def.EndpointBonuses.ContainsKey($issue.EndpointAttackVector)) {
                $epBonus = $def.EndpointBonuses[$issue.EndpointAttackVector]
                $riskValue += $epBonus
                $riskScoring.Add("EndpointBonus($($issue.EndpointAttackVector)): +$epBonus")
            }
        }

        $rawValues[$issue]   = $riskValue
        $scoreTrails[$issue] = $riskScoring
    }

    # ---- Pass 2: Cross-ESC modifiers --------------------------------------------- #
    foreach ($issue in $Issues) {
        $def = $script:ESCDefinitions[$issue.Technique]
        if ($null -eq $def -or $def.CrossESCModifiers.Count -eq 0) { continue }

        foreach ($modifier in $def.CrossESCModifiers) {

            # Gate: only applies when this issue is disabled (if configured)
            if ($modifier.OnlyWhenDisabled -and $issue.Enabled -ne $false) { continue }

            # Find qualifying related issues in the same forest
            $relatedIssues = $Issues | Where-Object {
                $candidate = $_
                if ([object]::ReferenceEquals($candidate, $issue)) { return $false }
                if ($candidate.Forest -ne $issue.Forest)           { return $false }

                # Technique must match at least one RequiredTechniquePatterns entry
                $techniqueMatch = $false
                foreach ($pattern in $modifier.RequiredTechniquePatterns) {
                    if ($candidate.Technique -like $pattern) {
                        $techniqueMatch = $true
                        break
                    }
                }
                if (-not $techniqueMatch) { return $false }

                # RequiredObjectClass filter ('' = any)
                if ($modifier.RequiredObjectClass -ne '' -and
                    $candidate.ObjectClass -ne $modifier.RequiredObjectClass) {
                    return $false
                }

                # OnlyEnabledMatches filter
                if ($modifier.OnlyEnabledMatches -and $candidate.Enabled -ne $true) {
                    return $false
                }

                return $true
            }

            $relatedIssues = @($relatedIssues)
            if ($relatedIssues.Count -eq 0) { continue }

            $crossBonus = 0
            if ($modifier.BonusFromPrincipalRisk) {
                foreach ($related in $relatedIssues) {
                    $pBonus = Get-PrincipalRiskBonus `
                        -IdentityReferenceSID   $related.IdentityReferenceSID `
                        -IdentityReferenceClass $related.IdentityReferenceClass
                    $crossBonus += $pBonus.Score
                }
                $crossBonus = [Math]::Min($crossBonus, $modifier.BonusCap)
            } else {
                $crossBonus = [Math]::Min($modifier.Bonus, $modifier.BonusCap)
            }

            if ($crossBonus -gt 0) {
                $rawValues[$issue] += $crossBonus
                $scoreTrails[$issue].Add(
                    "CrossESC($($modifier.RequiredTechniquePatterns -join ',')): +$crossBonus"
                )
            }
        }
    }

    # ---- Final: clamp, map RiskName, commit ---------------------------------------- #
    foreach ($issue in $Issues) {
        $def = $script:ESCDefinitions[$issue.Technique]
        if ($null -eq $def) { continue }

        $finalValue = [Math]::Max(0, $rawValues[$issue])

        $riskName = if ($finalValue -le 1) { 'Informational' }
                    elseif ($finalValue -eq 2) { 'Low' }
                    elseif ($finalValue -eq 3) { 'Medium' }
                    elseif ($finalValue -eq 4) { 'High' }
                    else   { 'Critical' }

        $issue.RiskValue  = $finalValue
        $issue.RiskName   = $riskName
        $issue.RiskScoring = [string[]]$scoreTrails[$issue]
    }
}
