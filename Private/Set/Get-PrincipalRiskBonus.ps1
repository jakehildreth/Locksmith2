function Get-PrincipalRiskBonus {
    <#
    .SYNOPSIS
        Computes the principal risk bonus score for a given SID and class.
    .DESCRIPTION
        Additive evaluation — modifiers accumulate independently:
          1. SafePrincipal match            -> Score=0, Labels=@()  (early return)
          2. DangerousPrincipal match       -> Score=3, Labels=['UnsafePrincipal: +1', 'DangerousPrincipal: +2']
             (group modifier never applies to dangerous principals)
          3. UnsafePrincipal (not safe, not dangerous, class = 'group') -> Score=2, Labels=['UnsafePrincipal: +1', 'UnsafeGroup: +1']
          4. UnsafePrincipal (not safe, not dangerous, non-group)       -> Score=1, Labels=['UnsafePrincipal: +1']
        Returns a PSCustomObject with Score ([int]) and Labels ([string[]]) properties.
    .PARAMETER IdentityReferenceSID
        SID or NTAccount string of the principal.
    .PARAMETER IdentityReferenceClass
        Object class of the principal (e.g. 'group', 'user').
    .EXAMPLE
        Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-1-0' -IdentityReferenceClass 'group'
        # Returns Score=3, Labels=@('UnsafePrincipal: +1', 'DangerousPrincipal: +2')  (Everyone)
    .EXAMPLE
        Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-1001' -IdentityReferenceClass 'group'
        # Returns Score=2, Labels=@('UnsafePrincipal: +1', 'UnsafeGroup: +1')
    .EXAMPLE
        Get-PrincipalRiskBonus -IdentityReferenceSID 'S-1-5-21-1234-5678-9012-512' -IdentityReferenceClass 'group'
        # Returns Score=0, Labels=@()  (Domain Admins is a SafePrincipal)
    .OUTPUTS
        [PSCustomObject] with Score ([int]) and Labels ([string[]]) properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string]$IdentityReferenceSID = '',

        [Parameter()]
        [string]$IdentityReferenceClass = ''
    )

    $sid = if ($null -ne $IdentityReferenceSID) { $IdentityReferenceSID } else { '' }

    # SafePrincipal check — early return, always +0, no further modifiers
    foreach ($pattern in $script:PrincipalDefinitionsBase.SafePrincipals) {
        if ($pattern -match '\$$') {
            if ($sid -match $pattern) {
                return [PSCustomObject]@{ Score = 0; Labels = [string[]]@() }
            }
        } else {
            if ($sid -eq $pattern) {
                return [PSCustomObject]@{ Score = 0; Labels = [string[]]@() }
            }
        }
    }

    # DangerousPrincipal check — +3 flat regardless of objectClass; group modifier never applies
    foreach ($pattern in $script:PrincipalDefinitionsBase.DangerousPrincipals) {
        if ($pattern -match '\$$') {
            if ($sid -match $pattern) {
                return [PSCustomObject]@{
                    Score  = 3
                    Labels = [string[]]@('UnsafePrincipal: +1', 'DangerousPrincipal: +2')
                }
            }
        } else {
            if ($sid -eq $pattern) {
                return [PSCustomObject]@{
                    Score  = 3
                    Labels = [string[]]@('UnsafePrincipal: +1', 'DangerousPrincipal: +2')
                }
            }
        }
    }

    # Unsafe non-dangerous principal — accumulate UnsafePrincipal + optional UnsafeGroup
    $score  = 1
    $labels = [System.Collections.Generic.List[string]]::new()
    $labels.Add('UnsafePrincipal: +1')

    if ($IdentityReferenceClass -eq 'group') {
        $score += 1
        $labels.Add('UnsafeGroup: +1')
    }

    return [PSCustomObject]@{ Score = $score; Labels = [string[]]$labels }
}
