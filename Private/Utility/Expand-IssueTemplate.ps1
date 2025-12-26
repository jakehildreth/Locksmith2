function Expand-IssueTemplate {
    <#
    .SYNOPSIS
        Expands Issue, Fix, and Revert templates with variable substitution.

    .DESCRIPTION
        Handles the common pattern of joining array templates and replacing 
        variable placeholders with actual values. Supports $(VariableName) syntax.

    .PARAMETER Config
        The ESC configuration hashtable containing IssueTemplate, FixTemplate, and RevertTemplate.

    .PARAMETER Variables
        A hashtable of variable names and their replacement values.
        Example: @{ TemplateName = 'User'; Owner = 'DOMAIN\Admin' }

    .PARAMETER IssueTemplate
        Optional override for the IssueTemplate. If provided, uses this instead of Config.IssueTemplate.

    .EXAMPLE
        $templates = Expand-IssueTemplate -Config $config -Variables @{
            TemplateName = 'User'
            IdentityReference = 'DOMAIN\Users'
            DistinguishedName = 'CN=User,CN=Certificate Templates,...'
        }
        # Returns: @{ Issue = '...'; Fix = '...'; Revert = '...' }

    .OUTPUTS
        [hashtable] A hashtable with Issue, Fix, and Revert expanded strings.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Config,

        [Parameter(Mandatory)]
        [hashtable]$Variables,

        [string[]]$IssueTemplate
    )

    # Use provided IssueTemplate or get from config
    $issueSource = if ($IssueTemplate) { $IssueTemplate } else { $Config.IssueTemplate }

    # Join arrays into single strings
    $issue = if ($issueSource -is [array]) {
        $issueSource -join ''
    } else {
        $issueSource
    }

    $fix = if ($Config.FixTemplate -is [array]) {
        $Config.FixTemplate -join "`n"
    } else {
        $Config.FixTemplate
    }

    $revert = if ($Config.RevertTemplate -is [array]) {
        $Config.RevertTemplate -join "`n"
    } else {
        $Config.RevertTemplate
    }

    # Expand variables in all templates
    foreach ($key in $Variables.Keys) {
        $pattern = "`$(`$key)"
        $escapedPattern = [regex]::Escape($pattern)
        $value = $Variables[$key]
        
        if ($null -eq $value) { $value = '' }
        
        $issue = $issue -replace $escapedPattern, $value
        $fix = $fix -replace $escapedPattern, $value
        $revert = $revert -replace $escapedPattern, $value
    }

    return @{
        Issue  = $issue
        Fix    = $fix
        Revert = $revert
    }
}
