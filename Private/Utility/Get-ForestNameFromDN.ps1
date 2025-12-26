function Get-ForestNameFromDN {
    <#
    .SYNOPSIS
        Extracts the forest/domain name from a Distinguished Name.

    .DESCRIPTION
        Parses a Distinguished Name to extract the domain DNS name by
        converting DC= components into dot-separated domain format.
        
        Example: CN=User,CN=Users,DC=contoso,DC=com -> contoso.com

    .PARAMETER DistinguishedName
        The Distinguished Name to parse.

    .EXAMPLE
        Get-ForestNameFromDN -DistinguishedName 'CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
        Returns: contoso.com

    .OUTPUTS
        [string] The DNS domain name extracted from the DN, or 'Unknown' if parsing fails.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$DistinguishedName
    )

    process {
        if ($DistinguishedName -match 'DC=([^,]+)') {
            return $DistinguishedName -replace '^.*?DC=(.*)$', '$1' -replace ',DC=', '.'
        }
        return 'Unknown'
    }
}
