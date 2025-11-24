function Convert-IdentityReferenceToSid {
    <#
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Principal
    )

    if ($Principal.GetType().UnderlyingSystemType -eq [System.Security.Principal.NTAccount]) {
        $Principal.Translate([System.Security.Principal.SecurityIdentifier])
    } else {
        $Principal
    }
}
