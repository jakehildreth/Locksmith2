function Find-ESC1 {
    <#
    .SYNOPSIS
        Identifies AD CS certificate templates vulnerable to ESC1 attack.

    .DESCRIPTION
        ESC1 occurs when a certificate template allows a Subject Alternative Name (SAN) to be specified
        during enrollment, has an authentication EKU, does not require manager approval or authorized
        signatures, and allows enrollment by low-privilege or dangerous principals.

        This function queries the AdcsObjectStore for vulnerable templates and checks their permissions
        to identify which principals can exploit the misconfiguration.

    .OUTPUTS
        PSCustomObject[] representing ESC1 issues with properties:
        - Forest: Forest name
        - Name: Template name
        - DistinguishedName: Template DN
        - IdentityReference: Principal that can exploit
        - IdentityReferenceSID: SID of the principal
        - ActiveDirectoryRights: Rights the principal has
        - Enabled: Whether template is enabled on any CA
        - EnabledOn: List of CAs where template is enabled
        - Issue: Description of the vulnerability
        - Fix: PowerShell script to remediate
        - Revert: PowerShell script to undo remediation
        - Technique: 'ESC1'

    .EXAMPLE
        Find-ESC1

    .NOTES
        Stores results in $script:IssueStore['ESC1']
        Queries $script:AdcsObjectStore for template data
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Scanning for ESC1: Misconfigured Certificate Templates..."

    # Query AdcsObjectStore for vulnerable templates
    $VulnerableTemplates = $script:AdcsObjectStore.Values | Where-Object {
        $_.IsCertificateTemplate() -and
        $_.SANAllowed -and
        $_.AuthenticationEKUExist -and
        $_.ManagerApprovalNotRequired -and
        $_.AuthorizedSignatureNotRequired
    }

    Write-Verbose "Found $($VulnerableTemplates.Count) template(s) with ESC1-vulnerable configuration"

    $issueCount = 0

    foreach ($template in $VulnerableTemplates) {
        Write-Verbose "  Checking enrollees on template: $($template.Name)"

        # Get the list of dangerous and low-privilege enrollees (pre-calculated by Set-* functions)
        $dangerousEnrollees = @($template.DangerousEnrollee)
        $lowPrivilegeEnrollees = @($template.LowPrivilegeEnrollee)
        $problematicEnrollees = @($dangerousEnrollees + $lowPrivilegeEnrollees | Select-Object -Unique)

        if ($problematicEnrollees.Count -eq 0) {
            Write-Verbose "    No dangerous or low-privilege enrollees found"
            continue
        }

        Write-Verbose "    Found $($problematicEnrollees.Count) problematic enrollee(s)"

        # Check ObjectSecurity for ACE details
        if (-not $template.ObjectSecurity) {
            Write-Verbose "    No ObjectSecurity available for template: $($template.Name)"
            continue
        }

        # For each problematic enrollee, find their ACE and create an issue
        foreach ($enrolleeSid in $problematicEnrollees) {
            # Find the ACE for this SID
            $ace = $template.ObjectSecurity.Access | Where-Object {
                $aceSid = ($_.IdentityReference | Convert-IdentityReferenceToSid).Value
                $aceSid -eq $enrolleeSid
            } | Select-Object -First 1

            if (-not $ace) {
                Write-Verbose "    Could not find ACE for SID: $enrolleeSid"
                continue
            }

            Write-Verbose "    VULNERABLE: $($ace.IdentityReference) ($enrolleeSid) has enrollment rights"

            # Get domain/forest name from DN
            $forestName = if ($template.distinguishedName -match 'DC=([^,]+)') {
                $template.distinguishedName -replace '^.*?DC=(.*)$', '$1' -replace ',DC=', '.'
            } else {
                'Unknown'
            }

            # Create LS2Issue object
            $issue = [LS2Issue]@{
                Technique             = 'ESC1'
                Forest                = $forestName
                Name                  = $template.Name
                DistinguishedName     = $template.distinguishedName
                IdentityReference     = $ace.IdentityReference
                IdentityReferenceSID  = $enrolleeSid
                ActiveDirectoryRights = $ace.ActiveDirectoryRights
                Enabled               = $template.Enabled
                EnabledOn             = $template.EnabledOn
                Issue                 = @"
$($ace.IdentityReference) can provide a Subject Alternative Name (SAN) while
enrolling in this Client Authentication template, and enrollment does not require
Manager Approval.

The resultant certificate can be used by an attacker to authenticate as any
principal listed in the SAN up to and including Domain Admins, Enterprise Admins,
or Domain Controllers.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
                Fix                   = @"
# Enable Manager Approval
`$Object = '$($template.distinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}
"@
                Revert                = @"
# Disable Manager Approval
`$Object = '$($template.distinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}
"@
            }

            # Initialize IssueStore structure if needed
            $dn = $template.distinguishedName
            if (-not $script:IssueStore.ContainsKey($dn)) {
                $script:IssueStore[$dn] = @{}
            }
            if (-not $script:IssueStore[$dn].ContainsKey('ESC1')) {
                $script:IssueStore[$dn]['ESC1'] = @()
            }
            
            # Store in IssueStore
            $script:IssueStore[$dn]['ESC1'] += $issue
            $issueCount++

            # Output to pipeline
            $issue
        }
    }

    Write-Verbose "ESC1 scan complete. Found $issueCount issue(s)."
}
