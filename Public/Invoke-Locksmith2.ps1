function Invoke-Locksmith2 {
    <#
        .SYNOPSIS
        Performs comprehensive AD CS security audit scanning for known ESC vulnerabilities.

        .DESCRIPTION
        Invoke-Locksmith2 audits Active Directory Certificate Services (AD CS) infrastructure
        for security misconfigurations documented as ESC (Escalation) techniques. It scans:
        
        - Certificate templates (ESC1, ESC2, ESC3, ESC4, ESC9)
        - Certification Authorities (ESC6, ESC7a, ESC7m, ESC11, ESC16)
        - PKI container objects (ESC5)
        
        The function initializes four module-level stores:
        - PrincipalStore: Caches resolved SIDs and NTAccount principals
        - AdcsObjectStore: Stores all AD CS objects (templates, CAs, OIDs, etc.)
        - DomainStore: Caches domain information
        - IssueStore: Collects discovered vulnerabilities by technique
        
        Results are returned as structured LS2Issue objects containing vulnerability details,
        affected principals, and PowerShell remediation scripts.

        .PARAMETER Forest
        Fully qualified domain name of the forest/domain/domain controller to audit.
        If not specified, prompts interactively for the target forest.

        .PARAMETER Credential
        PSCredential object for authenticating to the target forest.
        If not specified, prompts interactively for username and password.
        Username should be in NTAccount format (DOMAIN\username).

        .PARAMETER SkipVersionCheck
        Skips checking for module updates from PowerShell Gallery.
        Use when running in air-gapped environments or to speed up execution.

        .PARAMETER SkipPowerShellCheck
        Skips validation and remediation of PowerShell environment settings.
        Use if you've already validated PowerShell profile and encoding settings.

        .PARAMETER Mode
        Specifies the output mode for displaying scan results.
        If not specified, returns LS2Issue objects to the pipeline without formatting.
        - Mode 0: Identify issues, output to console in table format
        - Mode 1: Identify issues and fixes, output to console in list format

        .PARAMETER SkipForestCheck
        Reserved for future use. Currently not implemented.

        .PARAMETER ExpandGroups
        Expands issues where the IdentityReference is a group into individual issues
        for each direct member of the group. This allows attribution of vulnerabilities
        to individual users rather than just showing group permissions.

        .PARAMETER Rescan
        Forces a fresh vulnerability scan even if IssueStore is already populated.
        Clears and regenerates the IssueStore with current AD CS configuration.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        Hashtable
        Returns four hashtables:
        - PrincipalStore: All resolved principals by SID
        - DomainStore: All domains in the audited forest
        - AdcsObjectStore: All AD CS objects
        - IssueStore: All discovered vulnerabilities grouped by technique

        .EXAMPLE
        Invoke-Locksmith2
        
        Runs interactive audit and returns LS2Issue objects to the pipeline.

        .EXAMPLE
        $cred = Get-Credential CONTOSO\admin
        Invoke-Locksmith2 -Forest 'dc01.contoso.com' -Credential $cred
        
        Audits contoso.com forest and returns LS2Issue objects to the pipeline.

        .EXAMPLE
        Invoke-Locksmith2 -Forest 'contoso.com' -Credential $cred -SkipPowerShellCheck
        
        Runs audit skipping PowerShell environment validation.

        .EXAMPLE
        Invoke-Locksmith2 -Mode 0
        
        Runs audit and displays results in table format (default behavior).

        .EXAMPLE
        Invoke-Locksmith2 -Mode 1
        
        Runs audit and displays results in list format with fix scripts.

        .EXAMPLE
        Invoke-Locksmith2 -ExpandGroups
        
        Runs audit and expands group issues into individual per-member issues.

        .LINK
        https://github.com/jakehildreth/Locksmith2

        .LINK
        Find-LS2VulnerableCA

        .LINK
        Find-LS2VulnerableTemplate

        .LINK
        Find-LS2VulnerableObject

        .LINK
        Get-LS2Stores

        .NOTES
        Author: Jake Hildreth (@jakehildreth)
        Requires PowerShell 5.1 or later
        Requires appropriate AD permissions to read Public Key Services container
    #>
    [CmdletBinding()]
    param (
        [string]$Forest,
        [System.Management.Automation.PSCredential]$Credential,
        [ValidateSet(0, 1)]
        [Nullable[int]]$Mode,
        [switch]$SkipVersionCheck,
        [switch]$SkipPowerShellCheck,
        [switch]$SkipForestCheck,
        [switch]$ExpandGroups,
        [switch]$Rescan
    )

    #requires -Version 5.1

    if (-not $SkipPowerShellCheck) {
        Test-PowerShellEnvironment | Repair-PowerShellEnvironment | Out-Null
    }

    foreach ($depName in @('PSWriteHTML', 'PSCertutil')) {
        $depRoot = Join-Path $PSScriptRoot "Modules\$depName"
        if (Test-Path $depRoot) {
            $depVer = (Get-ChildItem $depRoot | Sort-Object Name -Descending | Select-Object -First 1).Name
            Import-Module (Join-Path $depRoot "$depVer\$depName.psm1") -Force
        }
    }

    Write-Verbose "Starting Locksmith2 AD CS security audit..."

    # Reset credential-resolved flag so each run re-evaluates context
    $script:CredentialResolved = $false

    # Resolve connection context - auto-detects forest and credential if not supplied at CLI
    $ctxParams = @{}
    if ($PSBoundParameters.ContainsKey('Forest')) { $ctxParams['Forest'] = $Forest }
    if ($PSBoundParameters.ContainsKey('Credential')) { $ctxParams['Credential'] = $Credential }
    $ctx = Resolve-LS2ConnectionContext @ctxParams

    if (-not $ctx) {
        Write-Error 'Failed to resolve connection context. Supply -Forest and -Credential explicitly.'
        return
    }

    Write-Verbose "Connection context resolved: Forest=$($ctx.Forest), Method=$($ctx.Method)"

    if (Test-IsInteractiveSession) {
        $rawUser = if ($ctx.Credential) { $ctx.Credential.UserName } else { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
        $userDisplay = if ($rawUser -match '^([^\\]+)\\(.+)$') { "$($Matches[1].ToUpper())\$($Matches[2])" } else { $rawUser }
        Write-Host ''
        Write-Host 'Connection Context' -ForegroundColor Cyan
        Write-Host "  Forest   : $($ctx.Forest)"
        Write-Host "  User     : $userDisplay"
        Write-Host "  Computer : $($env:USERDOMAIN.ToUpper())\$($env:COMPUTERNAME.ToUpper())"
        Write-Host "  Method   : $($ctx.Method)"
        Write-Host ''
        $confirm = Read-Choice -Question 'Proceed with scan?' -Options @('y', 'n') -Default 'y'
        if ($confirm -ne 'y') {
            Write-Host 'Scan cancelled.' -ForegroundColor Yellow
            return
        }
        Write-Host ''
    }

    $initParams = @{
        Forest     = $ctx.Forest
        Credential = $ctx.Credential
    }
    if ($Rescan) {
        $initParams['Rescan'] = $true
    }

    $initResult = Initialize-LS2Scan @initParams
        
    if (-not $initResult) {
        Write-Error "Failed to initialize scan. Verify credentials and forest connectivity."
        return
    }
        
    Write-Verbose "`nScan complete. Issue summary:"
    $techniques = @(
        'ESC1', 'ESC2', 'ESC3c1', 'ESC3c2', 'ESC4a', 'ESC4o',
        'ESC5a', 'ESC5o', 'ESC6', 'ESC7a', 'ESC7m', 'ESC8', 'ESC9', 'ESC11', 'ESC13', 'ESC15', 'ESC16',
        'Auditing', 'SchemaV1'
    )

    foreach ($technique in $techniques) {
        $issueCount = Get-IssueCount -Technique $technique
        Write-Verbose "  $($technique): $issueCount issue(s)"
    }

    # Get all flattened issues
    $allIssues = Get-FlattenedIssues
        
    # Expand groups if requested
    if ($ExpandGroups) {
        Write-Verbose "Expanding group memberships into individual issues..."
        $allIssues = $allIssues | ForEach-Object { Expand-IssueByGroup $_ }
        Write-Verbose "Expansion complete. Total issues: $($allIssues.Count)"
    }
        
    # Output based on whether Mode was specified
    if ($PSBoundParameters.ContainsKey('Mode')) {
        # Display issues in console using specified mode
        Show-IssueReport -Issues $allIssues -Mode $Mode
    } else {
        # Return LS2Issue objects to pipeline
        $allIssues
    }
}
