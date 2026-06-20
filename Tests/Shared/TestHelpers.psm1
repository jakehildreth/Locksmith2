#requires -Version 5.1
<#
.SYNOPSIS
    Shared test helpers for Locksmith2 Pester tests.

.DESCRIPTION
    Provides mock factory functions for LS2AdcsObject, LS2Issue, and LS2Principal,
    and a PSScriptAnalyzer helper. Import this module in BeforeAll blocks:

        Import-Module (Join-Path $ModuleRoot 'Tests\Shared\TestHelpers.psm1') -Force

.NOTES
    LS2AdcsObject and LS2Principal have AD-dependent constructors. Tests bypass them
    using GetUninitializedObject, which creates an instance without invoking any
    constructor. Properties are then set directly.

    Store resets ($script:IssueStore, etc.) are NOT abstracted here because helper
    functions cannot set $script: variables in Locksmith2's module scope.
    Inline the reset in each InModuleScope BeforeEach block.
#>

function New-MockLS2AdcsObject {
    <#
    .SYNOPSIS
        Creates an LS2AdcsObject without invoking the DirectoryEntry constructor.

    .PARAMETER Properties
        Hashtable of property overrides applied after defaults are set.

    .EXAMPLE
        $template = New-MockLS2AdcsObject
        $ca = New-MockLS2AdcsObject -Properties @{
            SchemaClassName = 'pKIEnrollmentService'
            objectClass     = @('top', 'pKIEnrollmentService')
            SANFlagEnabled  = $true
        }
    #>
    [CmdletBinding()]
    [OutputType([LS2AdcsObject])]
    param(
        [Parameter()]
        [hashtable]$Properties = @{}
    )

    $obj = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([LS2AdcsObject])

    # Defaults: a typical certificate template
    $obj.objectClass              = @('top', 'pKICertificateTemplate')
    $obj.SchemaClassName          = 'pKICertificateTemplate'
    $obj.distinguishedName        = 'CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
    $obj.name                     = 'TestTemplate'
    $obj.displayName              = $null
    $obj.cn                       = 'TestTemplate'
    $obj.Path                     = $null
    $obj.Owner                    = $null
    $obj.HasNonStandardOwner      = $null
    $obj.flags                    = $null
    $obj.pKIDefaultKeySpec        = $null
    $obj.pKIMaxIssuingDepth       = $null
    $obj.pKICriticalExtensions    = @()
    $obj.pKIExtendedKeyUsage      = @()
    $obj.CertificateNameFlag      = $null
    $obj.EnrollmentFlag           = $null
    $obj.PrivateKeyFlag           = $null
    $obj.RASignature              = $null
    $obj.RAApplicationPolicies    = @()
    $obj.TemplateSchemaVersion    = $null
    $obj.TemplateMinorRevision    = $null
    $obj.CertificatePolicy        = @()
    $obj.CertTemplateOID          = $null
    $obj.OIDToGroupLink           = $null
    $obj.certificateTemplates     = @()
    $obj.dNSHostName              = $null
    $obj.CAFullName               = $null
    $obj.CAAdministrators         = @()
    $obj.CertificateManagers      = @()
    $obj.DangerousCAAdministrator          = @()
    $obj.DangerousCAAdministratorNames     = @()
    $obj.LowPrivilegeCAAdministrator       = @()
    $obj.LowPrivilegeCAAdministratorNames  = @()
    $obj.DangerousCACertificateManager         = @()
    $obj.DangerousCACertificateManagerNames    = @()
    $obj.LowPrivilegeCACertificateManager      = @()
    $obj.LowPrivilegeCACertificateManagerNames = @()
    $obj.SANAllowed               = $null
    $obj.AuthenticationEKUExist   = $null
    $obj.AnyPurposeEKUExist       = $null
    $obj.EnrollmentAgentEKUExist  = $null
    $obj.NoSecurityExtension      = $null
    $obj.RequiresEnrollmentAgentSignature = $null
    $obj.DangerousEnrollee        = @()
    $obj.DangerousEnrolleeNames   = @()
    $obj.LowPrivilegeEnrollee     = @()
    $obj.LowPrivilegeEnrolleeNames = @()
    $obj.DangerousEditor          = @()
    $obj.DangerousEditorNames     = @()
    $obj.LowPrivilegeEditor       = @()
    $obj.LowPrivilegeEditorNames  = @()
    $obj.ManagerApprovalNotRequired     = $null
    $obj.AuthorizedSignatureNotRequired = $null
    $obj.Enabled                  = $null
    $obj.EnabledOn                = @()
    $obj.ComputerPrincipal        = $null
    $obj.RPCEncryptionNotRequired = $null
    $obj.EditFlags                = @()
    $obj.SANFlagEnabled           = $null
    $obj.InterfaceFlags           = @()
    $obj.AuditFilter              = $null
    $obj.AuditingIncomplete       = $false
    $obj.DisableExtensionList     = @()
    $obj.SecurityExtensionDisabled = $null
    $obj.HasLinkedGroupOIDPolicy  = $null
    $obj.LinkedGroupOIDPolicies   = @()

    foreach ($key in $Properties.Keys) {
        $obj.$key = $Properties[$key]
    }

    return $obj
}

function New-MockLS2Issue {
    <#
    .SYNOPSIS
        Creates an LS2Issue using the hashtable constructor, with sensible defaults.

    .PARAMETER Overrides
        Hashtable of property overrides applied on top of defaults.

    .EXAMPLE
        $issue = New-MockLS2Issue
        $caIssue = New-MockLS2Issue -Overrides @{ Technique = 'ESC6'; CAFullName = 'myserver\MyCA' }
    #>
    [CmdletBinding()]
    [OutputType([LS2Issue])]
    param(
        [Parameter()]
        [hashtable]$Overrides = @{}
    )

    $defaults = @{
        Technique         = 'ESC1'
        Forest            = 'contoso.com'
        Name              = 'TestTemplate'
        DistinguishedName = 'CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
        ObjectClass       = 'pKICertificateTemplate'
        Issue             = 'Test issue description.'
        Fix               = '# Fix script'
        Revert            = '# Revert script'
    }

    foreach ($key in $Overrides.Keys) {
        $defaults[$key] = $Overrides[$key]
    }

    return [LS2Issue]::new($defaults)
}

function New-MockLS2Principal {
    <#
    .SYNOPSIS
        Creates an LS2Principal without invoking the SearchResult constructor.

    .PARAMETER Properties
        Hashtable of property overrides applied after defaults are set.

    .EXAMPLE
        $principal = New-MockLS2Principal
        $group = New-MockLS2Principal -Properties @{ objectClass = 'group'; MemberCount = 5 }
    #>
    [CmdletBinding()]
    [OutputType([LS2Principal])]
    param(
        [Parameter()]
        [hashtable]$Properties = @{}
    )

    $obj = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([LS2Principal])

    $obj.distinguishedName  = 'CN=TestUser,CN=Users,DC=contoso,DC=com'
    $obj.objectSid          = 'S-1-5-21-1234567890-1234567890-1234567890-1001'
    $obj.sAMAccountName     = 'TestUser'
    $obj.objectClass        = 'user'
    $obj.displayName        = $null
    $obj.NTAccountName      = 'CONTOSO\TestUser'
    $obj.userPrincipalName  = $null
    $obj.memberOf           = @()
    $obj.MemberCount        = 0

    foreach ($key in $Properties.Keys) {
        $obj.$key = $Properties[$key]
    }

    return $obj
}

function Invoke-PSScriptAnalyzerCheck {
    <#
    .SYNOPSIS
        Runs PSScriptAnalyzer on a path. Returns empty array if PSSA is not installed.

    .PARAMETER Path
        Path to analyze. Passed to Invoke-ScriptAnalyzer -Path.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Get-Module -Name PSScriptAnalyzer -ListAvailable -ErrorAction SilentlyContinue)) {
        Write-Warning 'PSScriptAnalyzer is not installed — skipping static analysis checks.'
        return @()
    }

    return Invoke-ScriptAnalyzer -Path $Path -Recurse -Severity Warning, Error -ErrorAction SilentlyContinue
}

Export-ModuleMember -Function 'New-MockLS2AdcsObject', 'New-MockLS2Issue', 'New-MockLS2Principal', 'Invoke-PSScriptAnalyzerCheck'
