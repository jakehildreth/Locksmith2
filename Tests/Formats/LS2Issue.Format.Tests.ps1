#requires -Version 5.1
<#
.SYNOPSIS
    Tests for LS2Issue format view definitions (Summary/Detailed/Full detail levels).
#>
BeforeDiscovery {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:FormatFilePath = Join-Path $ModuleRoot 'LS2Issue.format.ps1xml'

    # Expected property lists per view (order matters)
    $script:ExpectedListViews = @(
        @{ ViewName = 'ESC1Detailed'; Properties = @('Name', 'Technique', 'ObjectClass', 'DistinguishedName', 'IdentityReference', 'IdentityReferenceClass', 'Enabled', 'EnabledOn', 'Issue') }
        @{ ViewName = 'ESC2Detailed'; Properties = @('Name', 'Technique', 'ObjectClass', 'DistinguishedName', 'IdentityReference', 'IdentityReferenceClass', 'Enabled', 'EnabledOn', 'Issue') }
        @{ ViewName = 'ESC3c1Detailed'; Properties = @('Name', 'Technique', 'ObjectClass', 'DistinguishedName', 'IdentityReference', 'IdentityReferenceClass', 'Enabled', 'EnabledOn', 'Issue') }
        @{ ViewName = 'ESC3c2Detailed'; Properties = @('Name', 'Technique', 'ObjectClass', 'DistinguishedName', 'IdentityReference', 'IdentityReferenceClass', 'Enabled', 'EnabledOn', 'Issue') }
        @{ ViewName = 'ESC9Detailed'; Properties = @('Name', 'Technique', 'ObjectClass', 'DistinguishedName', 'IdentityReference', 'IdentityReferenceClass', 'Enabled', 'EnabledOn', 'Issue') }
        @{ ViewName = 'ESC4aDetailed'; Properties = @('Name', 'Technique', 'ObjectClass', 'DistinguishedName', 'IdentityReference', 'IdentityReferenceClass', 'ActiveDirectoryRights', 'AceObjectTypeName', 'Enabled', 'EnabledOn', 'Issue') }
        @{ ViewName = 'ESC4oDetailed'; Properties = @('Name', 'Technique', 'ObjectClass', 'DistinguishedName', 'Owner', 'HasNonStandardOwner', 'Enabled', 'EnabledOn', 'Issue') }
        @{ ViewName = 'ESC5aDetailed'; Properties = @('Name', 'Technique', 'ObjectClass', 'DistinguishedName', 'IdentityReference', 'IdentityReferenceClass', 'ActiveDirectoryRights', 'AceObjectTypeName', 'Issue') }
        @{ ViewName = 'ESC5oDetailed'; Properties = @('Name', 'Technique', 'ObjectClass', 'DistinguishedName', 'Owner', 'HasNonStandardOwner', 'Issue') }
        @{ ViewName = 'ESC6Detailed'; Properties = @('Name', 'Technique', 'DistinguishedName', 'CAFullName', 'Issue') }
        @{ ViewName = 'ESC11Detailed'; Properties = @('Name', 'Technique', 'DistinguishedName', 'CAFullName', 'Issue') }
        @{ ViewName = 'ESC16Detailed'; Properties = @('Name', 'Technique', 'DistinguishedName', 'CAFullName', 'Issue') }
        @{ ViewName = 'ESC7aDetailed'; Properties = @('Name', 'Technique', 'DistinguishedName', 'CAFullName', 'IdentityReference', 'IdentityReferenceClass', 'ActiveDirectoryRights', 'Issue') }
        @{ ViewName = 'ESC7mDetailed'; Properties = @('Name', 'Technique', 'DistinguishedName', 'CAFullName', 'IdentityReference', 'IdentityReferenceClass', 'ActiveDirectoryRights', 'Issue') }
        @{ ViewName = 'Full'; Properties = @('Name', 'Technique', 'Forest', 'ObjectClass', 'DistinguishedName', 'IdentityReference', 'IdentityReferenceSID', 'IdentityReferenceClass', 'ActiveDirectoryRights', 'AceObjectTypeGUID', 'AceObjectTypeName', 'Enabled', 'EnabledOn', 'CAFullName', 'Owner', 'HasNonStandardOwner', 'MemberCount', 'Issue', 'Fix', 'Revert') }
    )
}

BeforeAll {
    $ModuleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:FormatFilePath = Join-Path $ModuleRoot 'LS2Issue.format.ps1xml'
    $ls2Manifest = if ($env:LS2_MODULE_ROOT) { Join-Path $env:LS2_MODULE_ROOT 'Locksmith2.psd1' } else { Join-Path $ModuleRoot 'Locksmith2.psd1' }
    Import-Module $ls2Manifest -Force -ErrorAction Stop

    $script:FormatXml = [xml](Get-Content -LiteralPath $script:FormatFilePath -Raw)

    # Helper: get a view node by name
    $script:GetView = {
        param([string]$Name)
        $script:FormatXml.Configuration.ViewDefinitions.View | Where-Object { $_.Name -eq $Name }
    }
}

Describe 'LS2Issue format file' -Tag 'Unit' {
    It 'is valid XML' {
        { [xml](Get-Content -LiteralPath $script:FormatFilePath -Raw) } | Should -Not -Throw
    }

    It 'targets the LS2Issue type in every view' {
        foreach ($view in $script:FormatXml.Configuration.ViewDefinitions.View) {
            $view.ViewSelectedBy.TypeName | Should -Be 'LS2Issue'
        }
    }

    It 'retains the Default table view first' {
        $firstView = @($script:FormatXml.Configuration.ViewDefinitions.View)[0]
        $firstView.Name | Should -Be 'Default'
        $firstView.TableControl | Should -Not -BeNullOrEmpty
    }
}

Describe 'Summary view' -Tag 'Unit' {
    BeforeAll {
        $script:SummaryView = & $script:GetView 'Summary'
    }

    It 'exists' {
        $script:SummaryView | Should -Not -BeNullOrEmpty
    }

    It 'is a table view' {
        $script:SummaryView.TableControl | Should -Not -BeNullOrEmpty
    }

    It 'shows exactly the summary columns in order' {
        $columns = @($script:SummaryView.TableControl.TableRowEntries.TableRowEntry.TableColumnItems.TableColumnItem.PropertyName)
        $columns | Should -Be @('Name', 'Technique', 'Issue', 'RiskName')
    }

    It 'labels RiskName as Severity' {
        $severityHeader = @($script:SummaryView.TableControl.TableHeaders.TableColumnHeader) |
            Where-Object { $_.Label -eq 'Severity' }
        $severityHeader | Should -Not -BeNullOrEmpty
    }
}

Describe 'Detailed and Full list views' -Tag 'Unit' {
    Context '<ViewName>' -ForEach $script:ExpectedListViews {
        BeforeAll {
            $script:View = & $script:GetView $ViewName
        }

        It 'exists' {
            $script:View | Should -Not -BeNullOrEmpty
        }

        It 'is a list view' {
            $script:View.ListControl | Should -Not -BeNullOrEmpty
        }

        It 'shows exactly the expected properties in order' {
            $items = @($script:View.ListControl.ListEntries.ListEntry.ListItems.ListItem.PropertyName)
            $items | Should -Be $Properties
        }
    }
}

Describe 'ESC7 role labeling' -Tag 'Unit' {
    It 'labels ActiveDirectoryRights as Role in <_>' -ForEach @('ESC7aDetailed', 'ESC7mDetailed') {
        $view = & $script:GetView $_
        $roleItem = @($view.ListControl.ListEntries.ListEntry.ListItems.ListItem) |
            Where-Object { $_.PropertyName -eq 'ActiveDirectoryRights' }
        $roleItem.Label | Should -Be 'Role'
    }
}

Describe 'View rendering' -Tag 'Unit' {
        BeforeAll {
            $script:templateIssue = [LS2Issue]@{
                Technique              = 'ESC1'
                Forest                 = 'contoso.com'
                Name                   = 'VulnTemplate'
                DistinguishedName      = 'CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                ObjectClass            = 'pKICertificateTemplate'
                IdentityReference      = 'CONTOSO\Domain Users'
                IdentityReferenceClass = 'group'
                Enabled                = $true
                EnabledOn              = @('CA01')
                Issue                  = 'Test issue text'
                Fix                    = 'Test fix script'
                Revert                 = 'Test revert script'
            }
            $script:caRoleIssue = [LS2Issue]@{
                Technique              = 'ESC7a'
                Forest                 = 'contoso.com'
                Name                   = 'TestCA'
                DistinguishedName      = 'CN=TestCA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                ObjectClass            = 'pKIEnrollmentService'
                CAFullName             = 'ca01.contoso.com\TestCA'
                IdentityReference      = 'CONTOSO\Help Desk'
                IdentityReferenceClass = 'group'
                ActiveDirectoryRights  = 'Administrators'
                Issue                  = 'Test CA role issue'
            }
        }

        It 'renders ESC1Detailed with enrollee properties only' {
            $out = $script:templateIssue | Format-List -View 'ESC1Detailed' | Out-String
            $out | Should -Match 'IdentityReference'
            $out | Should -Match '(?m)^Enabled'
            $out | Should -Not -Match '(?m)^ActiveDirectoryRights'
            $out | Should -Not -Match '(?m)^Fix'
        }

        It 'renders ESC7aDetailed with Role label' {
            $out = $script:caRoleIssue | Format-List -View 'ESC7aDetailed' | Out-String
            $out | Should -Match '(?m)^Role\s+:'
            $out | Should -Match 'Administrators'
        }

        It 'renders Full with remediation scripts' {
            $out = $script:templateIssue | Format-List -View 'Full' | Out-String
            $out | Should -Match '(?m)^Fix'
            $out | Should -Match '(?m)^Revert'
            $out | Should -Match '(?m)^IdentityReferenceSID'
        }

        It 'renders Summary as a table' {
            $out = $script:templateIssue | Format-Table -View 'Summary' | Out-String
            $out | Should -Match 'Technique'
            $out | Should -Match 'VulnTemplate'
        }
    }