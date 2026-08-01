#requires -Version 5.1
# Run integration tests against a real AD CS environment.
# Must be run from the module root.
#
# Example (supply params to skip prompts):
#   $cred = Get-Credential
#   & '.\Locksmith2.Pester.Integration.config.ps1' -Forest 'ad.contoso.com' -Credential $cred | Invoke-Pester -Configuration $_
#
param (
    [string]$Forest,
    [System.Management.Automation.PSCredential]$Credential
)

if (-not $Forest) {
    $Forest = Read-Host -Prompt 'Target AD forest DNS name'
}
if (-not $Credential) {
    $Credential = Get-Credential -Message "Credentials for '$Forest'"
}

$config = New-PesterConfiguration
$config.Run.Container = New-PesterContainer -Path './Tests' -Data @{
    IntegrationForest     = $Forest
    IntegrationCredential = $Credential
}
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
$config.Output.StackTraceVerbosity = 'Filtered'
$config.Filter.Tag = @('Integration')
$config.TestResult.Enabled = $true
$config.TestResult.OutputFormat = 'NUnitXml'
$config.TestResult.OutputPath = './Tests/testResults.Integration.xml'
$config.Should.ErrorAction = 'Continue'
return $config
