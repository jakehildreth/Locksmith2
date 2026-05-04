#requires -Version 5.1
$config = New-PesterConfiguration
$config.Run.Path = './Tests'
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
$config.Output.StackTraceVerbosity = 'Filtered'
$config.Filter.Tag = @('Unit')
$config.Filter.ExcludeTag = @('Integration')
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = @('./Classes/*.ps1', './Private/**/*.ps1', './Public/*.ps1')
$config.CodeCoverage.OutputFormat = 'JaCoCo'
$config.CodeCoverage.OutputPath = './Tests/coverage.xml'
$config.TestResult.Enabled = $true
$config.TestResult.OutputFormat = 'NUnitXml'
$config.TestResult.OutputPath = './Tests/testResults.xml'
$config.Should.ErrorAction = 'Continue'
return $config
