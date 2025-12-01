Set-Location ~\Documents\Locksmith2\
Import-Module .\Locksmith2.psd1 -Force

if (-not $Credential) {
    $Credential = New-Credential -User 'adcs.goat\Administrator'
}
$Forest = 'adcs.goat'

# Start performance measurement
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Run main function
$results = Invoke-Locksmith2 -Forest $Forest -Credential $Credential -Verbose -SkipPowerShellCheck

# Stop performance measurement and display results
$stopwatch.Stop()

# Get previous run time for this PS version
$logPath = "~\Documents\Locksmith2\performance.log"
$currentVersion = $PSVersionTable.PSVersion.ToString()
$previousRuns = Get-Content -Path $logPath -ErrorAction SilentlyContinue | Where-Object { $_ -match "PS $([regex]::Escape($currentVersion))" }
$previousTime = $null
$timeDiff = $null

if ($previousRuns) {
    $lastRun = $previousRuns | Select-Object -Last 1
    if ($lastRun -match "Execution Time: ([\d.]+) seconds") {
        $previousTime = [double]$Matches[1]
        $timeDiff = $stopwatch.Elapsed.TotalSeconds - $previousTime
    }
}

# Log execution time to file
$logEntry = "[{0:yyyy-MM-dd HH:mm:ss}] PS {1} | Execution Time: {2:F3} seconds" -f (Get-Date), $PSVersionTable.PSVersion, $stopwatch.Elapsed.TotalSeconds
$logEntry | Add-Content -Path $logPath

$diffText = if ($null -ne $timeDiff) {
    $diffSign = if ($timeDiff -gt 0) { "+" } else { "" }
    $diffColor = if ($timeDiff -lt 0) { "Green" } else { "Red" }
    " ($diffSign$($timeDiff.ToString('F3'))s vs previous)"
} else {
    " (first run)"
}

$performanceOutput = @"

========================================
Performance Metrics:
========================================
Total Execution Time: $($stopwatch.Elapsed.TotalSeconds.ToString('F3')) seconds$diffText
  Minutes: $($stopwatch.Elapsed.Minutes)
  Seconds: $($stopwatch.Elapsed.Seconds)
  Milliseconds: $($stopwatch.Elapsed.Milliseconds)
========================================

"@
Write-Host $performanceOutput
