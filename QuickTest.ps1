Set-Location ~\Documents\Locksmith2\
Import-Module .\Locksmith2.psd1 -Force

# Start performance measurement
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# $Credential = New-Credential -User 'adcs.goat\Administrator'
$Forest = 'adcs.goat'
$results = Invoke-Locksmith2 -Forest $Forest -Credential $Credential -Verbose -SkipPowerShellCheck
$stores = Get-Locksmith2Stores
$stores.PrincipalStore.Values

# Stop performance measurement and display results
$stopwatch.Stop()
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Performance Metrics:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Execution Time: $($stopwatch.Elapsed.TotalSeconds.ToString('F3')) seconds" -ForegroundColor Green
Write-Host "  Minutes: $($stopwatch.Elapsed.Minutes)" -ForegroundColor Gray
Write-Host "  Seconds: $($stopwatch.Elapsed.Seconds)" -ForegroundColor Gray
Write-Host "  Milliseconds: $($stopwatch.Elapsed.Milliseconds)" -ForegroundColor Gray
Write-Host "========================================`n" -ForegroundColor Cyan