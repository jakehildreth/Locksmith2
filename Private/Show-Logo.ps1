function Show-Logo {
    param (
        [string]$Version = (Get-Date -Format yyyy.M.d.Hmm),
        [int]$padpad = 11
    )
    Write-Host
    $logo = @"
█████████████████████████████▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█████████
█  █████▀    ▀█▀     █  █▀ ▄█ ▄█████ ██▄  ▄██ ██ ██████ ██  ██ ██    ▀██
█  █████  ██  █  █████    ███ ▀▀▀▄▄▄ ██ ▀▀ ██ ██   ██   ██████ ███▀  ▄██
█      █▄    ▄█▄     █  █▄ ▀█ █████▀ ██    ██ ██   ██   ██  ██ ██   ▀▀██
█████████████████████████████▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█████████
"@  
    Write-Host $logo -ForegroundColor DarkGray -BackgroundColor Black
    
    # Right-align version string, ending 10 characters before the end
    $logoWidth = ($logo -split "`n")[0].Length
    $padding = [Math]::Max(0, $logoWidth - $Version.Length - $padpad)
    $rightAlignedVersion = (' ' * $padding) + $Version + (' ' * $padpad)
    
    Write-Host $rightAlignedVersion -ForegroundColor DarkGray -BackgroundColor Black
}