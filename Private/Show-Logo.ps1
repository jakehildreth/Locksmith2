function Show-Logo {
    param (
        [string]$Version = (Get-Date -Format yyyy.M.d.Hmm),
        [int]$padpad = 11,
        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkRed')]
        [string]$ForegroundColor,
        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkRed')]
        [string]$BackgroundColor
    )

    $safeColors = @(
        'Black',
        'DarkBlue',
        'DarkGreen',
        'DarkRed'
    )

    while ($ForegroundColor -eq $BackgroundColor) {
        $ForegroundColor = $safeColors | Get-Random
        $BackgroundColor = $safeColors | Get-Random
    }

    Write-Host
    $logo = @(
        '█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█████████',
        '█ ██     ▄████▄ ▄█████ ██ ▄█▀ ▄█████ ██▄  ▄██ ██ ██████ ██  ██ ██    ▀██',
        '█ ██     ██  ██ ██     ████   ▀▀▀▄▄▄ ██ ▀▀ ██ ██   ██   ██████ ███▀  ▄██',
        '█ ██████ ▀████▀ ▀█████ ██ ▀█▄ █████▀ ██    ██ ██   ██   ██  ██ ██   ▀▀██',
        '█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█████████'
    )

    $logo | ForEach-Object {
        Write-Host $_ -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor -NoNewline; Write-Host
    }
    
    # Right-align version string, ending 10 characters before the end
    $logoWidth = ($logo -split "`n")[0].Length
    $padding = [Math]::Max(0, $logoWidth - $Version.Length - $padpad)
    $rightAlignedVersion = (' ' * $padding) + 'v' + $Version + (' ' * ($padpad - 1))
    
    Write-Host $rightAlignedVersion -ForegroundColor $ForegroundColor
}