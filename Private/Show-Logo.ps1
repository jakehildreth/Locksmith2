function Show-Logo {
    param (
        [string]$Version = (Get-Date -Format yyyy.M.d.Hmm),
        [int]$rightPad = 1,
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
    
    $logoWidth = ($logo -split "`n")[0].Length
    $by = "(c) $(Get-Date -Format yyyy) Jake Hildreth"
    $Url = 'https://locksmith.ad'
    $subtitleWidth = $by.Length + $Url.Length + $Version.Length + 1 # + 1 for the 'v' in the subtitle
    $paddingTotal = $logoWidth - $subtitleWidth
    $padding1 = [Math]::Floor($paddingTotal  / 2)
    $padding2 = $paddingTotal - $padding1
    $rightAlignedVersion = $by + (' ' * $padding1) + $Url + (' ' * $padding2) + 'v' + $Version
    
    Write-Host $rightAlignedVersion -ForegroundColor $ForegroundColor
}