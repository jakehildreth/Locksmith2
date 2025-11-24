function Show-Logo {
    param (
        [string]$Version = (Get-Date -Format yyyy.M.d.Hmm),
        [int]$padpad = 11,
        [ValidateScript({ [enum]::GetValues([System.ConsoleColor]) -contains $_ })]
        [string]$ForegroundColor = 'DarkGray',
        [ValidateScript({ [enum]::GetValues([System.ConsoleColor]) -contains $_ })]
        [string]$BackgroundColor = 'Black'
    )

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
    $rightAlignedVersion = (' ' * $padding) + $Version + (' ' * $padpad)
    
    Write-Host $rightAlignedVersion -ForegroundColor $ForegroundColor
}