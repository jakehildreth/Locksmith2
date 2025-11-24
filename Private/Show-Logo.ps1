function Show-Logo {
    <#
        .SYNOPSIS
        Displays the Locksmith 2 ASCII logo with version and copyright information.

        .DESCRIPTION
        Renders the Locksmith 2 ASCII art logo with configurable foreground and background colors.
        Displays a subtitle line containing copyright (Gilmour Ltd), URL (https://locksmith.ad),
        and version information, evenly spaced across the logo width.
        
        The foreground color defaults to a random ConsoleColor, while the background defaults to Black.
        If the foreground and background colors are the same, the foreground is automatically randomized
        to ensure readability.

        .PARAMETER Version
        The version string to display. Defaults to current date/time in yyyy.M.d.Hmm format.

        .PARAMETER ForegroundColor
        The foreground color for the logo. Accepts any System.ConsoleColor value with tab completion.
        Defaults to a random color.

        .PARAMETER BackgroundColor
        The background color for the logo. Accepts any System.ConsoleColor value with tab completion.
        Defaults to Black.

        .INPUTS
        None

        .OUTPUTS
        None
        Displays the logo and subtitle to the console.

        .EXAMPLE
        Show-Logo
        Displays the logo with a random foreground color, black background, and current version/timestamp.

        .EXAMPLE
        Show-Logo -Version '2025.11.24.0800'
        Displays the logo with a specific version string.

        .EXAMPLE
        Show-Logo -ForegroundColor Green -BackgroundColor DarkBlue
        Displays the logo with specific colors.

        .EXAMPLE
        Show-Logo -ForegroundColor Cyan
        Displays the logo with cyan text on black background.

        .NOTES
        The function uses UTF-8 block characters for the logo border and requires proper console encoding.
        All System.ConsoleColor values are supported with automatic tab completion.
    #>
    [CmdletBinding()]
    param (
        [string]$Version = (Get-Date -Format yyyy.M.d.Hmm),
        [System.ConsoleColor]$ForegroundColor = ([enum]::GetValues([System.ConsoleColor]) | Get-Random),
        [System.ConsoleColor]$BackgroundColor = 'Black'
    )
    
    $author = 'Jake Hildreth'
    $by = "(c) $(Get-Date -Format yyyy) $author"
    $url = 'https://locksmith.ad'

    while ($ForegroundColor -eq $BackgroundColor) {
        $ForegroundColor = [enum]::GetValues([System.ConsoleColor]) | Get-Random
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
    
    $logoWidth = $logo[0].Length
    $versionString = "v$Version"
    $subtitleWidth = $by.Length + $url.Length + $versionString.Length
    $paddingTotal = $logoWidth - $subtitleWidth
    $padding1 = [Math]::Floor($paddingTotal / 2)
    $padding2 = $paddingTotal - $padding1
    $subtitle = $by + (' ' * $padding1) + $url + (' ' * $padding2) + $versionString
    
    Write-Host $subtitle -ForegroundColor $ForegroundColor
}