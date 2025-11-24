function Show-Logo {
    <#
        .SYNOPSIS
        Displays the Locksmith 2 ASCII logo with version and copyright information.

        .DESCRIPTION
        Renders the Locksmith 2 ASCII art logo with configurable foreground and background colors.
        Displays a subtitle line containing copyright, URL, and version information.
        
        If colors are not specified, random colors are selected ensuring the foreground and
        background colors are different for readability.

        .PARAMETER Version
        The version string to display. Defaults to current date/time in yyyy.M.d.Hmm format.

        .PARAMETER ForegroundColor
        The foreground color for the logo. Must be one of: Black, DarkBlue, DarkGreen, DarkRed.
        If not specified, a random safe color will be chosen.

        .PARAMETER BackgroundColor
        The background color for the logo. Must be one of: Black, DarkBlue, DarkGreen, DarkRed.
        If not specified, a random safe color will be chosen (different from foreground).

        .INPUTS
        None

        .OUTPUTS
        None
        Displays the logo to the console.

        .EXAMPLE
        Show-Logo
        Displays the logo with random colors and current date/time version.

        .EXAMPLE
        Show-Logo -Version '2025.11.23.0700'
        Displays the logo with a specific version string.

        .EXAMPLE
        Show-Logo -ForegroundColor DarkGreen -BackgroundColor Black
        Displays the logo with specific colors.

        .NOTES
        The function automatically ensures UTF-8 encoding for proper display of block characters.
        Safe colors are limited to those that display well in most terminal environments.
    #>
    [CmdletBinding()]
    param (
        [string]$Version = (Get-Date -Format yyyy.M.d.Hmm),
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
    
    $logoWidth = $logo[0].Length
    $author = 'Gilmour Ltd'
    $by = "(c) $(Get-Date -Format yyyy) $author"
    $url = 'https://locksmith.ad'
    $versionString = "v$Version"
    $subtitleWidth = $by.Length + $url.Length + $versionString.Length
    $paddingTotal = $logoWidth - $subtitleWidth
    $padding1 = [Math]::Floor($paddingTotal / 2)
    $padding2 = $paddingTotal - $padding1
    $subtitle = $by + (' ' * $padding1) + $url + (' ' * $padding2) + $versionString
    
    Write-Host $subtitle -ForegroundColor $ForegroundColor
}