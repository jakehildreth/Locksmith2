function Show-Logo {
    <#
        .SYNOPSIS
        Displays the Locksmith 2 ASCII logo with version and copyright information.

        .DESCRIPTION
        Renders the Locksmith 2 ASCII art logo with configurable foreground and background colors using ANSI escape codes.
        Displays a subtitle line containing copyright, URL, and version information, evenly spaced across the logo width.
        
        The function uses true RGB colors via ANSI escape sequences, bypassing terminal color scheme remapping.
        In Windows PowerShell 5.1, ANSI support requires Windows 10 1511+ with conhost or Windows Terminal.

        .PARAMETER Version
        The version string to display. Defaults to current date/time in yyyy.M.d.Hmm format.

        .PARAMETER ForegroundRGB
        The foreground color as an RGB array [R, G, B]. Defaults to a random bright color.

        .PARAMETER BackgroundRGB
        The background color as an RGB array [R, G, B]. Defaults to true black [0, 0, 0].

        .PARAMETER FullWidth
        When specified, extends the logo to fill the entire terminal width with colored blocks.

        .INPUTS
        None

        .OUTPUTS
        None
        Displays the logo and subtitle to the console.

        .EXAMPLE
        Show-Logo
        Displays the logo with a random foreground color and black background.

        .EXAMPLE
        Show-Logo -Version '2025.11.24.0800'
        Displays the logo with a specific version string.

        .EXAMPLE
        Show-Logo -ForegroundRGB @(0, 255, 0) -BackgroundRGB @(0, 0, 128)
        Displays the logo with green text on dark blue background.

        .EXAMPLE
        Show-Logo -FullWidth
        Displays the logo extended to full terminal width with colored block padding.

        .NOTES
        The function uses UTF-8 block characters and ANSI escape codes.
        Requires ANSI/VT100 support in the terminal (Windows 10 1511+, Windows Terminal, or PowerShell 7+).
    #>
    [CmdletBinding()]
    param (
        [string]$Version = (Get-Date -Format yyyy.M.d.Hmm),
        [ValidateCount(3, 3)]
        [ValidateRange(0, 255)]
        [int[]]$ForegroundRGB,
        [ValidateCount(3, 3)]
        [ValidateRange(0, 255)]
        [int[]]$BackgroundRGB = @(0, 0, 0),
        [switch]$FullWidth
    )
    
    # Generate random bright color if not specified
    if (-not $ForegroundRGB) {
        $ForegroundRGB = @(
            (Get-Random -Minimum 100 -Maximum 255),
            (Get-Random -Minimum 100 -Maximum 255),
            (Get-Random -Minimum 100 -Maximum 255)
        )
    }
    
    # Ensure foreground and background are different
    while (($ForegroundRGB[0] -eq $BackgroundRGB[0]) -and 
           ($ForegroundRGB[1] -eq $BackgroundRGB[1]) -and 
           ($ForegroundRGB[2] -eq $BackgroundRGB[2])) {
        $ForegroundRGB = @(
            (Get-Random -Minimum 100 -Maximum 255),
            (Get-Random -Minimum 100 -Maximum 255),
            (Get-Random -Minimum 100 -Maximum 255)
        )
    }
    
    $author = 'Jake Hildreth'
    $by = "█ (c) $(Get-Date -Format yyyy) $author"
    $url = 'https://locksmith.ad'

    # ANSI escape sequences for RGB colors
    $fgColor = "`e[38;2;$($ForegroundRGB[0]);$($ForegroundRGB[1]);$($ForegroundRGB[2])m"
    $bgColor = "`e[48;2;$($BackgroundRGB[0]);$($BackgroundRGB[1]);$($BackgroundRGB[2])m"
    $reset = "`e[0m"

    Write-Host
    $logo = @(
        '█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█████████',
        '█ ██     ▄████▄ ▄█████ ██ ▄█▀ ▄█████ ██▄  ▄██ ██ ██████ ██  ██ ██    ▀██',
        '█ ██     ██  ██ ██     ████    ▀▀▄▄  ██ ▀▀ ██ ██   ██   ██████ ███▀  ▄██',
        '█ ██████ ▀████▀ ▀█████ ██ ▀█▄ █████▀ ██    ██ ██   ██   ██  ██ ██   ▀▀██',
        '█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█████████'
    )
    
    # Calculate centering based on terminal width
    $logoWidth = $logo[0].Length
    $terminalWidth = $Host.UI.RawUI.WindowSize.Width
    $leftPadding = [Math]::Max(0, [Math]::Floor(($terminalWidth - $logoWidth) / 2))
    $leftPaddingBlocks = '█' * $leftPadding
    $rightPadding = [Math]::Max(0, $terminalWidth - $logoWidth - $leftPadding)
    $rightPaddingBlocks = '█' * $rightPadding

    # Display logo (with or without padding based on FullWidth switch)
    $logo | ForEach-Object {
        if ($FullWidth) {
            Write-Host "$fgColor$bgColor$leftPaddingBlocks" -NoNewline
        }
        Write-Host "$fgColor$bgColor$_" -NoNewline
        if ($FullWidth) {
            Write-Host "$fgColor$bgColor$rightPaddingBlocks" -NoNewline
        }
        Write-Host $reset
    }
    
    $versionString = "v$Version █"
    $subtitleWidth = $by.Length + $url.Length + $versionString.Length
    $paddingTotal = $logoWidth - $subtitleWidth
    $padding1 = [Math]::Floor($paddingTotal / 2)
    $padding2 = $paddingTotal - $padding1
    $subtitle = $by + (' ' * $padding1) + $url + (' ' * $padding2) + $versionString
    
    if ($FullWidth) {
        Write-Host "$fgColor$bgColor$leftPaddingBlocks" -NoNewline
    }
    Write-Host "$fgColor$bgColor$subtitle" -NoNewline
    if ($FullWidth) {
        Write-Host "$fgColor$bgColor$rightPaddingBlocks" -NoNewline
    }
    Write-Host $reset
    
    # Bottom border line
    $bottomLine = '▀' * $logoWidth
    if ($FullWidth) {
        $leftBottomBlocks = '▀' * $leftPadding
        $rightBottomBlocks = '▀' * $rightPadding
        Write-Host "$fgColor$leftBottomBlocks" -NoNewline
    }
    Write-Host "$fgColor$bottomLine" -NoNewline
    if ($FullWidth) {
        Write-Host "$fgColor$rightBottomBlocks" -NoNewline
    }
    Write-Host $reset
}