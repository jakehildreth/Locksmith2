function Show-Logo2 {
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
    
    # Enable ANSI/VT100 support in Windows PowerShell 5.1
    $useAnsi = $true
    if ($PSVersionTable.PSVersion.Major -le 5) {
        try {
            $code = @'
using System;
using System.Runtime.InteropServices;
public class VirtualTerminal {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
    
    public static bool Enable() {
        IntPtr handle = GetStdHandle(-11); // STD_OUTPUT_HANDLE
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) {
            return false;
        }
        uint mode;
        if (!GetConsoleMode(handle, out mode)) {
            return false;
        }
        mode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return SetConsoleMode(handle, mode);
    }
}
'@
            if (-not ([System.Management.Automation.PSTypeName]'VirtualTerminal').Type) {
                Add-Type -TypeDefinition $code
            }
            $useAnsi = [VirtualTerminal]::Enable()
            if (-not $useAnsi) {
                Write-Verbose "ANSI support not available, falling back to ConsoleColor"
            }
        } catch {
            $useAnsi = $false
            Write-Verbose "Could not enable ANSI support: $_"
        }
    }
    
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
    $by = "(c) $(Get-Date -Format yyyy) $author"
    $url = 'https://locksmith.ad'

    # Convert RGB to nearest ConsoleColor for fallback
    if (-not $useAnsi) {
        # Map RGB to closest ConsoleColor (simplified mapping)
        $fgColorEnum = [System.ConsoleColor]::White
        $bgColorEnum = [System.ConsoleColor]::Black
        
        # Try to pick a bright ConsoleColor based on RGB values
        $totalBrightness = $ForegroundRGB[0] + $ForegroundRGB[1] + $ForegroundRGB[2]
        if ($ForegroundRGB[0] -gt $ForegroundRGB[1] -and $ForegroundRGB[0] -gt $ForegroundRGB[2]) {
            $fgColorEnum = if ($totalBrightness -gt 450) { [System.ConsoleColor]::Red } else { [System.ConsoleColor]::DarkRed }
        } elseif ($ForegroundRGB[1] -gt $ForegroundRGB[0] -and $ForegroundRGB[1] -gt $ForegroundRGB[2]) {
            $fgColorEnum = if ($totalBrightness -gt 450) { [System.ConsoleColor]::Green } else { [System.ConsoleColor]::DarkGreen }
        } elseif ($ForegroundRGB[2] -gt $ForegroundRGB[0] -and $ForegroundRGB[2] -gt $ForegroundRGB[1]) {
            $fgColorEnum = if ($totalBrightness -gt 450) { [System.ConsoleColor]::Cyan } else { [System.ConsoleColor]::DarkCyan }
        } else {
            $fgColorEnum = if ($totalBrightness -gt 450) { [System.ConsoleColor]::White } else { [System.ConsoleColor]::Gray }
        }
    }

    # ANSI escape sequences for RGB colors (use [char]27 for PS 5.1 compatibility)
    $esc = [char]27
    $fgColor = "$esc[38;2;$($ForegroundRGB[0]);$($ForegroundRGB[1]);$($ForegroundRGB[2])m"
    $bgColor = "$esc[48;2;$($BackgroundRGB[0]);$($BackgroundRGB[1]);$($BackgroundRGB[2])m"
    $reset = "$esc[0m"

    $logo = @(
        '█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀███▀▀▀▀███',
        '█ ██     ▄████▄ ▄█████ ██ ▄█▀ ▄█████ ██▄  ▄██ ██ ██████ ██  ██ ██  ▄▄  ██',
        '█ ██     ██  ██ ██     ████    ▀▀▄▄  ██ ▀▀ ██ ██   ██   ██████ ████▀ ▄███',
        '█ ██████ ▀████▀ ▀█████ ██ ▀█▄ █████▀ ██    ██ ██   ██   ██  ██ ██▀  ▀▀▀██',
        '█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄██▄▄▄▄▄▄██'
    )
    
    $logo = @(
        '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄',
        '█ ▄      ▄▄▄▄   ▄▄▄▄  ▄   ▄  ▄▄▄▄ ▄   ▄ ▄▄▄ ▄▄▄▄▄ ▄   ▄ ██▀▄▄▄▀██',
        '█ █     █    █ █    ▀ █▄▄▀  ▀▄▄▄  █▀▄▀█  █    █   █▄▄▄█ ███▀▀▀▄██',
        '█ █▄▄▄▄ ▀▄▄▄▄▀ ▀▄▄▄▄▀ █  ▀▄ ▄▄▄▄▀ █   █ ▄█▄   █   █   █ ██ ██████',
        '█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄██▄▄▄▄▄██'
    )

    $logo = @(
        '█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀███▀▀▀███',
        '█  ▄▀▀▄  █     ▄▀▀▀▀▄ ▄▀▀▀▀▄ █  ▄▀ ▄▀▀▀▀ █▄ ▄█ ▀▀█▀▀ ▀▀█▀▀ █   █ ██▄███ ██',
        '█ ▄█▄▄█▄ █     █    █ █    ▄ █▀▀▄   ▀▀▀▄ █ ▀ █   █     █   █▀▀▀█ ██▀▄▄▄███',
        '█ ▀▀▀▀▀▀ ▀▀▀▀▀  ▀▀▀▀   ▀▀▀▀  ▀   ▀ ▀▀▀▀  ▀   ▀ ▀▀▀▀▀   ▀   ▀   ▀ ██ ▀▀▀▀██',
        '█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█'
    )

    # $logo = @(
    #     '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄',
    #     '█ ▄     ▄▄▄▄▄ ▄▄▄▄▄ ▄   ▄ ▄▄▄▄▄ ▄   ▄ ▄▄▄ ▄▄▄▄▄ ▄   ▄ ██▀▄▄▄▀██',
    #     '█ █     █   █ █     █▄▄▀  █▄▄▄▄ █▀▄▀█  █    █   █▄▄▄█ ███▀▀▀▄██',
    #     '█ █▄▄▄▄ █▄▄▄█ █▄▄▄▄ █  ▀▄ ▄▄▄▄█ █   █ ▄█▄   █   █   █ ██ ██████',
    #     '█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄██▄▄▄▄▄██'
    # )

    $logo = @(
        '█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀███▀▀▀███',
        '█ ██ ▄▄▄▄▄▄ ▄▄▄▄▄▄ ██ ▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄ ▀▀ ▄██▄▄▄▄ ██▄▄▄▄ ██▄███ ██',
        '█ ██ ██  ██ ██     ██▀██  ▀▀▀▄▄▄ ██ ██ ██ ██  ██     ██  ██ ██▀▄▄▄███',
        '█ ▀▀ ▀▀▀▀▀▀ ▀▀▀▀▀▀ ▀▀ ▀▀▀ ▀▀▀▀▀▀ ▀▀ ▀▀ ▀▀ ▀▀  ▀▀▀▀▀▀ ▀▀  ▀▀ ██ ▀▀▀▀██',
        '▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀'
    )
    # Calculate centering based on terminal width
    $logoWidth = $logo[0].Length
    $terminalWidth = $Host.UI.RawUI.WindowSize.Width
    
    # Warn if using FullWidth in ISE where WindowSize.Width returns 0
    if ($FullWidth -and ($terminalWidth -eq 0 -or $null -eq $terminalWidth)) {
        Write-Warning @"
FullWidth mode is not supported in hosts that do not support `$Host.UI.RawUI.WindowSize.Width.
         Displaying logo without padding.

"@
        $FullWidth = $false
    }
    
    $leftPadding = [Math]::Max(0, [Math]::Floor(($terminalWidth - $logoWidth) / 2))
    $leftPaddingBlocks = '█' * $leftPadding
    $rightPadding = [Math]::Max(0, $terminalWidth - $logoWidth - $leftPadding)
    $rightPaddingBlocks = '█' * $rightPadding

    # Display logo (with or without padding based on FullWidth switch)
    $logo | ForEach-Object {
        if ($useAnsi) {
            if ($FullWidth) {
                Write-Host "$fgColor$bgColor$leftPaddingBlocks" -NoNewline
            }
            Write-Host "$fgColor$bgColor$_" -NoNewline
            if ($FullWidth) {
                Write-Host "$fgColor$bgColor$rightPaddingBlocks" -NoNewline
            }
            Write-Host $reset
        } else {
            if ($FullWidth) {
                Write-Host $leftPaddingBlocks -ForegroundColor $fgColorEnum -BackgroundColor $bgColorEnum -NoNewline
            }
            Write-Host $_ -ForegroundColor $fgColorEnum -BackgroundColor $bgColorEnum -NoNewline
            if ($FullWidth) {
                Write-Host $rightPaddingBlocks -ForegroundColor $fgColorEnum -BackgroundColor $bgColorEnum -NoNewline
            }
            Write-Host
        }
    }
    
    $versionString = "v$Version"
    $subtitleWidth = $by.Length + $url.Length + $versionString.Length
    $paddingTotal = $logoWidth - $subtitleWidth
    $padding1 = [Math]::Floor($paddingTotal / 2)
    $padding2 = $paddingTotal - $padding1
    $subtitle = $by + (' ' * $padding1) + $url + (' ' * $padding2) + $versionString
    
    if ($useAnsi) {
        if ($FullWidth) {
            Write-Host "$leftPaddingBlocks" -NoNewline
        }
        Write-Host "$subtitle" -NoNewline
        if ($FullWidth) {
            Write-Host "$rightPaddingBlocks" -NoNewline
        }
        Write-Host $reset
    } else {
        if ($FullWidth) {
            Write-Host $leftPaddingBlocks -NoNewline
        }
        Write-Host $subtitle -NoNewline
        if ($FullWidth) {
            Write-Host $rightPaddingBlocks -NoNewline
        }
        Write-Host
    }
    
    # # Bottom border line
    # $bottomLine = '▀' * $logoWidth
    # if ($useAnsi) {
    #     if ($FullWidth) {
    #         $leftBottomBlocks = '▀' * $leftPadding
    #         $rightBottomBlocks = '▀' * $rightPadding
    #         Write-Host "$fgColor$leftBottomBlocks" -NoNewline
    #     }
    #     Write-Host "$fgColor$bottomLine" -NoNewline
    #     if ($FullWidth) {
    #         Write-Host "$fgColor$rightBottomBlocks" -NoNewline
    #     }
    #     Write-Host $reset
    # } else {
    #     if ($FullWidth) {
    #         $leftBottomBlocks = '▀' * $leftPadding
    #         $rightBottomBlocks = '▀' * $rightPadding
    #         Write-Host $leftBottomBlocks -ForegroundColor $fgColorEnum -NoNewline
    #     }
    #     Write-Host $bottomLine -ForegroundColor $fgColorEnum -NoNewline
    #     if ($FullWidth) {
    #         Write-Host $rightBottomBlocks -ForegroundColor $fgColorEnum -NoNewline
    #     }
    #     Write-Host
    # }
}