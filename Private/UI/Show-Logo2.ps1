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

        .INPUTS
        None

        .OUTPUTS
        None
        Displays the logo and subtitle to the console.

        .EXAMPLE
        Show-Logo2
        Displays the logo with a random foreground color and black background.

        .EXAMPLE
        Show-Logo2 -Version '2025.11.24.0800'
        Displays the logo with a specific version string.

        .EXAMPLE
        Show-Logo -ForegroundRGB @(0, 255, 0) -BackgroundRGB @(0, 0, 128)
        Displays the logo with green text on dark blue background.

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
        [int[]]$BackgroundRGB = @(0, 0, 0)
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
    
    # main font (lightly modified to shorten t): https://www.dafont.com/04b-09.font?fpp=200
    $logo = @(
        '█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀███▀▀▀▀███',
        '█ ██ ▄▄▄▄▄▄ ▄▄▄▄▄▄ ██ ▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄ ▀▀ ██▄▄ ██▄▄▄▄ ██▄████ ██ ',
        '█ ██ ██  ██ ██     ██▀██  ▀▀▀▄▄▄ ██ ██ ██ ██ ██   ██  ██ ██▀▄▄▄▄███ ',
        '█ ▀▀ ▀▀▀▀▀▀ ▀▀▀▀▀▀ ▀▀ ▀▀▀ ▀▀▀▀▀▀ ▀▀ ▀▀ ▀▀ ▀▀ ▀▀▀▀ ▀▀  ▀▀ ██ ▀▀▀▀▀██ '
    )

    $logoWidth = $logo[0].Length
    $logoBottomLeftCorner = '▀'
    $logoBottomLine = ($logoBottomLeftCorner * ($logoWidth - 1) ) + ' '

    # Display logo
    $logo | ForEach-Object {
        if ($useAnsi) {
            Write-Host "$fgColor$bgColor$_" -NoNewline
            Write-Host $reset
        } else {
            Write-Host $_ -ForegroundColor $fgColorEnum -BackgroundColor $bgColorEnum
        }
    }
    
    if ($useAnsi) {
            Write-Host "$fgColor$logoBottomLeftCorner" -NoNewline
            Write-Host "$fgColor$bgColor$logoBottomLine"
    } else {
        Write-Host $logoBottomLeftCorner -ForegroundColor $fgColorEnum -NoNewline
        Write-Host $logoBottomLine -ForegroundColor $fgColorEnum -BackgroundColor $bgColorEnum
    }

    $versionString = "v$Version"
    $subtitleWidth = $by.Length + $url.Length + $versionString.Length
    $paddingTotal = $logoWidth - $subtitleWidth
    $padding1 = [Math]::Floor($paddingTotal / 2)
    $padding2 = $paddingTotal - $padding1
    $subtitle = $by + (' ' * $padding1) + $url + (' ' * $padding2) + $versionString
    
    Write-Host $subtitle
}