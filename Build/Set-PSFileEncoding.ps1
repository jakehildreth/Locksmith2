function Set-PSFileEncoding {
    <#
        .SYNOPSIS
        Re-encodes PowerShell files to UTF-8 with BOM.

        .DESCRIPTION
        Reads each specified file, detects the current encoding, and rewrites it as
        UTF-8 with a byte order mark (BOM). This encoding is the safest choice for
        PowerShell scripts that must run on both Windows PowerShell 5.1 and
        PowerShell 7.x across Windows, Linux, and macOS.

        .PARAMETER Path
        One or more paths to PowerShell files (.ps1, .psm1, .psd1).

        .INPUTS
        System.String
        Accepts file paths via the pipeline.

        .OUTPUTS
        None

        .EXAMPLE
        Set-PSFileEncoding -Path 'Private\Test\Test-IsBA.ps1'

        Re-encodes the specified file to UTF-8 with BOM.

        .EXAMPLE
        Get-ChildItem -Path 'Private' -Recurse -Include '*.ps1','*.psm1','*.psd1' | Set-PSFileEncoding

        Re-encodes all PowerShell files under the Private directory.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullName')]
        [string[]]$Path
    )

    #requires -Version 5.1

    begin {
        $utf8BomEncoding = New-Object System.Text.UTF8Encoding($true)
    }

    process {
        foreach ($filePath in $Path) {
            $resolvedPath = Resolve-Path -Path $filePath -ErrorAction SilentlyContinue
            if (-not $resolvedPath) {
                Write-Warning "Path not found: $filePath"
                continue
            }

            $item = Get-Item -Path $resolvedPath
            if ($item.PSIsContainer) {
                continue
            }

            if ($item.Extension -notin @('.ps1', '.psm1', '.psd1')) {
                Write-Verbose "Skipping non-PowerShell file: $resolvedPath"
                continue
            }

            # Read raw bytes to detect current encoding.
            $bytes = [System.IO.File]::ReadAllBytes($resolvedPath)

            $currentEncoding = $null
            if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
                $currentEncoding = 'UTF-8 BOM'
            } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
                $currentEncoding = 'UTF-16 LE'
            } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
                $currentEncoding = 'UTF-16 BE'
            } elseif ($bytes.Length -ge 4 -and $bytes[0] -eq 0x00 -and $bytes[1] -eq 0x00 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) {
                $currentEncoding = 'UTF-32 BE'
            } elseif ($bytes.Length -ge 4 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x00) {
                $currentEncoding = 'UTF-32 LE'
            } else {
                $currentEncoding = 'UTF-8 (no BOM) or ASCII'
            }

            # Decode using current encoding and re-encode as UTF-8 with BOM.
            $text = [System.IO.File]::ReadAllText($resolvedPath)

            if ($currentEncoding -eq 'UTF-8 BOM' -and [System.Text.Encoding]::UTF8.GetBytes($text).Length -eq ($bytes.Length - 3)) {
                Write-Verbose "Already UTF-8 with BOM: $resolvedPath"
                continue
            }

            if ($PSCmdlet.ShouldProcess($resolvedPath, 'Re-encode to UTF-8 with BOM')) {
                [System.IO.File]::WriteAllText($resolvedPath, $text, $utf8BomEncoding)
                Write-Verbose "Re-encoded $resolvedPath from $currentEncoding to UTF-8 with BOM"
            }
        }
    }
}
