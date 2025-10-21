function Write-StyledHost {
    <#
        .SYNOPSIS
        Writes styled, decorated messages to the console host with color coding.

        .DESCRIPTION
        Write-StyledHost provides consistent, visually distinct output formatting for different
        message types in Locksmith 2. Each message type has a unique decorator character and
        color scheme to improve readability and user experience in the console.
        
        This function intentionally uses Write-Host for visual formatting that should not be
        captured in the output pipeline. It preserves and restores the original console colors.

        .PARAMETER Type
        The type of message to display. Each type has a unique decorator and color:
        - Info: Cyan '[i]' for informational messages
        - Warning: DarkYellow '[!]' for warnings
        - Success: Green '[+]' for successful operations
        - Error: Red '[X]' for errors
        - Code: Black on DarkGray '[>]' for code/commands
        - Remediation: DarkCyan on Gray '[~]' for remediation steps
        - Title: White '[>]' for section titles
        - Subtitle: DarkGray '[>]' for subsection titles

        .PARAMETER Message
        The message text to display. Accepts pipeline input.

        .INPUTS
        System.String
        You can pipe message strings to Write-StyledHost.

        .OUTPUTS
        None
        This function writes directly to the host and does not produce pipeline output.

        .EXAMPLE
        Write-StyledHost -Type Info -Message "Scanning certificate templates..."
        Displays: [i] Scanning certificate templates... (in Cyan)

        .EXAMPLE
        Write-StyledHost -Type Error -Message "Failed to connect to Certificate Authority"
        Displays: [X] Failed to connect to Certificate Authority (in Red)

        .EXAMPLE
        "ESC1 vulnerability detected" | Write-StyledHost -Type Warning
        Displays: [!] ESC1 vulnerability detected (in DarkYellow)

        .EXAMPLE
        Write-StyledHost Success "Remediation applied successfully"
        Displays: [+] Remediation applied successfully (in Green)

        .LINK
        https://github.com/jakehildreth/Locksmith2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('Info', 'Warning', 'Success', 'Error', 'Code', 'Remediation', 'Title', 'Subtitle')]
        [string]$Type,
        
        [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        try {
            $ForegroundColor = $Host.UI.RawUI.ForegroundColor
            $BackgroundColor = $Host.UI.RawUI.BackgroundColor
        } catch {
            # Fallback to defaults if host UI is not available (non-interactive session)
            $ForegroundColor = 'Gray'
            $BackgroundColor = 'Black'
            Write-Verbose "Unable to access host UI colors, using defaults: $_"
        }
    }

    process {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        try {
            $Status = switch ($Type) {
                'Info' {
                    @{
                        Decoration      = 'i'
                        ForegroundColor = 'Cyan'
                        BackgroundColor = $BackgroundColor
                    }
                }
                'Warning' {
                    @{
                        Decoration      = '!'
                        ForegroundColor = 'DarkYellow'
                        BackgroundColor = $BackgroundColor
                    }
                }
                'Success' {
                    @{
                        Decoration      = '+'
                        ForegroundColor = 'Green'
                        BackgroundColor = $BackgroundColor
                    }
                }
                'Error' {
                    @{
                        Decoration      = 'X'
                        ForegroundColor = 'Red'
                        BackgroundColor = $BackgroundColor
                    }
                }
                'Code' {
                    @{
                        Decoration      = '>'
                        ForegroundColor = 'Black'
                        BackgroundColor = 'DarkGray'
                    }
                }
                'Remediation' {
                    @{
                        Decoration      = '~'
                        ForegroundColor = 'DarkCyan'
                        BackgroundColor = 'Gray'
                    }
                }
                'Title' {
                    @{
                        Decoration      = '>'
                        ForegroundColor = 'White'
                        BackgroundColor = $BackgroundColor
                    }
                }
                'Subtitle' {
                    @{
                        Decoration      = '>'
                        ForegroundColor = 'DarkGray'
                        BackgroundColor = $BackgroundColor
                    }
                }
            }

            if ($VerbosePreference -eq 'Continue') {
                $Decorator = "[$($Status.Decoration)]      [$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]"
            } else {
                $Decorator = "[$($Status.Decoration)]"
            }

            Write-Host "$Decorator $Message" -ForegroundColor $Status.ForegroundColor -BackgroundColor $Status.BackgroundColor -NoNewline
            Write-Host -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
        } catch {
            # Fallback to plain output if Write-Host fails
            Write-Verbose "Write-Host failed, falling back to Write-Output: $_"
            Write-Output "$Decorator $Message"
        }
    }
}
