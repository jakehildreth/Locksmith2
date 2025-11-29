function Read-Choice {
    <#
        .SYNOPSIS
        Prompts the user to select from a list of options.

        .DESCRIPTION
        Displays a question with a set of options and waits for user input.
        Validates the response against the provided options and returns the selected choice.
        Supports a default option that is used if the user presses Enter without input.
        The default option is displayed in uppercase to indicate it will be used if no input is provided.
        
        Input is case-insensitive and the function will loop until a valid option is selected.

        .PARAMETER Question
        The question or prompt to display to the user.

        .PARAMETER Options
        An array of valid option strings that the user can choose from.
        Default is @('y', 'n') for yes/no questions.

        .PARAMETER Default
        The default option to use if the user provides no input (presses Enter).
        Must be one of the options in the Options array.
        If not specified, defaults to the first option in the Options array.
        The default option is displayed in uppercase in the prompt.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        System.String
        Returns the selected option as a string.

        .EXAMPLE
        Read-Choice -Question "Continue?"
        Prompts "Continue? [Y/n]" and accepts 'y' or 'n'. Default is 'y'.

        .EXAMPLE
        Read-Choice -Question "Select action" -Options @('run', 'skip', 'exit') -Default 'skip'
        Prompts "Select action [run/SKIP/exit]" with 'skip' as the default.

        .EXAMPLE
        $choice = Read-Choice -Question "Overwrite file?" -Options @('yes', 'no', 'all') -Default 'no'
        if ($choice -eq 'yes') {
            # Overwrite the file
        }
        Stores the user's choice and uses it in conditional logic.

        .EXAMPLE
        $action = Read-Choice -Question "What would you like to do?" -Options @('audit', 'fix', 'export', 'quit')
        switch ($action) {
            'audit'  { Invoke-Audit }
            'fix'    { Invoke-Fix }
            'export' { Export-Results }
            'quit'   { exit }
        }
        Uses the returned choice in a switch statement.

        .NOTES
        The function loops until a valid option is entered.
        User input is case-insensitive (e.g., 'Y', 'y', and 'yes' will all match 'yes').
        Pressing Enter without input uses the default option.
        Invalid input displays a yellow warning message with valid options.
    #>
    
    #requires -Version 5.1
    
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Question,
        
        [string[]]$Options = @('y', 'n'),
        
        [ValidateScript({
                if ($Options -notcontains $_) {
                    throw "-Default option '$_' must be one of the available options: $($Options -join ', ')"
                }
                $true
            })]
        [string]$Default = $null
    )
    
    # Set default to first option if not specified
    if (-not $Default) {
        $Default = $Options[0]
    }
    
    # Format options display with default highlighted
    $optionsDisplay = ($Options | ForEach-Object {
            if ($_ -eq $Default) { $_.ToUpper() } else { $_ }
        }) -join '/'
    
    while ($true) {
        try {
            $response = Read-Host "$Question [$optionsDisplay]"
            
            # Use default if no input provided
            if ([string]::IsNullOrWhiteSpace($response)) {
                return $Default
            }
            
            # Check if response matches an option (case-insensitive)
            $match = $Options | Where-Object { $_ -eq $response }
            if ($match) {
                return $match
            }
            
            Write-Warning "Invalid option. Please choose from: $($Options -join ', ')"
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $_.Exception,
                'PromptFailed',
                [System.Management.Automation.ErrorCategory]::NotSpecified,
                $Question
            )
            $PSCmdlet.WriteError($errorRecord)
            return $Default
        }
    }
}