function Get-ModsmithObject {
    <#
    .SYNOPSIS
        Retrieves objects with specified properties.

    .DESCRIPTION
        Get-ModsmithObject retrieves objects based on the provided criteria. This cmdlet supports
        pipeline input and follows PowerShell best practices including proper error handling,
        WhatIf support, and verbose output.

    .PARAMETER Name
        Specifies the name of the object to retrieve. This parameter is mandatory and supports
        pipeline input by property name.

    .PARAMETER Type
        Specifies the type of object to retrieve. Valid values are 'User', 'Group', or 'Computer'.
        Default value is 'User'.

    .PARAMETER IncludeDisabled
        If specified, includes disabled objects in the results.

    .EXAMPLE
        Get-ModsmithObject -Name 'John.Doe'

        Retrieves the object with the name 'John.Doe'.

    .EXAMPLE
        'User1', 'User2' | Get-ModsmithObject -Type User -Verbose

        Retrieves multiple user objects through the pipeline with verbose output.

    .EXAMPLE
        Get-ModsmithObject -Name 'TestGroup' -Type Group -IncludeDisabled

        Retrieves a group object named 'TestGroup' including disabled objects.

    .OUTPUTS
        PSCustomObject
        Returns custom objects with Name, Type, Enabled, and LastModified properties.

    .NOTES
        Author: Jake Hildreth
        Version: 2026.2.1
        Requires: PowerShell 5.1 or higher
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [ValidateSet('User', 'Group', 'Computer')]
        [string]$Type = 'User',

        [Parameter()]
        [switch]$IncludeDisabled
    )

    begin {
        Write-Verbose 'Starting object retrieval process'
        $processedCount = 0
    }

    process {
        try {
            Write-Verbose "Processing object: $Name (Type: $Type)"

            # Simulate object retrieval logic
            # In a real implementation, this would query AD or another data source
            $object = [PSCustomObject]@{
                Name         = $Name
                Type         = $Type
                Enabled      = $true
                LastModified = Get-Date
                Source       = 'Modsmith'
            }

            # Apply filtering based on IncludeDisabled parameter
            if (-not $IncludeDisabled -and -not $object.Enabled) {
                Write-Verbose "Skipping disabled object: $Name"
                return
            }

            Write-Output $object
            $processedCount++

        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $_.Exception,
                'ObjectRetrievalFailed',
                [System.Management.Automation.ErrorCategory]::NotSpecified,
                $Name
            )
            $PSCmdlet.WriteError($errorRecord)
        }
    }

    end {
        Write-Verbose "Object retrieval process completed. Processed $processedCount object(s)"
    }
}
