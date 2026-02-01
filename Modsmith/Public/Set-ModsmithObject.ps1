function Set-ModsmithObject {
    <#
    .SYNOPSIS
        Modifies properties of an object.

    .DESCRIPTION
        Set-ModsmithObject modifies specified properties of an object. This cmdlet supports
        WhatIf and Confirm parameters for safe operation, and follows PowerShell best practices
        including proper error handling and the PassThru pattern.

    .PARAMETER Name
        Specifies the name of the object to modify. This parameter is mandatory and supports
        pipeline input by property name.

    .PARAMETER Property
        Specifies the property name to modify.

    .PARAMETER Value
        Specifies the new value for the property.

    .PARAMETER PassThru
        Returns an object representing the modified item. By default, this cmdlet does not
        generate any output.

    .EXAMPLE
        Set-ModsmithObject -Name 'John.Doe' -Property 'Department' -Value 'IT'

        Modifies the Department property of the object named 'John.Doe'.

    .EXAMPLE
        'User1', 'User2' | Set-ModsmithObject -Property 'Title' -Value 'Administrator' -PassThru

        Modifies multiple objects through the pipeline and returns the modified objects.

    .EXAMPLE
        Set-ModsmithObject -Name 'TestUser' -Property 'Enabled' -Value 'True' -WhatIf

        Shows what would happen if the cmdlet runs without actually making changes.

    .OUTPUTS
        PSCustomObject (when PassThru is specified)
        Returns custom objects with Name, Property, Value, and Modified properties.

    .NOTES
        Author: Jake Hildreth
        Version: 2026.2.1
        Requires: PowerShell 5.1 or higher
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Property,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Value,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        Write-Verbose 'Starting object modification process'
        $modifiedCount = 0
    }

    process {
        try {
            Write-Verbose "Processing object: $Name"

            # Validate object exists (simulated)
            $objectExists = $true  # In real implementation, verify object existence

            if (-not $objectExists) {
                $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new("Object '$Name' not found"),
                    'ObjectNotFound',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $Name
                )
                $PSCmdlet.WriteError($errorRecord)
                return
            }

            # ShouldProcess check
            $shouldProcessMessage = "Set property '$Property' to '$Value'"
            if ($PSCmdlet.ShouldProcess($Name, $shouldProcessMessage)) {
                Write-Verbose "Modifying object '$Name': $Property = $Value"

                # Perform the modification (simulated)
                $modifiedObject = [PSCustomObject]@{
                    Name     = $Name
                    Property = $Property
                    Value    = $Value
                    Modified = Get-Date
                }

                $modifiedCount++
                Write-Verbose "Successfully modified object: $Name"

                # Return object if PassThru is specified
                if ($PassThru.IsPresent) {
                    Write-Output $modifiedObject
                }
            }

        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $_.Exception,
                'ObjectModificationFailed',
                [System.Management.Automation.ErrorCategory]::NotSpecified,
                $Name
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }

    end {
        Write-Verbose "Object modification process completed. Modified $modifiedCount object(s)"
    }
}
