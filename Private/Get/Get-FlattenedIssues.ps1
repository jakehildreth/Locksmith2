function Get-FlattenedIssues {
    <#
        .SYNOPSIS
        Flattens the IssueStore hashtable into individual issue entries.

        .DESCRIPTION
        Converts the nested IssueStore structure (DN -> Technique -> Issues array) into
        a flat list of objects containing key information about each discovered issue.
        
        Each returned object contains:
        - ObjectName: Friendly name of the vulnerable object
        - ObjectClass: Type of object (template, CA, container, etc.)
        - Technique: ESC classification (ESC1, ESC6, etc.)
        - Principal: Identity that can abuse the issue (if applicable)
        
        Some techniques (ESC6, ESC11, ESC16) are configuration-based and not tied to
        specific principals, so the Principal field will be null for those issues.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        PSCustomObject
        Returns custom objects with ObjectName, ObjectClass, Technique, and Principal properties.

        .EXAMPLE
        Get-FlattenedIssues
        Returns a flattened list of all issues from the IssueStore.

        .EXAMPLE
        Get-FlattenedIssues | Where-Object Technique -eq 'ESC1'
        Returns only ESC1 issues in flattened format.

        .EXAMPLE
        Get-FlattenedIssues | Group-Object ObjectClass
        Groups issues by object class (template, CA, etc.).

        .NOTES
        Requires $script:IssueStore and $script:AdcsObjectStore to be populated by
        Invoke-Locksmith2 or related Find-LS2Vulnerable* functions.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    #requires -Version 5.1

    begin {
        Write-Verbose "Flattening IssueStore into individual issue entries..."
        
        if (-not $script:IssueStore -or $script:IssueStore.Count -eq 0) {
            Write-Warning "IssueStore is empty or not initialized. Run Invoke-Locksmith2 first."
            return
        }
    }

    process {
        $issueCount = 0

        # Iterate through each DN in the IssueStore
        foreach ($dn in $script:IssueStore.Keys) {
            # Get the object from AdcsObjectStore to determine object class
            $adcsObject = $script:AdcsObjectStore[$dn]
            
            $objectName = if ($adcsObject) {
                if ($adcsObject.displayName) {
                    $adcsObject.displayName
                } elseif ($adcsObject.name) {
                    $adcsObject.name
                } elseif ($adcsObject.cn) {
                    $adcsObject.cn
                } else {
                    $dn
                }
            } else {
                $dn
            }

            $objectClass = if ($adcsObject) {
                if ($adcsObject.objectClass -is [array]) {
                    # Take the most specific class (last in array)
                    $adcsObject.objectClass[-1]
                } else {
                    $adcsObject.objectClass
                }
            } else {
                'Unknown'
            }

            # Iterate through each technique for this DN
            foreach ($technique in $script:IssueStore[$dn].Keys) {
                # Get all issues for this DN + technique combination
                $issues = $script:IssueStore[$dn][$technique]

                foreach ($issue in $issues) {
                    $issueCount++

                    # Output flattened object
                    [PSCustomObject]@{
                        ObjectName  = $objectName
                        ObjectClass = $objectClass
                        Technique   = $technique
                        Principal   = $issue.IdentityReference  # Will be null for ESC6, ESC11, ESC16
                    }
                }
            }
        }

        Write-Verbose "Flattened $issueCount issue(s) from IssueStore"
    }
}
