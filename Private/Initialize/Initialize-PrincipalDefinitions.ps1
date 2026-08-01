function Initialize-PrincipalDefinitions {
    <#
        .SYNOPSIS
        Loads and customizes principal definitions for the current forest.

        .DESCRIPTION
        Reads principal definitions from $script:PrincipalDefinitionsBase (loaded at module
        import) and injects forest-specific security principals (such as the forest's
        Enterprise Admins SID). Stores the customized definitions in module-level variables
        for use throughout the scan.
        
        This function should be called after Initialize-DomainStore so that domain SIDs
        are available for injection.

        .INPUTS
        None
        Uses module-level variables $script:DomainStore and $script:RootDSE.

        .OUTPUTS
        None
        Populates module-level variables:
        - $script:SafePrincipals
        - $script:DangerousPrincipals
        - $script:StandardOwners

        .EXAMPLE
        Initialize-PrincipalDefinitions
        Loads principal definitions and customizes them for the current forest.

        .NOTES
        Requires $script:DomainStore and $script:RootDSE to be initialized first.
        The StandardOwners array will include the forest-specific Enterprise Admins SID.
    #>
    [CmdletBinding()]
    param()

    #requires -Version 5.1

    begin {
        Write-Verbose "Loading and customizing principal definitions..."
    }

    process {
        if (-not $script:PrincipalDefinitionsBase) {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.InvalidOperationException]::new('PrincipalDefinitionsBase is not initialized. Cannot load principal definitions.'),
                    'PrincipalDefinitionsBaseNotInitialized',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $null
                )
            )
        }

        try {
            Write-Verbose 'Loading principal definitions from $script:PrincipalDefinitionsBase'

            # Start with the base definitions
            $script:SafePrincipals      = $script:PrincipalDefinitionsBase.SafePrincipals
            $script:DangerousPrincipals = $script:PrincipalDefinitionsBase.DangerousPrincipals
            $script:StandardOwners      = $script:PrincipalDefinitionsBase.StandardOwners
            
            # Inject forest-specific principals
            if ($script:RootDSE -and $script:DomainStore) {
                $rootDomainDN = $script:RootDSE.rootDomainNamingContext.Value
                
                if ($script:DomainStore.ContainsKey($rootDomainDN)) {
                    $forestRootDomain = $script:DomainStore[$rootDomainDN]
                    
                    if ($forestRootDomain.objectSid) {
                        # Add forest-specific Enterprise Admins SID
                        $enterpriseAdminsSid = "$($forestRootDomain.objectSid)-519"
                        
                        # Add to StandardOwners if not already present (avoid duplicates)
                        if ($enterpriseAdminsSid -notin $script:StandardOwners) {
                            $script:StandardOwners += $enterpriseAdminsSid
                            Write-Verbose "Added forest Enterprise Admins SID to StandardOwners: $enterpriseAdminsSid"
                        }
                    } else {
                        Write-Warning "Forest root domain SID not available in DomainStore"
                    }
                } else {
                    Write-Warning "Forest root domain not found in DomainStore"
                }
            } else {
                Write-Warning "DomainStore or RootDSE not initialized. Principal definitions will not include forest-specific SIDs."
            }
            
            Write-Verbose "Principal definitions loaded:"
            Write-Verbose "  - Safe Principals: $($script:SafePrincipals.Count)"
            Write-Verbose "  - Dangerous Principals: $($script:DangerousPrincipals.Count)"
            Write-Verbose "  - Standard Owners: $($script:StandardOwners.Count)"
            
        } catch {
            Write-Warning "Failed to load principal definitions: $_"
            
            # Initialize with empty arrays as fallback
            if (-not $script:SafePrincipals) { $script:SafePrincipals = @() }
            if (-not $script:DangerousPrincipals) { $script:DangerousPrincipals = @() }
            if (-not $script:StandardOwners) { $script:StandardOwners = @() }
        }
    }
}
