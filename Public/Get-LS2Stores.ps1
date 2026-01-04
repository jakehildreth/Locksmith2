function Get-LS2Stores {
    <#
        .SYNOPSIS
        Returns the internal data stores used by Locksmith2.

        .DESCRIPTION
        Provides access to the internal hashtable and array stores that cache data during
        Locksmith2 execution:
        
        - PrincipalStore: Keyed by SID, contains resolved principal objects with properties
          like distinguishedName, sAMAccountName, objectClass, displayName, etc.
        
        - AdcsObjectStore: Keyed by distinguishedName, contains AD CS objects (CAs, templates,
          etc.) with computed security properties.
        
        - DomainStore: Keyed by distinguishedName, contains domain information including
          nETBIOSName, dnsRoot, and objectSid.
        
        - IssueStore: Keyed by technique name (ESC1, ESC6, etc.), contains arrays of discovered
          security vulnerabilities with details about the issue, fix, and revert scripts.
        
        - SafePrincipals: Array of SID patterns representing principals considered safe
          (e.g., Enterprise Admins, Domain Admins, SYSTEM).
        
        - DangerousPrincipals: Array of SID patterns representing principals considered dangerous
          (e.g., Everyone, Authenticated Users, Domain Users).
        
        - StandardOwners: Array of SID patterns representing acceptable owners for AD CS objects
          (includes forest-specific Enterprise Admins SID).
        
        These stores are populated during the execution of Invoke-Locksmith2 and persist
        for the duration of the PowerShell session.

        .PARAMETER Name
        Optional. Name of a specific store to retrieve. Valid values:
        - PrincipalStore
        - AdcsObjectStore
        - DomainStore
        - IssueStore
        - SafePrincipals
        - DangerousPrincipals
        - StandardOwners
        
        If not specified, returns an object containing all stores.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        PSCustomObject
        Returns an object with seven properties:
        - PrincipalStore, AdcsObjectStore, DomainStore, IssueStore: Hashtables of cached data
        - SafePrincipals, DangerousPrincipals, StandardOwners: Arrays of SID patterns

        .EXAMPLE
        $stores = Get-LS2Stores
        $stores.PrincipalStore.Count
        Shows the number of principals that have been resolved and cached.

        .EXAMPLE
        $stores = Get-LS2Stores
        $stores.PrincipalStore['S-1-5-21-...'] | Format-List *
        Displays all properties of a specific principal by SID.

        .EXAMPLE
        $stores = Get-LS2Stores
        $stores.AdcsObjectStore.Values | Where-Object DangerousEnrollee
        Shows all AD CS objects that have dangerous enrollees.

        .EXAMPLE
        $stores = Get-LS2Stores
        $stores.DomainStore.Values | Select-Object nETBIOSName, dnsRoot
        Lists all cached domain information.

        .EXAMPLE
        $stores = Get-LS2Stores
        $stores.StandardOwners
        Shows all SID patterns considered acceptable owners for AD CS objects.

        .NOTES
        Author: Jake Hildreth (@jakehildreth)
        Module: Locksmith2
        Requires: PowerShell 5.1+
        
        The stores are module-scoped and shared across all Locksmith2 functions.
        They are initialized by Invoke-Locksmith2 and persist until the module is
        reloaded or PowerShell session ends.
        
        Use this function to inspect internal module state for debugging
        or advanced analysis scenarios.

        .LINK
        Invoke-Locksmith2

        .LINK
        Find-LS2VulnerableCA

        .LINK
        Find-LS2VulnerableTemplate

        .LINK
        Find-LS2VulnerableObject
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    [PSCustomObject]@{
        AdcsObjectStore     = $script:AdcsObjectStore
        DangerousPrincipals = $script:DangerousPrincipals
        DomainStore         = $script:DomainStore
        Forest              = $script:Forest
        IssueStore          = $script:IssueStore
        PrincipalStore      = $script:PrincipalStore
        SafePrincipals      = $script:SafePrincipals
        StandardOwners      = $script:StandardOwners
    }
}
