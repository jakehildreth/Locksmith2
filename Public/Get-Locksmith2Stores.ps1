function Get-Locksmith2Stores {
    <#
        .SYNOPSIS
        Returns the internal data stores used by Locksmith2.

        .DESCRIPTION
        Provides access to the four internal hashtable stores that cache data during
        Locksmith2 execution:
        
        - PrincipalStore: Keyed by SID, contains resolved principal objects with properties
          like distinguishedName, sAMAccountName, objectClass, displayName, etc.
        
        - AdcsObjectStore: Keyed by distinguishedName, contains AD CS objects (CAs, templates,
          etc.) with computed security properties.
        
        - DomainStore: Keyed by distinguishedName, contains domain information including
          nETBIOSName and dnsRoot.
        
        - IssueStore: Keyed by technique name (ESC1, ESC6, etc.), contains arrays of discovered
          security vulnerabilities with details about the issue, fix, and revert scripts.
        
        These stores are populated during the execution of Invoke-Locksmith2 and persist
        for the duration of the PowerShell session.

        .OUTPUTS
        PSCustomObject
        Returns an object with four properties (PrincipalStore, AdcsObjectStore, DomainStore, 
        IssueStore), each containing a hashtable of cached data.

        .EXAMPLE
        $stores = Get-Locksmith2Stores
        $stores.PrincipalStore.Count
        Shows the number of principals that have been resolved and cached.

        .EXAMPLE
        $stores = Get-Locksmith2Stores
        $stores.PrincipalStore['S-1-5-21-...'] | Format-List *
        Displays all properties of a specific principal by SID.

        .EXAMPLE
        $stores = Get-Locksmith2Stores
        $stores.AdcsObjectStore.Values | Where-Object DangerousEnrollee
        Shows all AD CS objects that have dangerous enrollees.

        .EXAMPLE
        $stores = Get-Locksmith2Stores
        $stores.DomainStore.Values | Select-Object nETBIOSName, dnsRoot
        Lists all cached domain information.

        .NOTES
        The stores are module-scoped and shared across all Locksmith2 functions.
        They are initialized by Invoke-Locksmith2 and persist until the module is
        reloaded or PowerShell session ends.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    [PSCustomObject]@{
        PrincipalStore = $script:PrincipalStore
        AdcsObjectStore = $script:AdcsObjectStore
        DomainStore = $script:DomainStore
        IssueStore = $script:IssueStore
    }
}
