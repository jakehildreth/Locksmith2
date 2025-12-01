function Initialize-DirectoryConnections {
    <#
        .SYNOPSIS
        Initializes script-scoped authenticated DirectoryEntry objects for common LDAP/GC paths.

        .DESCRIPTION
        Creates reusable authenticated DirectoryEntry objects for the Global Catalog and root domain
        LDAP paths. These objects are stored in script scope to avoid repeated authentication overhead
        and object creation throughout the module execution.
        
        This function should be called once during module initialization (in Invoke-Locksmith2)
        after RootDSE and Credential are established.
        
        The initialized objects are:
        - $script:GCDirectoryEntry: Global Catalog connection to root domain
        - $script:LDAPDirectoryEntry: LDAP connection to default naming context
        - $script:ConfigDirectoryEntry: LDAP connection to configuration naming context

        .PARAMETER RootDSE
        The RootDSE DirectoryEntry object used to determine paths and server.

        .PARAMETER Credential
        PSCredential for authenticating to Active Directory.

        .INPUTS
        None

        .OUTPUTS
        None
        Populates script-scoped variables for use throughout the module.

        .EXAMPLE
        Initialize-DirectoryConnections -RootDSE $script:RootDSE -Credential $script:Credential
        Initializes the common directory connections for module use.

        .NOTES
        The caller is responsible for disposing these objects when the module session ends.
        These objects should be reused throughout the module execution to improve performance.
        
        Benefits:
        - Reduces authentication overhead
        - Eliminates repeated object creation
        - Provides consistent connection objects
        - Improves overall module performance
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]
        $RootDSE,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    try {
        # Extract server from RootDSE
        if ($RootDSE.Path -match 'LDAP://([^/]+)') {
            $server = $Matches[1]
        } else {
            Write-Warning "Could not extract server from RootDSE path."
            return
        }

        # Get naming contexts
        $rootDomainDN = $RootDSE.rootDomainNamingContext.Value
        $defaultDN = $RootDSE.defaultNamingContext.Value
        $configDN = $RootDSE.configurationNamingContext.Value

        # Initialize Global Catalog connection (forest-wide searches)
        if ($rootDomainDN) {
            $gcPath = "GC://$server/$rootDomainDN"
            $script:GCDirectoryEntry = New-AuthenticatedDirectoryEntry -Path $gcPath
            Write-Verbose "Initialized GC connection: $gcPath"
        }

        # Initialize LDAP connection to default naming context (domain searches)
        if ($defaultDN) {
            $ldapPath = "LDAP://$server/$defaultDN"
            $script:LDAPDirectoryEntry = New-AuthenticatedDirectoryEntry -Path $ldapPath
            Write-Verbose "Initialized LDAP connection: $ldapPath"
        }

        # Initialize Configuration naming context connection (for AD CS objects)
        if ($configDN) {
            $configPath = "LDAP://$server/$configDN"
            $script:ConfigDirectoryEntry = New-AuthenticatedDirectoryEntry -Path $configPath
            Write-Verbose "Initialized Config connection: $configPath"
        }

    } catch {
        Write-Warning "Failed to initialize directory connections: $_"
    }
}
