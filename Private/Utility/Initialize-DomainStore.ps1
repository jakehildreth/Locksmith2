function Initialize-DomainStore {
    <#
        .SYNOPSIS
        Populates the module-level DomainStore with all domains in the forest.

        .DESCRIPTION
        Queries the Configuration partition for all crossRef objects representing domain
        partitions and stores their Distinguished Names, NetBIOS names, and DNS names in
        the module-level DomainStore hashtable for fast lookups.
        
        This function should be called once during module initialization to pre-populate
        domain information for the entire forest, avoiding repeated LDAP queries during
        principal resolution.

        .INPUTS
        None
        Uses module-level variables $script:Credential and $script:RootDSE.

        .OUTPUTS
        None
        Populates the module-level $script:DomainStore hashtable.

        .EXAMPLE
        Initialize-DomainStore
        Populates the DomainStore with all domains in the forest.

        .NOTES
        Requires $script:Credential and $script:RootDSE to be set before calling.
        The DomainStore is keyed by domain DN (e.g., "DC=contoso,DC=com").
        
        Store structure:
        - Key: Domain Distinguished Name
        - Value: PSCustomObject with distinguishedName, nETBIOSName, dnsRoot
    #>
    [CmdletBinding()]
    param()

    #requires -Version 5.1

    begin {
        Write-Verbose "Initializing DomainStore..."
        
        # Initialize Domain Store if it doesn't exist
        if (-not $script:DomainStore) {
            $script:DomainStore = @{}
        }
    }

    process {
        # Require Credential and RootDSE
        if (-not $script:Credential) {
            Write-Warning "Credential not set. Cannot initialize DomainStore."
            return
        }

        if (-not $script:RootDSE) {
            Write-Warning "RootDSE not set. Cannot initialize DomainStore."
            return
        }

        try {
            $configNC = $script:RootDSE.configurationNamingContext.Value
            if ($script:RootDSE.Path -match 'LDAP://([^/]+)') {
                $server = $Matches[1]
                $partitionsPath = "LDAP://$server/CN=Partitions,$configNC"
                
                $partitionsEntry = New-AuthenticatedDirectoryEntry -Path $partitionsPath
                
                $partitionsSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $partitionsSearcher.SearchRoot = $partitionsEntry
                $partitionsSearcher.Filter = "(objectClass=crossRef)"
                $partitionsSearcher.PropertiesToLoad.AddRange(@('nCName', 'nETBIOSName', 'dnsRoot')) | Out-Null
                $partitionsSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
                
                $allPartitions = $partitionsSearcher.FindAll()
                
                $domainCount = 0
                foreach ($partition in $allPartitions) {
                    if ($partition.Properties['nCName'].Count -gt 0) {
                        $domainDN = $partition.Properties['nCName'][0]
                        
                        # Create domain store entry with all properties
                        if (-not $script:DomainStore.ContainsKey($domainDN)) {
                            $domainObject = [PSCustomObject]@{
                                distinguishedName = $domainDN
                                nETBIOSName = if ($partition.Properties['nETBIOSName'].Count -gt 0) { $partition.Properties['nETBIOSName'][0] } else { $null }
                                dnsRoot = if ($partition.Properties['dnsRoot'].Count -gt 0) { $partition.Properties['dnsRoot'][0] } else { $null }
                            }
                            
                            $script:DomainStore[$domainDN] = $domainObject
                            Write-Verbose "Stored domain: $domainDN (NetBIOS: $($domainObject.nETBIOSName), DNS: $($domainObject.dnsRoot))"
                            $domainCount++
                        }
                    }
                }
                
                Write-Verbose "DomainStore initialized with $domainCount domain(s)"
                
                $allPartitions.Dispose()
                $partitionsSearcher.Dispose()
                $partitionsEntry.Dispose()
            } else {
                Write-Warning "Could not extract server from RootDSE path: $($script:RootDSE.Path)"
            }
        } catch {
            Write-Warning "Failed to initialize DomainStore: $_"
        }
    }
}
