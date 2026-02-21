function Get-AdcsObject {
    <#
        .SYNOPSIS
        Retrieves all objects from the Public Key Services Container in Active Directory.

        .DESCRIPTION
        Queries the Active Directory Configuration partition to retrieve all objects from the
        Public Key Services Container (CN=Public Key Services,CN=Services,CN=Configuration).
        This container contains Certificate Authority objects, Certificate Templates, and other 
        PKI-related objects used by Active Directory Certificate Services (AD CS).
        
        Uses module-level $script:Credential, $script:RootDSE, and $script:AdcsObjectStore
        variables set by Invoke-Locksmith2. The function performs a recursive LDAP search and
        returns LS2AdcsObject instances for all discovered PKI objects, including their
        properties and ACLs.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        LS2AdcsObject
        Returns LS2AdcsObject instances for all objects found in the Public Key Services 
        container and its subtree.

        .EXAMPLE
        Get-AdcsObject
        Retrieves all AD CS objects using script-scope credentials and root DSE.

        .EXAMPLE
        $templates = Get-AdcsObject | Where-Object { $_.IsCertificateTemplate() }
        Retrieves all certificate template objects from the PKI container.

        .NOTES
        Requires script-scope variables set by Invoke-Locksmith2:
        - $script:Credential: Credentials for AD access
        - $script:RootDSE: Forest configuration naming context
        - $script:AdcsObjectStore: Cache of retrieved objects

        .LINK
        https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/
    #>
    [CmdletBinding()]
    param ()

    #requires -Version 5.1 -Modules Microsoft.PowerShell.Security

    begin {
        # Initialize the AD CS Object Store if it doesn't exist
        if (-not $script:AdcsObjectStore) {
            $script:AdcsObjectStore = @{}
        }
    }

    process {
        try {
            # Build the LDAP search base for the Public Key Services container
            $searchBase = "CN=Public Key Services,CN=Services,$($script:RootDSE.configurationNamingContext)"
            
            Write-Verbose "Searching $searchBase for AD CS objects."
            Write-Verbose "AD CS Object Store currently has $($script:AdcsObjectStore.Count) entries"
            
            # Create DirectorySearcher for recursive search
            $searcherDirectoryEntry = New-AuthenticatedDirectoryEntry -Path "$($script:RootDSE.Parent)/$searchBase"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($searcherDirectoryEntry)
            $searcher.Filter = "(objectClass=*)"  # Get all objects
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree  # Recursive search
            $searcher.PageSize = 1000  # Handle large result sets
            
            # Get all results
            $searchResults = $searcher.FindAll()
            
            # Convert paths into DirectoryEntry objects and store them
            $objectCount = 0
            $cachedCount = 0
            $searchResults | ForEach-Object {
                $objectDirectoryEntry = $_.GetDirectoryEntry()
                $distinguishedName = $objectDirectoryEntry.distinguishedName.Value
                
                Write-Verbose "`nFound object: $distinguishedName`nClass: $($objectDirectoryEntry.objectClass -join ', ')"
                
                # Store the AD CS object if not already stored
                if (-not $script:AdcsObjectStore.ContainsKey($distinguishedName)) {
                    # Create LS2AdcsObject from DirectoryEntry
                    $adcsObject = [LS2AdcsObject]::new($objectDirectoryEntry)
                    
                    $script:AdcsObjectStore[$distinguishedName] = $adcsObject
                    $cachedCount++
                    Write-Verbose "Stored AD CS object: $distinguishedName"
                }
                
                $script:AdcsObjectStore[$distinguishedName]
                $objectCount++
            }
            Write-Verbose "Found $objectCount total objects in the Public Key Services container and its subtree"
            Write-Verbose "Stored $cachedCount new AD CS objects (Total store size: $($script:AdcsObjectStore.Count))"
            
            # Clean up
            $searcher.Dispose()
            $searcherDirectoryEntry.Dispose()
            $searchResults.Dispose()
        } catch {
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $_.Exception,
                Created 7 todos
                
                Let me read the full Get-AdcsObject to make a precise edit:
                
                Good -- Get-AdcsObject already emits LS2AdcsObject from the store. So the real work is updating Initialize-AdcsObjectStore and all 27 Set-* functions. Let me read them all to plan precise edits.
                
                Starting: Update Initialize-AdcsObjectStore (2/7)
                
                Let me read all the Set-* files now to understand each one's property access patterns:
                
                
                Good -- I have a comprehensive map of all 24 Set-* functions. Now I'll start implementing. Let me begin with Initialize-AdcsObjectStore, then batch the Set-* functions.
                
                Now let me read and edit the template Set-* functions. I already have the contents of several. Let me start with the EKU group and the flag group:
                
                Now I have enough detail. Let me start with the batch edits for the first set of files. I'll do Set-SANAllowed, Set-AnyPurposeEKUExist, Set-AuthenticationEKUExist, and Set-EnrollmentAgentEKUExist:
                
                Now the flag-based functions. Let me update Set-AuthorizedSignatureNotRequired, Set-ManagerApprovalNotRequired, and Set-NoSecurityExtension:
                
                Good progress. Now let me read and update the remaining template flag functions and ACL functions. I need to read the ones I haven't seen yet:
                
                Summarized conversation history
                
                Now let me read the ACL-based functions and more:
                
                Good, I have a clear picture of those. Now let me read the CA functions and the LS2AdcsObject class to verify property declarations:
                
                Let me read the remaining files:
                
                Now let me check the current state of an already-modified file to confirm the exact pattern:
                
                Good, I now have a complete picture of all remaining files. Let me update the todo list and start working:
                
                Added 2 todos
                
                First, I need to fix the LS2AdcsObject class. Several properties are missing or have wrong types:
                
                Missing from class:
                
                EnrollmentAgentEKUExist, RequiresEnrollmentAgentSignature, AuthorizedSignatureRequired, ManagerApprovalRequired, NoSecurityExtension (all [Nullable[bool]])
                DangerousEnrolleeNames, LowPrivilegeEnrolleeNames (both [string[]])
                Type mismatches:
                
                DangerousEnrollee is [Nullable[bool]] but functions assign [string[]] (SID arrays)
                LowPrivilegeEnrollee is [Nullable[bool]] but functions assign [string[]] (SID arrays)
                Now updating the 3 remaining flag-check template functions: Set-AuthorizedSignatureRequired, Set-ManagerApprovalRequired, Set-RequiresEnrollmentAgentSignature, and Set-TemplateEnabled:
                
                I notice I left a $_.Properties.'msPKI-RA-Application-Policies' reference in Set-RequiresEnrollmentAgentSignature. The LS2AdcsObject class doesn't have this property yet. Let me add it and fix the reference:
                
                Now update Set-TemplateEnabled:
                
                Now updating the 4 ACL-based functions. These all follow the same pattern - they use $_.ObjectSecurity.Access, $_.Properties.displayName[0], and Add-Member for store + pipeline:
                
                Now updating the CA functions. These are trickier because they use $_.Properties['cn'][0], $_.Properties['dNSHostName'][0], and $_.Properties.distinguishedName[0] plus certutil-based property reads:
                
                Now update Set-CAAdministrator and Set-CACertificateManager:
                
                Now updating the 4 derived CA functions. These already use $_.Properties.distinguishedName with fallback to $_.DistinguishedName, and read data from AdcsObjectStore. The key changes are param type and removing redundant Add-Member:
                
                Now for Set-HasNonStandardOwner. This is the tricky one - it already uses [object[]] and handles both DirectoryEntry and LS2AdcsObject. Since everything is now LS2AdcsObject, I can simplify it significantly:
                
                Now let me verify for any remaining DirectoryEntry references in the Set-* files and other key areas:
                
                Those remaining DirectoryEntry references are in comment-based help (.INPUTS/.OUTPUTS sections). Let me verify there are no functional issues by checking for remaining Add-Member calls and $_.Properties access:
                
                All Add-Member calls have been removed from Set-* functions. The only remaining ones are in class constructors (ScriptProperty members) which are correct.
                
                Now let me check for any remaining $_.Properties. access in the Set-* functions:
                
                Good - the .Properties. references in the class constructor are correct (reading FROM DirectoryEntry to construct LS2AdcsObject). The Get-AdcsObjectName and Find-LS2VulnerableCA files are outside the Set-* scope but should also be updated. Let me check for the obsolete $script:AdcsObject variable:
                
                Now let me also update Get-AdcsObjectName since it still uses .Properties. access pattern and should use GetFriendlyName():
                
                Now let me check the Find-LS2VulnerableCA references and verify Initialize-AdcsObjectStore is correct:
                
                Initialize-AdcsObjectStore looks correct. Let me do a final check to verify everything is clean — check for any remaining $script:AdcsObjectStore[$dn] patterns that should now be replaced by direct $_ access in the Set-* functions:
                
                All remaining AdcsObjectStore references in Set-* files are either:
                
                In comment-based help (documentation)
                $script:AdcsObjectStore.Values in Set-TemplateEnabled's begin block (needed to build the template-to-CA mapping)
                No functional $script:AdcsObjectStore[$dn] store-update patterns remain. Let me also update Set-TemplateEnabled's begin block to use IsCertificationAuthority():
                
                Edited
                Set-TemplateEnabled.ps1+1-1
                Now let me verify there are no compile/lint errors:
                
                That error is from a code block in the conversation context, not from actual files. Let me verify with specific file checks:
                
                Issue #1 (Type System Inconsistency) implementation is complete. Here's the summary:
                
                Files modified: 25
                
                
                'ADCSObjectRetrievalFailed',
                [System.Management.Automation.ErrorCategory]::NotSpecified,
                $searchBase
            )
            $PSCmdlet.WriteError($errorRecord)
        }
    }
}