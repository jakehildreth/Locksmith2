class LS2Issue {
    # Core issue identification
    [string]$Technique              # ESC1, ESC2, ESC6, etc.
    [string]$Forest                 # Forest where issue was found
    [string]$Name                   # Friendly name of vulnerable object
    [string]$DistinguishedName      # DN of vulnerable object
    
    # Principal information (for permission-based issues)
    [string]$IdentityReference      # DOMAIN\User or group name
    [string]$IdentityReferenceSID   # SID of the principal
    [string]$ActiveDirectoryRights  # GenericAll, ExtendedRight, etc.
    
    # Template-specific properties
    [Nullable[bool]]$Enabled        # Whether template is enabled on any CA
    [string[]]$EnabledOn            # List of CAs where template is enabled
    
    # CA-specific properties
    [string]$CAFullName             # For CA issues: SERVER\CA
    
    # Issue details
    [string]$Issue                  # Description of the vulnerability
    [string]$Fix                    # PowerShell script to remediate
    [string]$Revert                 # PowerShell script to undo remediation
    
    # Constructor for creating issues from hashtable
    LS2Issue([hashtable]$Properties) {
        # Core properties
        $this.Technique = $Properties.Technique
        $this.Forest = $Properties.Forest
        $this.Name = $Properties.Name
        $this.DistinguishedName = $Properties.DistinguishedName
        
        # Principal properties (may be null for non-permission issues)
        $this.IdentityReference = $Properties.IdentityReference
        $this.IdentityReferenceSID = $Properties.IdentityReferenceSID
        $this.ActiveDirectoryRights = $Properties.ActiveDirectoryRights
        
        # Template properties (may be null for CA issues)
        $this.Enabled = $Properties.Enabled
        $this.EnabledOn = $Properties.EnabledOn
        
        # CA properties (may be null for template issues)
        $this.CAFullName = $Properties.CAFullName
        
        # Issue details
        $this.Issue = $Properties.Issue
        $this.Fix = $Properties.Fix
        $this.Revert = $Properties.Revert
    }
    
    # Method to get a friendly identifier for the issue
    [string] GetIdentifier() {
        if ($this.IdentityReference) {
            return "$($this.Technique): $($this.Name) - $($this.IdentityReference)"
        } else {
            return "$($this.Technique): $($this.Name)"
        }
    }
    
    # Method to check if this is a permission-based issue
    [bool] HasPrincipal() {
        return -not [string]::IsNullOrEmpty($this.IdentityReference)
    }
    
    # Method to check if this is a template issue
    [bool] IsTemplateIssue() {
        return $null -ne $this.Enabled
    }
    
    # Method to check if this is a CA issue
    [bool] IsCAIssue() {
        return -not [string]::IsNullOrEmpty($this.CAFullName)
    }
}
