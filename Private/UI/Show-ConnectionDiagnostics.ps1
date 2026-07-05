function Show-ConnectionDiagnostics {
    <#
        .SYNOPSIS
        Displays detailed connection diagnostics for Active Directory LDAP connectivity.

        .DESCRIPTION
        Performs a series of diagnostic checks to help troubleshoot LDAP connection
        failures, including DNS resolution, port connectivity tests (LDAP 389,
        LDAPS 636, Global Catalog 3268), LDAP bind verification, and identity
        information.

        This function outputs directly to the host for interactive troubleshooting
        and does not return objects.

        .PARAMETER Forest
        The fully qualified domain name of the target Active Directory forest.

        .PARAMETER Credential
        Optional PSCredential used for the LDAP bind test.

        .PARAMETER RootDSE
        Optional DirectoryEntry object from a failed RootDSE connection attempt.
        Used to capture the specific bind error.

        .EXAMPLE
        Show-ConnectionDiagnostics -Forest 'corp.contoso.com'
        Displays diagnostics for the target forest using the current identity.

        .EXAMPLE
        Show-ConnectionDiagnostics -Forest 'corp.contoso.com' -Credential $cred -RootDSE $rootDSE
        Displays diagnostics including credential info and the original bind error.

        .OUTPUTS
        None. This function writes directly to the host.

        .NOTES
        This is an interactive troubleshooting aid, not a data-producing function.
        All output is via Write-Host intentionally.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Forest,

        [System.Management.Automation.PSCredential]$Credential,

        [System.DirectoryServices.DirectoryEntry]$RootDSE
    )

    Write-Host "`n--- Connection Diagnostics ---" -ForegroundColor Cyan
    Write-Host "Target Forest:       $Forest"
    Write-Host "Credential User:     $(if ($Credential) { $Credential.UserName } else { '(none - using current identity)' })"
    Write-Host "Current Identity:    $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Host "Current Domain:      $([System.Environment]::UserDomainName)"
    Write-Host "Machine Name:        $([System.Environment]::MachineName)"
    Write-Host "PowerShell Edition:  $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"

    # DNS resolution
    Write-Host "`n[DNS Resolution]" -ForegroundColor Cyan
    try {
        $dnsResult = [System.Net.Dns]::GetHostAddresses($Forest)
        Write-Host "  Resolved $Forest to: $($dnsResult.IPAddressToString -join ', ')"
    } catch {
        Write-Host "  FAILED to resolve '$Forest': $($_.Exception.Message)" -ForegroundColor Red
    }

    # Port connectivity tests
    $portTests = @(
        @{ Label = 'LDAP Port 389';           Port = 389  }
        @{ Label = 'LDAPS Port 636';          Port = 636  }
        @{ Label = 'Global Catalog Port 3268'; Port = 3268 }
    )

    foreach ($test in $portTests) {
        Write-Host "`n[$($test.Label)]" -ForegroundColor Cyan
        try {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $connectTask = $tcp.ConnectAsync($Forest, $test.Port)
            if ($connectTask.Wait(3000)) {
                Write-Host "  Port $($test.Port) is OPEN on $Forest" -ForegroundColor Green
            } else {
                Write-Host "  Port $($test.Port) connection TIMED OUT on $Forest" -ForegroundColor Red
            }
            $tcp.Dispose()
        } catch {
            Write-Host "  Port $($test.Port) connection FAILED: $($_.Exception.Message)" -ForegroundColor Red
            if ($tcp) { $tcp.Dispose() }
        }
    }

    # LDAP bind error from the original attempt
    if ($RootDSE) {
        Write-Host "`n[LDAP Bind Error]" -ForegroundColor Cyan
        try {
            $null = $RootDSE.Name
            Write-Host "  No exception captured (silent failure)"
        } catch {
            Write-Host "  Exception Type:    $($_.Exception.GetType().FullName)" -ForegroundColor Red
            Write-Host "  Message:           $($_.Exception.Message)" -ForegroundColor Red
            if ($_.Exception.InnerException) {
                Write-Host "  Inner Exception:   $($_.Exception.InnerException.Message)" -ForegroundColor Red
            }
        }
    }

    Write-Host "`n--- End Diagnostics ---`n" -ForegroundColor Cyan
}
