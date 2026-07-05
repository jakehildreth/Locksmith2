#requires -Version 5.1
BeforeAll {
    $PrivateGetRoot = Join-Path (Split-Path (Split-Path (Split-Path $PSScriptRoot))) 'Private\Get'
    . (Join-Path $PrivateGetRoot 'Get-RootDSE.ps1')
}

Describe 'Get-RootDSE' -Tag 'Unit' {

    Context 'When forest and credential are supplied and bind succeeds' -Tag 'Integration' {

        It 'should return an object with a Name property' {
            $result = Get-RootDSE -Forest $IntegrationForest -Credential $IntegrationCredential
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be 'rootDSE'
        }
    }

    Context 'When the LDAP bind fails (Name is null)' {

        BeforeAll {
            $emptyRootDSE = [PSCustomObject]@{ Name = $null; Path = 'LDAP://bad.domain/RootDSE' }
            Mock New-Object { return $emptyRootDSE } -ParameterFilter {
                $TypeName -eq 'DirectoryServices.DirectoryEntry' -or
                $TypeName -eq 'System.DirectoryServices.DirectoryEntry'
            }
        }

        It 'should return $null' {
            $securePass = ConvertTo-SecureString 'pass' -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new('CONTOSO\user', $securePass)
            $result = Get-RootDSE -Forest 'bad.domain' -Credential $cred -ErrorAction SilentlyContinue
            $result | Should -BeNullOrEmpty
        }

        It 'should write a non-terminating error on bind failure' {
            $securePass = ConvertTo-SecureString 'pass' -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new('CONTOSO\user', $securePass)
            $errorRecord = $null
            Get-RootDSE -Forest 'bad.domain' -Credential $cred -ErrorVariable errorRecord -ErrorAction SilentlyContinue 2>$null
            $errorRecord | Should -Not -BeNullOrEmpty
        }

        It 'should NOT call Read-Host regardless of failure' {
            Mock Read-Host {}
            $securePass = ConvertTo-SecureString 'pass' -AsPlainText -Force
            $cred = [System.Management.Automation.PSCredential]::new('CONTOSO\user', $securePass)
            Get-RootDSE -Forest 'bad.domain' -Credential $cred -ErrorAction SilentlyContinue
            Should -Invoke Read-Host -Exactly 0
        }
    }

    Context 'When no forest is supplied (current-session token path)' {

        BeforeAll {
            $mockRootDSE = [PSCustomObject]@{
                Name                       = 'rootDSE'
                configurationNamingContext = [PSCustomObject]@{ Value = 'CN=Configuration,DC=contoso,DC=com' }
                defaultNamingContext       = [PSCustomObject]@{ Value = 'DC=contoso,DC=com' }
                rootDomainNamingContext    = [PSCustomObject]@{ Value = 'DC=contoso,DC=com' }
                Path                       = 'LDAP://RootDSE'
            }
            # [ADSI] is a type accelerator — mock via wrapping; test the happy path by
            # ensuring the function falls back gracefully when no forest is given
            Mock Get-Variable { return $null } # ensure $script:Forest is null in dot-source scope
        }

        It 'should not throw when called with no parameters' {
            { Get-RootDSE -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
    }
}
