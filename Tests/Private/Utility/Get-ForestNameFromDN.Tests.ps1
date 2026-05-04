#requires -Version 5.1
BeforeAll {
    # Dot-source via scriptblock to handle UTF-16LE source encoding
    $SourcePath = Join-Path $PSScriptRoot '..' '..' '..' 'Private' 'Utility' 'Get-ForestNameFromDN.ps1'
    . ([scriptblock]::Create((Get-Content -Path $SourcePath -Raw)))
}

Describe 'Get-ForestNameFromDN' -Tag 'Unit' {
    It 'should return contoso.com for a single-level domain DN' {
        Get-ForestNameFromDN -DistinguishedName 'CN=Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com' |
            Should -Be 'contoso.com'
    }

    It 'should return child.contoso.com for a multi-level domain DN' {
        Get-ForestNameFromDN -DistinguishedName 'CN=User,CN=Users,DC=child,DC=contoso,DC=com' |
            Should -Be 'child.contoso.com'
    }

    It 'should return a.b.c.d for a four-part domain DN' {
        Get-ForestNameFromDN -DistinguishedName 'CN=Obj,DC=a,DC=b,DC=c,DC=d' |
            Should -Be 'a.b.c.d'
    }

    It 'should return fabrikam.org via pipeline input' {
        'CN=User,CN=Users,DC=fabrikam,DC=org' | Get-ForestNameFromDN |
            Should -Be 'fabrikam.org'
    }

    It 'should return Unknown when DN has no DC components' {
        Get-ForestNameFromDN -DistinguishedName 'CN=SomeObject,CN=SomeContainer' |
            Should -Be 'Unknown'
    }

    It 'should return Unknown for an empty string' -Tag 'EdgeCase' {
        Get-ForestNameFromDN -DistinguishedName '' |
            Should -Be 'Unknown'
    }

    It 'should process multiple pipeline values independently' {
        $results = @('CN=A,DC=alpha,DC=com', 'CN=B,DC=beta,DC=net') | Get-ForestNameFromDN
        $results[0] | Should -Be 'alpha.com'
        $results[1] | Should -Be 'beta.net'
    }
}
