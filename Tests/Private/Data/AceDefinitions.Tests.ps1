#requires -Version 5.1
BeforeAll {
    $PesterPreference = [PesterConfiguration]::Default
    $PesterPreference.Should.ErrorAction = 'Continue'

    $DataFilePath = Join-Path $PSScriptRoot '..' '..' '..' 'Private' 'Data' 'AceDefinitions.psd1'
    $script:Data = Import-PowerShellDataFile -Path $DataFilePath
}

Describe 'AceDefinitions data file' -Tag 'Unit', 'Data' {

    Context 'Required top-level keys' {

        It 'should have a DataVersion key' {
            $script:Data.ContainsKey('DataVersion') | Should -BeTrue
        }

        It 'should have a DangerousAces key' {
            $script:Data.ContainsKey('DangerousAces') | Should -BeTrue
        }
    }

    Context 'DangerousAces collection' {

        It 'should be an array' {
            @($script:Data.DangerousAces).Count | Should -BeGreaterThan 0
        }

        It 'should contain exactly 20 entries' {
            @($script:Data.DangerousAces).Count | Should -Be 20
        }

        It 'should have no entries with null or empty Name' {
            foreach ($ace in $script:Data.DangerousAces) {
                $ace.Name | Should -Not -BeNullOrEmpty
            }
        }

        It 'should have no entries with null or empty Rights' {
            foreach ($ace in $script:Data.DangerousAces) {
                $ace.Rights | Should -Not -BeNullOrEmpty
            }
        }

        It 'should have ObjectTypeGUID key present on all entries' {
            foreach ($ace in $script:Data.DangerousAces) {
                $ace.Keys | Should -Contain 'ObjectTypeGUID'
            }
        }

        It 'should have ObjectTypeName key present on all entries' {
            foreach ($ace in $script:Data.DangerousAces) {
                $ace.Keys | Should -Contain 'ObjectTypeName'
            }
        }

        It 'should have ApplicableToClasses key present on all entries' {
            foreach ($ace in $script:Data.DangerousAces) {
                $ace.Keys | Should -Contain 'ApplicableToClasses'
            }
        }

        It 'should have Description key present on all entries' {
            foreach ($ace in $script:Data.DangerousAces) {
                $ace.Keys | Should -Contain 'Description'
            }
        }

        It 'should have a non-empty ApplicableToClasses array for all entries' {
            foreach ($ace in $script:Data.DangerousAces) {
                @($ace.ApplicableToClasses).Count | Should -BeGreaterThan 0
            }
        }
    }

    Context 'Named entry spot-checks' {

        It 'should contain a GenericAll entry' {
            $ace = $script:Data.DangerousAces | Where-Object { $_.Name -eq 'GenericAll' }
            $ace | Should -Not -BeNullOrEmpty
        }

        It 'GenericAll entry should have Rights set to GenericAll' {
            $ace = $script:Data.DangerousAces | Where-Object { $_.Name -eq 'GenericAll' }
            $ace.Rights | Should -Be 'GenericAll'
        }

        It 'GenericAll entry should apply to pKICertificateTemplate class' {
            $ace = $script:Data.DangerousAces | Where-Object { $_.Name -eq 'GenericAll' }
            $ace.ApplicableToClasses | Should -Contain 'pKICertificateTemplate'
        }

        It 'should contain a WriteDacl entry' {
            $ace = $script:Data.DangerousAces | Where-Object { $_.Name -eq 'WriteDacl' }
            $ace | Should -Not -BeNullOrEmpty
        }

        It 'should contain a WriteOwner entry' {
            $ace = $script:Data.DangerousAces | Where-Object { $_.Name -eq 'WriteOwner' }
            $ace | Should -Not -BeNullOrEmpty
        }

        It 'should contain a WriteProperty-CertificateNameFlag entry' {
            $ace = $script:Data.DangerousAces | Where-Object { $_.Name -eq 'WriteProperty-CertificateNameFlag' }
            $ace | Should -Not -BeNullOrEmpty
        }

        It 'should contain a CreateChild-CertificateTemplate entry' {
            $ace = $script:Data.DangerousAces | Where-Object { $_.Name -eq 'CreateChild-CertificateTemplate' }
            $ace | Should -Not -BeNullOrEmpty
        }

        It 'should contain a WriteProperty-cACertificate entry' {
            $ace = $script:Data.DangerousAces | Where-Object { $_.Name -eq 'WriteProperty-cACertificate' }
            $ace | Should -Not -BeNullOrEmpty
        }
    }

    Context 'All 20 expected ACE names are present' {

        $expectedNames = @(
            'GenericAll',
            'WriteDacl',
            'WriteOwner',
            'GenericWrite',
            'WriteProperty-AllProperties',
            'WriteProperty-CertificateNameFlag',
            'WriteProperty-ExtendedKeyUsage',
            'WriteProperty-CertificateApplicationPolicy',
            'WriteProperty-EnrollmentFlag',
            'WriteProperty-RASignature',
            'WriteProperty-MaxIssuingDepth',
            'WriteProperty-TemplateSchemaVersion',
            'WriteProperty-TemplateMinorRevision',
            'WriteProperty-certificateTemplates',
            'WriteProperty-AllowedToActOnBehalfOfOtherIdentity',
            'WriteProperty-ServicePrincipalName',
            'WriteProperty-UserAccountControl',
            'CreateChild-All',
            'CreateChild-CertificateTemplate',
            'WriteProperty-cACertificate'
        )

        It 'should contain all 20 expected ACE names' {
            $actualNames = $script:Data.DangerousAces | Select-Object -ExpandProperty Name
            foreach ($name in $expectedNames) {
                $actualNames | Should -Contain $name
            }
        }

        It 'should have no duplicate ACE names' {
            $names = $script:Data.DangerousAces | Select-Object -ExpandProperty Name
            $uniqueNames = $names | Select-Object -Unique
            @($uniqueNames).Count | Should -Be @($names).Count
        }
    }
}
