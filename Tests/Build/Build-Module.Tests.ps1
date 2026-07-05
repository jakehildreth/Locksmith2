BeforeAll {
    . "$PSScriptRoot\..\..\Build\Invoke-LS2PostBuildPublish.ps1"

    # Build the fake vendor tree that Get-ChildItem probes for version discovery.
    # Save-Module is mocked so these dirs stand in for what it would have created.
    function New-FakeArtefactRoot {
        param([string]$Root)
        $null = New-Item -ItemType Directory -Path $Root -Force
        foreach ($pair in @('PSWriteHTML\1.41.0', 'PSCertutil\0.0.3')) {
            $null = New-Item -ItemType Directory -Path (Join-Path $Root "Modules\$pair") -Force
        }
    }
}

Describe 'Invoke-LS2PostBuildPublish' {

    Context 'When PublishToPSGallery is not requested' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-no-publish'
            New-FakeArtefactRoot -Root $artefactRoot
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
        }

        It 'Should not call Publish-Module' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false -PSGalleryAPIKey 'dummy'
            Should -Invoke Publish-Module -Exactly 0
        }

        It 'Should still vendor dependencies' {
            Mock Save-Module {} -Verifiable
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false -PSGalleryAPIKey 'dummy'
            Should -InvokeVerifiable
        }
    }

    Context 'When PublishToPSGallery is requested with an API key' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-with-key'
            New-FakeArtefactRoot -Root $artefactRoot
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
        }

        It 'Should call Publish-Module exactly once' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'fake-key'
            Should -Invoke Publish-Module -Exactly 1
        }

        It 'Should pass -Path pointing at the artefact root' {
            Mock Publish-Module {}
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'fake-key'
            Should -Invoke Publish-Module -ParameterFilter { $Path -eq $artefactRoot } -Exactly 1
        }

        It 'Should pass the API key to Publish-Module' {
            Mock Publish-Module {}
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'fake-key'
            Should -Invoke Publish-Module -ParameterFilter { $NuGetApiKey -eq 'fake-key' } -Exactly 1
        }

        It 'Should NOT use -Name when publishing' {
            Mock Publish-Module {}
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'fake-key'
            Should -Invoke Publish-Module -ParameterFilter { -not $PSBoundParameters.ContainsKey('Name') } -Exactly 1
        }
    }

    Context 'When PublishToPSGallery is requested but no API key or path provided' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-no-key'
            New-FakeArtefactRoot -Root $artefactRoot
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Write-Error {}
        }

        It 'Should not call Publish-Module' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery
            Should -Invoke Publish-Module -Exactly 0
        }

        It 'Should write an error' {
            Mock Write-Error {} -Verifiable
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery
            Should -InvokeVerifiable
        }
    }

    Context 'When PublishToPSGallery is requested with an API file path' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-file-key'
            New-FakeArtefactRoot -Root $artefactRoot
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            $fakeKeyFile = 'TestDrive:\api.txt'
            Set-Content -Path $fakeKeyFile -Value 'file-key'
        }

        It 'Should read the key from the file and pass it to Publish-Module' {
            Mock Publish-Module {}
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIPath $fakeKeyFile
            Should -Invoke Publish-Module -ParameterFilter { $NuGetApiKey -eq 'file-key' } -Exactly 1
        }
    }

    Context 'Vendoring always runs' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-vendor'
            New-FakeArtefactRoot -Root $artefactRoot
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
        }

        It 'Should call Save-Module for PSWriteHTML' {
            Mock Save-Module {} -ParameterFilter { $Name -eq 'PSWriteHTML' } -Verifiable
            Mock Save-Module {} -ParameterFilter { $Name -eq 'PSCertutil' }
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false
            Should -InvokeVerifiable
        }

        It 'Should call Save-Module for PSCertutil' {
            Mock Save-Module {} -ParameterFilter { $Name -eq 'PSWriteHTML' }
            Mock Save-Module {} -ParameterFilter { $Name -eq 'PSCertutil' } -Verifiable
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false
            Should -InvokeVerifiable
        }

        It 'Should call Update-ModuleManifest to patch NestedModules' {
            Mock Save-Module {}
            Mock Update-ModuleManifest {} -Verifiable
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false
            Should -InvokeVerifiable
        }
    }
}

