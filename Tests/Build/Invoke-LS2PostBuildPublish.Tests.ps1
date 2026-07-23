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
        Set-Content -Path (Join-Path $Root 'Locksmith2.psd1') -Value "@{ ModuleVersion = '2026.5.141234' }"
    }

    function New-NestedFakeArtefactRoot {
        param([string]$Root)
        $nestedRoot = Join-Path $Root 'Locksmith2'
        New-FakeArtefactRoot -Root $nestedRoot
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

        It 'Should pass -Path pointing at the module root' {
            Mock Publish-Module {}
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'fake-key'
            Should -Invoke Publish-Module -ParameterFilter { $Path -like '*root-with-key' } -Exactly 1
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
        }

        It 'Should not call Publish-Module' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery
            Should -Invoke Publish-Module -Exactly 0
        }

        It 'Should write an error' {
            { Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -ErrorAction Stop } |
                Should -Throw '*-PublishToPSGallery was specified but neither -PSGalleryAPIKey nor -PSGalleryAPIPath was provided.*'
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

    Context 'When artefact is nested under a parent folder' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-nested'
            New-NestedFakeArtefactRoot -Root $artefactRoot
            $expectedPsd1 = Join-Path $artefactRoot 'Locksmith2\Locksmith2.psd1'
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
        }

        It 'Should patch the manifest inside the nested Locksmith2 folder' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false
            Should -Invoke Update-ModuleManifest -ParameterFilter { $Path -like '*root-nested*Locksmith2.psd1' } -Exactly 1
        }
    }

    Context 'When GitHub token is not supplied' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-no-gh'
            New-FakeArtefactRoot -Root $artefactRoot
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod {}
        }

        It 'Should not compress the artefact' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy'
            Should -Invoke Compress-Archive -Exactly 0
        }

        It 'Should not call Invoke-RestMethod' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy'
            Should -Invoke Invoke-RestMethod -Exactly 0
        }
    }

    Context 'When GitHub API key is supplied from main branch' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-gh-key'
            New-FakeArtefactRoot -Root $artefactRoot
            $psd1 = Join-Path $artefactRoot 'Locksmith2.psd1'
            Set-Content -Path $psd1 -Value "@{ ModuleVersion = '2026.5.141234' }"
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    upload_url = 'https://uploads.github.com/repos/jakehildreth/Locksmith2/releases/1/assets{?name,label}'
                }
            }
        }

        It 'Should compress the vendored artefact into a zip' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy' -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha 'abc123'
            Should -Invoke Compress-Archive -Exactly 1
        }

        It 'Should create a release via POST to the GitHub API' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy' -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha 'abc123'
            Should -Invoke Invoke-RestMethod -ParameterFilter { $Method -eq 'Post' -and $Uri -eq 'https://api.github.com/repos/jakehildreth/Locksmith2/releases' } -Exactly 1
        }

        It 'Should use the GitHub API key as Bearer token' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy' -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha 'abc123'
            Should -Invoke Invoke-RestMethod -ParameterFilter { $Headers.Authorization -eq 'Bearer ghp_fake' -and $Uri -eq 'https://api.github.com/repos/jakehildreth/Locksmith2/releases' } -Exactly 1 -Scope It
        }

        It 'Should not mark the release as prerelease' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy' -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha 'abc123'
            Should -Invoke Invoke-RestMethod -ParameterFilter { ($Body | ConvertFrom-Json).prerelease -eq $false } -Exactly 1 -Scope It
        }

        It 'Should upload the zip asset' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy' -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha 'abc123'
            Should -Invoke Invoke-RestMethod -ParameterFilter { $Uri -like '*assets?name=Locksmith2-2026.5.141234.zip' } -Exactly 1
        }
    }

    Context 'When GitHub API key path is supplied' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-gh-path'
            New-FakeArtefactRoot -Root $artefactRoot
            $psd1 = Join-Path $artefactRoot 'Locksmith2.psd1'
            Set-Content -Path $psd1 -Value "@{ ModuleVersion = '2026.5.141234' }"
            $tokenFile = 'TestDrive:\github-token.txt'
            Set-Content -Path $tokenFile -Value 'ghp_file_token'
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    upload_url = 'https://uploads.github.com/repos/jakehildreth/Locksmith2/releases/1/assets{?name,label}'
                }
            }
        }

        It 'Should use the token read from the file' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy' -PublishToGitHub -GitHubAPIPath $tokenFile -GitHubSha 'abc123'
            Should -Invoke Invoke-RestMethod -ParameterFilter { $Headers.Authorization -eq 'Bearer ghp_file_token' -and $Uri -eq 'https://api.github.com/repos/jakehildreth/Locksmith2/releases' } -Exactly 1 -Scope It
        }
    }

    Context 'When prerelease is specified' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-gh-prerelease'
            New-FakeArtefactRoot -Root $artefactRoot
            $psd1 = Join-Path $artefactRoot 'Locksmith2.psd1'
            Set-Content -Path $psd1 -Value "@{ ModuleVersion = '2026.5.141234' }"
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    upload_url = 'https://uploads.github.com/repos/jakehildreth/Locksmith2/releases/1/assets{?name,label}'
                }
            }
        }

        It 'Should include prerelease in release tag and zip name' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy' -PublishToGitHub -GitHubAPIKey 'ghp_fake' -Prerelease 'pre' -GitHubSha 'abc123'
            Should -Invoke Compress-Archive -ParameterFilter { $DestinationPath -like '*Locksmith2-2026.5.141234-pre.zip' } -Exactly 1
        }

        It 'Should mark the release as prerelease' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy' -PublishToGitHub -GitHubAPIKey 'ghp_fake' -Prerelease 'pre' -GitHubSha 'abc123'
            Should -Invoke Invoke-RestMethod -ParameterFilter { ($Body | ConvertFrom-Json).prerelease -eq $true } -Exactly 1 -Scope It
        }
    }

    Context 'When PublishToPSGallery is not requested' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-no-publish-gh'
            New-FakeArtefactRoot -Root $artefactRoot
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod {}
        }

        It 'Should not create a GitHub release' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false -GitHubAPIKey 'ghp_fake'
            Should -Invoke Invoke-RestMethod -Exactly 0
        }
    }

    Context 'When GitHub API call fails' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-gh-fail'
            New-FakeArtefactRoot -Root $artefactRoot
            $psd1 = Join-Path $artefactRoot 'Locksmith2.psd1'
            Set-Content -Path $psd1 -Value "@{ ModuleVersion = '2026.5.141234' }"
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod { throw 'API rate limit exceeded' }
            Mock Write-Host {}
        }

        It 'Should not throw' {
            { Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery -PSGalleryAPIKey 'dummy' -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha 'abc123' } | Should -Not -Throw
        }
    }

    Context 'When PublishToGitHub is requested without PublishToPSGallery' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-gh-only'
            New-FakeArtefactRoot -Root $artefactRoot
            $psd1 = Join-Path $artefactRoot 'Locksmith2.psd1'
            Set-Content -Path $psd1 -Value "@{ ModuleVersion = '2026.5.141234' }"
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    upload_url = 'https://uploads.github.com/repos/jakehildreth/Locksmith2/releases/1/assets{?name,label}'
                }
            }
        }

        It 'Should create a GitHub release' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha 'abc123'
            Should -Invoke Invoke-RestMethod -ParameterFilter { $Uri -eq 'https://api.github.com/repos/jakehildreth/Locksmith2/releases' } -Exactly 1
        }

        It 'Should not call Publish-Module' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false -PublishToGitHub -GitHubAPIKey 'ghp_fake'
            Should -Invoke Publish-Module -Exactly 0
        }
    }

    Context 'When PublishToGitHub is requested but no token is provided' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-gh-no-token'
            New-FakeArtefactRoot -Root $artefactRoot
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod {}
        }

        It 'Should not create a GitHub release' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToGitHub
            Should -Invoke Invoke-RestMethod -Exactly 0
        }

        It 'Should write an error' {
            { Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToGitHub -ErrorAction Stop } |
                Should -Throw '*-PublishToGitHub was specified but neither -GitHubAPIKey nor -GitHubAPIPath was provided.*'
        }
    }

    Context 'When PublishToGitHub is requested outside GitHub Actions' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-gh-local'
            New-FakeArtefactRoot -Root $artefactRoot
            $psd1 = Join-Path $artefactRoot 'Locksmith2.psd1'
            Set-Content -Path $psd1 -Value "@{ ModuleVersion = '2026.5.141234' }"
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod {}
        }

        It 'Should not create a GitHub release' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha ''
            Should -Invoke Invoke-RestMethod -Exactly 0
        }

        It 'Should write an error' {
            { Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha '' -ErrorAction Stop } |
                Should -Throw '*-PublishToGitHub was specified but -GitHubSha was not provided and $env:GITHUB_SHA is not set. GitHub releases must be created from GitHub Actions.*'
        }
    }

    Context 'When packaging the GitHub release zip' {
        BeforeAll {
            $artefactRoot = 'TestDrive:\root-gh-zip-layout'
            New-FakeArtefactRoot -Root $artefactRoot
            $psd1 = Join-Path $artefactRoot 'Locksmith2.psd1'
            Set-Content -Path $psd1 -Value "@{ ModuleVersion = '2026.5.141234' }"
            Mock Save-Module {}
            Mock Update-ModuleManifest {}
            Mock Publish-Module {}
            Mock Compress-Archive {}
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    upload_url = 'https://uploads.github.com/repos/jakehildreth/Locksmith2/releases/1/assets{?name,label}'
                }
            }
        }

        It 'Should compress a top-level Locksmith2 folder' {
            Invoke-LS2PostBuildPublish -ArtefactRoot $artefactRoot -PublishToPSGallery:$false -PublishToGitHub -GitHubAPIKey 'ghp_fake' -GitHubSha 'abc123'
            $sep = [System.IO.Path]::DirectorySeparatorChar
            Should -Invoke Compress-Archive -ParameterFilter {
                $Path -like "*$($sep)Locksmith2" -or $Path -like "*$($sep)Locksmith2$($sep)"
            } -Exactly 1
        }
    }
}

