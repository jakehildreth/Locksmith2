#requires -Version 5.1
BeforeDiscovery {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    $allFunctionCases = [System.Collections.Generic.List[hashtable]]::new()

    $sourceFiles = Get-ChildItem -Recurse -Include '*.ps1' -Path @(
        (Join-Path $ModuleRoot 'Private'),
        (Join-Path $ModuleRoot 'Public')
    ) | Sort-Object FullName

    foreach ($file in $sourceFiles) {
        # Handle UTF-16LE (BOM: FF FE)
        $rawBytes = [System.IO.File]::ReadAllBytes($file.FullName)
        $encoding = if ($rawBytes.Length -ge 2 -and $rawBytes[0] -eq 0xFF -and $rawBytes[1] -eq 0xFE) {
            [System.Text.Encoding]::Unicode
        } else {
            [System.Text.Encoding]::UTF8
        }
        $content = [System.IO.File]::ReadAllText($file.FullName, $encoding)

        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput(
            $content, $file.FullName, [ref]$null, [ref]$parseErrors
        )
        if ($parseErrors) { continue }

        $functions = $ast.FindAll({
            $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true)

        foreach ($func in $functions) {
            $help = $func.GetHelpContent()

            # Actual parameter names extracted from the AST param() block
            $paramNames = @()
            if ($func.Body.ParamBlock -and $func.Body.ParamBlock.Parameters.Count -gt 0) {
                $paramNames = @($func.Body.ParamBlock.Parameters | ForEach-Object {
                    $_.Name.VariablePath.UserPath
                })
            }

            # Parameter names documented in .PARAMETER blocks (lowercased for comparison)
            $docParamNamesLower = @()
            if ($help -and $help.Parameters -and $help.Parameters.Count -gt 0) {
                $docParamNamesLower = @($help.Parameters.Keys | ForEach-Object { $_.ToLower() })
            }

            $codeParamNamesLower = @($paramNames | ForEach-Object { $_.ToLower() })

            # In param() but missing from CBH
            $missingParams = @($paramNames | Where-Object { $_.ToLower() -notin $docParamNamesLower })

            # In CBH .PARAMETER but not in param() — phantom entries
            $phantomParams = @($docParamNamesLower | Where-Object { $_ -notin $codeParamNamesLower })

            # [OutputType(...)] attribute declared on the param block
            $hasOutputType = $false
            if ($func.Body.ParamBlock -and $func.Body.ParamBlock.Attributes) {
                $hasOutputType = [bool]($func.Body.ParamBlock.Attributes |
                    Where-Object { $_.TypeName.Name -eq 'OutputType' })
            }

            $allFunctionCases.Add(@{
                FunctionName   = $func.Name
                FileName       = $file.Name
                HasSynopsis    = $help -and -not [string]::IsNullOrWhiteSpace($help.Synopsis)
                HasDescription = $help -and -not [string]::IsNullOrWhiteSpace($help.Description)
                ParamCount     = $paramNames.Count
                MissingParams  = $missingParams
                PhantomParams  = $phantomParams
                HasExample     = $help -and $help.Examples -and $help.Examples.Count -gt 0
                HasOutputType  = $hasOutputType
                HasOutputsDoc  = $help -and $help.Outputs -and $help.Outputs.Count -gt 0
            })
        }
    }

    $casesWithParams     = @($allFunctionCases | Where-Object { $_.ParamCount -gt 0 })
    $casesWithOutputType = @($allFunctionCases | Where-Object { $_.HasOutputType })
}

Describe 'CBH Synopsis' -Tag 'Unit', 'CBH' {
    It '<FunctionName> in <FileName> should have a non-empty .SYNOPSIS' -ForEach $allFunctionCases {
        $HasSynopsis | Should -BeTrue
    }
}

Describe 'CBH Description' -Tag 'Unit', 'CBH' {
    It '<FunctionName> in <FileName> should have a non-empty .DESCRIPTION' -ForEach $allFunctionCases {
        $HasDescription | Should -BeTrue
    }
}

Describe 'CBH Parameter Coverage' -Tag 'Unit', 'CBH' {
    It '<FunctionName> in <FileName> should document all parameters in CBH' -ForEach $casesWithParams {
        $MissingParams | Should -BeNullOrEmpty -Because "these parameters lack a .PARAMETER doc block: $($MissingParams -join ', ')"
    }
}

Describe 'CBH No Phantom Parameters' -Tag 'Unit', 'CBH' {
    It '<FunctionName> in <FileName> should not document non-existent parameters in CBH' -ForEach $allFunctionCases {
        $PhantomParams | Should -BeNullOrEmpty -Because "these .PARAMETER entries do not match any param() variable: $($PhantomParams -join ', ')"
    }
}

Describe 'CBH Example' -Tag 'Unit', 'CBH' {
    It '<FunctionName> in <FileName> should have at least one .EXAMPLE' -ForEach $allFunctionCases {
        $HasExample | Should -BeTrue
    }
}

Describe 'CBH Outputs Coverage' -Tag 'Unit', 'CBH' {
    It '<FunctionName> in <FileName> should document .OUTPUTS when [OutputType] is declared' -ForEach $casesWithOutputType {
        $HasOutputsDoc | Should -BeTrue -Because '[OutputType] is declared but .OUTPUTS is missing from CBH'
    }
}
