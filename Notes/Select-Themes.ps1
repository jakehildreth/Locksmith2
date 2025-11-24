$Themes = foreach ($fg in [enum]::GetValues([System.ConsoleColor]) ) {
    foreach ($bg in [enum]::GetValues([System.ConsoleColor]) ) {
        Show-Logo -ForegroundColor $fg -BackgroundColor $bg
        Write-Host "ForegroundColor = $fg, BackgroundColor = $bg"
        $choices = [System.Management.Automation.Host.ChoiceDescription[]] @(
            [System.Management.Automation.Host.ChoiceDescription]::new("&Yes", "Like this combination")
            [System.Management.Automation.Host.ChoiceDescription]::new("&No", "Skip to next")
        )
        $result = $Host.UI.PromptForChoice("Color Selection", "Like this combination?", $choices, 1)
        if ($result -eq 0) {
            [PSCustomObject]@{
                Name = "$fg,$bg"
                ForegroundColor = $fg
                BackgroundColor = $bg
            }
        }
    }
}

$Themes | Export-Csv -Path Themes.csv -NoTypeInformation