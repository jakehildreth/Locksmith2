Clear-Host
Write-Host @"
█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█
█ ▄████▄                █
█ ██  █████████████████ █
█ ▀████▀        ██  ██  █
█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█

█████████████████████████
██▀    ▀█████████████████
██  ██                 ██
██▄    ▄████████  ██  ███
█████████████████████████
"@ -ForegroundColor ([enum]::GetValues(([System.ConsoleColor])) | Get-Random) -BackgroundColor Black