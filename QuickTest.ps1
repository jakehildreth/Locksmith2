Set-Location ~\Documents\Locksmith2\
Import-Module .\Locksmith2.psd1 -Force
$Credential = New-Credential -User 'adcs.goat\Administrator'
$Forest = 'adcs.goat'
$RootDSE = Get-RootDSE -Forest $Forest -Credential $Credential
$AdcsObject = Get-AdcsObject -RootDSE $RootDSE -Credential $Credential
$SubCA = $AdcsObject | Where-Object Name -eq SubCA