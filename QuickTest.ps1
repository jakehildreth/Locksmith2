Set-Location ~\Documents\Locksmith2\
Import-Module .\Locksmith2.psd1 -Force
# $Credential = New-Credential -User 'adcs.goat\Administrator'
$Forest = 'adcs.goat'
$results = Invoke-Locksmith2 -Forest $Forest -Credential $Credential -Verbose -SkipPowerShellCheck
$stores = Get-Locksmith2Stores
$stores.PrincipalStore.Values