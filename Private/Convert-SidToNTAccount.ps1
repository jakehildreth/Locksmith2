$sid = 'S-1-5-21-2298154379-2017097123-1132854487-519'
$searchBase = $RootDSE.Parent
$searcherDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry(
    $searchBase,
    $Credential.UserName,
    $Credential.GetNetworkCredential().Password
)
$searcher = New-Object System.DirectoryServices.DirectorySearcher($searcherDirectoryEntry)
$searcher.Filter = "(objectSid=$sid)"
$result = $searcher.FindOne()
$ntAccountName = $result.Properties['sAMAccountName'][0]