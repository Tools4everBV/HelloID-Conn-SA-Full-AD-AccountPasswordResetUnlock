try {
    $searchValue = $dataSource.searchValue
    $searchQuery = '*' + $dataSource.searchValue + '*'
    $searchOUs = $ADusersSearchOU

    Write-Information "SearchQuery: $searchQuery"
    Write-Information "SearchDepartment: $searchDepartment"
    Write-Information "SearchBase: $searchOUs"
         
    $ous = $searchOUs | ConvertFrom-Json
    $users = foreach ($item in $ous) {
        Get-ADUser -Filter { (Name -like $searchQuery -or DisplayName -like $searchQuery -or userPrincipalName -like $searchQuery -or mail -like $searchQuery) } -SearchBase $item.ou -properties SamAccountName, displayName, UserPrincipalName, Description, company, Department, Title
    }
         
    $users = $users | Sort-Object -Property DisplayName
    $resultCount = @($users).Count
    Write-Information "Result count: $resultCount"
         
    if ($resultCount -gt 0) {
        foreach ($user in $users) {
            $returnObject = @{SamAccountName = $user.SamAccountName; displayName = $user.displayName; UserPrincipalName = $user.UserPrincipalName; Description = $user.Description; Company = $user.company; Department = $user.Department; Title = $user.Title; }
            Write-Output $returnObject
        }
    }
    
}
catch {
    $msg = "Error searching AD user [$searchValue]. Error: $($_.Exception.Message)"
    Write-Error $msg
}
