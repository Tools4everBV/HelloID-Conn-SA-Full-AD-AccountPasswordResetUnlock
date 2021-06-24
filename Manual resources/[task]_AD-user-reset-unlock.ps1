try {
    $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
    HID-Write-Status -Message "Found AD user [$userPrincipalName]" -Event Information
    HID-Write-Summary -Message "Found AD user [$userPrincipalName]" -Event Information
} catch {
    HID-Write-Status -Message "Could not find AD user [$userPrincipalName]. Error: $($_.Exception.Message)" -Event Error
    HID-Write-Summary -Message "Failed to find AD user [$userPrincipalName]" -Event Failed
}

if($blnreset -eq 'true'){
    try {
    	Set-ADAccountPassword -Identity $adUser -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
    	Set-ADUser -Identity $adUser -ChangePasswordAtLogon ([System.Convert]::ToBoolean($blnchangenextlogon))
    	HID-Write-Status -Message "Password reset: $userPrincipalName .Change at next logon: $blnchangenextlogon" -Event Success
    	HID-Write-Summary -Message "Password reset: $userPrincipalName .Change at next logon: $blnchangenextlogon" -Event Success
    } catch {
        HID-Write-Status -Message "Could not reset password [$userPrincipalName]. Error: $($_.Exception.Message)" -Event Error
        HID-Write-Summary -Message "Failed to reset pasword [$userPrincipalName]" -Event Failed
    }
}

if($blnunlock -eq 'true'){
    try {
	    Unlock-ADAccount -Identity $adUser
	    HID-Write-Status -Message "Unlock account: $userPrincipalName" -Event Success
	    HID-Write-Summary -Message "Unlock account: $userPrincipalName" -Event Success
    } catch {
        HID-Write-Status -Message "Could not unlock [$userPrincipalName]. Error: $($_.Exception.Message)" -Event Error
        HID-Write-Summary -Message "Failed to unlock [$userPrincipalName]" -Event Failed
    }
}
