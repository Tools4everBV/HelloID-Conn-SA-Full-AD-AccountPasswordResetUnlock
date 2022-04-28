$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# variables configured in form
$userPrincipalName = $form.gridUsers.UserPrincipalName
$blnreset = [System.Convert]::ToBoolean($form.blnreset)
$password = $form.password
$changePasswordAtLogon = [System.Convert]::ToBoolean($form.blnchangenextlogon)
$blnunlock = [System.Convert]::ToBoolean($form.blnunlock)

if ($blnreset -eq $true) {
    try {
        $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
        Write-Verbose "Found AD acount: $($userPrincipalName)"

        $resetPasswordADUser = Set-ADAccountPassword -Identity $adUser -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
        $updateADUser = Set-ADUser -Identity $adUser -ChangePasswordAtLogon $changePasswordAtLogon
        Write-Information "Successfully reset password of AD account: $($userPrincipalName). Change at next logon: $($changePasswordAtLogon)"

        $adUserSID = $([string]$adUser.SID)
        $adUserdisplayName = $([string]$adUser.DisplayName)
        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Successfully reset password of AD account: $($userPrincipalName). Change at next logon: $($changePasswordAtLogon)" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $adUserdisplayName # optional (free format text) 
            TargetIdentifier  = $adUserSID # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {
        Write-Error "Could not reset password of AD account: $($userPrincipalName). Change at next logon: $($changePasswordAtLogon). Error: $($_)"
    
        $adUserSID = $([string]$adUser.SID)
        $adUserdisplayName = $([string]$adUser.DisplayName)   
        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Failed to reset password of AD account: $($userPrincipalName). Change at next logon: $($changePasswordAtLogon). Error: $($_.Exception.Message)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $adUserdisplayName # optional (free format text)
            TargetIdentifier  = $adUserSID # optional (free format text)
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
}

if ($blnunlock -eq $true) {
    try {
        $adUser = Get-ADuser -Filter { UserPrincipalName -eq $userPrincipalName }
        Write-Verbose "Found AD account: $($userPrincipalName)"

        $unlockADUser = Unlock-ADAccount -Identity $adUser
        Write-Information "Successfully unlocked AD account: $($userPrincipalName)"

        $adUserSID = $([string]$adUser.SID)
        $adUserdisplayName = $([string]$adUser.DisplayName)
        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Successfully unlocked AD account: $($userPrincipalName)" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $adUserdisplayName # optional (free format text) 
            TargetIdentifier  = $adUserSID # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {
        Write-Error "Could not unlock AD account: $($userPrincipalName). Error: $($_)"

        $adUserSID = $([string]$adUser.SID)
        $adUserdisplayName = $([string]$adUser.DisplayName)   
        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Failed to unlock AD account: $($userPrincipalName). Error: $($_.Exception.Message)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $adUserdisplayName # optional (free format text)
            TargetIdentifier  = $adUserSID # optional (free format text)
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
}
