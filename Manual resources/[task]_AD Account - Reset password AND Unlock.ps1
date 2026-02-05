# variables configured in form
$user = $form.gridUsers
$blnreset = [System.Convert]::ToBoolean($form.blnreset)
$password = $form.password
$blnchangePasswordAtLogon = [System.Convert]::ToBoolean($form.blnchangenextlogon)
$blnunlock = [System.Convert]::ToBoolean($form.blnunlock)

# Set debug logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

if ($blnreset -eq $true) {
    try {
        $actionMessage = "resetting AD account password for user [$($user.userPrincipalName)] with objectguid [$($user.ObjectGuid)]"

        Set-ADAccountPassword -Identity $user.ObjectGuid -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $password -Force)
        Write-Information "Successfully reset password of AD account: [$($user.userPrincipalName)]."

        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Successfully reset password of AD account: [$($user.userPrincipalName)] with objectguid [$($user.ObjectGuid)]" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $user.userPrincipalName # optional (free format text) 
            TargetIdentifier  = $user.ObjectGuid # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {

        $ex = $PSItem
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    
        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Failed to reset password of AD account: [$($user.userPrincipalName)]. Error: $($_.Exception.Message)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $user.userPrincipalName # optional (free format text) 
            TargetIdentifier  = $user.ObjectGuid # optional (free format text) 
        }
        Write-Information -Tags "Audit" -MessageData $log
        Write-Warning $warningMessage   
        Write-Error $auditMessage
    }
}

if ($blnchangePasswordAtLogon -eq $true) {
    try {
        $actionMessage = "changing attribute ChangePasswordAtNextLogon for user [$($user.userPrincipalName)] with objectguid [$($user.ObjectGuid)]"

        Set-ADUser -Identity $user.ObjectGuid -ChangePasswordAtLogon $blnchangePasswordAtLogon
        Write-Information "Successfully changed attribute ChangePasswordAtNextLogon of AD account: [$($user.userPrincipalName)] with objectguid [$($user.ObjectGuid)]"

        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Successfully changed attribute ChangePasswordAtNextLogon of AD account: [$($user.userPrincipalName)] with objectguid [$($user.ObjectGuid)]" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $user.userPrincipalName # optional (free format text) 
            TargetIdentifier  = $user.ObjectGuid # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {

        $ex = $PSItem
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Failed to change attribute ChangePasswordAtNextLogon of AD account: [$($user.userPrincipalName)] with objectguid [$($user.ObjectGuid)]. Error: $($_.Exception.Message)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $user.userPrincipalName # optional (free format text) 
            TargetIdentifier  = $user.ObjectGuid # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
        Write-Warning $warningMessage   
        Write-Error $auditMessage
    }
}

if ($blnunlock -eq $true) {
    try {

        Unlock-ADAccount -Identity $user.ObjectGuid
        Write-Information "Successfully unlocked AD account: [$($user.userPrincipalName)]"

        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Successfully unlocked AD account: [$($user.userPrincipalName)]" # required (free format text) 
            IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $user.userPrincipalName # optional (free format text) 
            TargetIdentifier  = $user.ObjectGuid # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
    }
    catch {

        $ex = $PSItem
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

        $Log = @{
            Action            = "UpdateAccount" # optional. ENUM (undefined = default) 
            System            = "ActiveDirectory" # optional (free format text) 
            Message           = "Failed to unlock AD account: [$($user.userPrincipalName)] with objectguid [$($user.ObjectGuid)]. Error: $($_.Exception.Message)" # required (free format text) 
            IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
            TargetDisplayName = $user.userPrincipalName # optional (free format text) 
            TargetIdentifier  = $user.ObjectGuid # optional (free format text) 
        }
        #send result back  
        Write-Information -Tags "Audit" -MessageData $log
        Write-Warning $warningMessage   
        Write-Error $auditMessage
    }
}
