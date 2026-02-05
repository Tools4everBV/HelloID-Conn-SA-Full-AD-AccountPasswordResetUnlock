# HelloID-Conn-SA-Full-AD-AccountPasswordResetUnlock

| :information_source: Information |
| :------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

## Description
_HelloID-Conn-SA-Full-AD-AccountPasswordResetUnlock_ is a delegated form designed for use with HelloID Service Automation (SA). It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can manage Active Directory user account passwords and account lock status. The following options are available:
1. Search for and select the target Active Directory (AD) user account.
2. Reset the password and/or unlock the selected AD user account.
3. A random password will be generated, but the user has the option to change it if needed.
4. The generated password will be validated against a regular expression (RegEx) to ensure it meets security requirements.
5. The password can be reset, and the option to require the user to change their password at the next logon can be enabled, along with unlocking the account if necessary.

## Getting started
### Requirements

- **Active Directory Access**:<br>
  The connector requires access to an Active Directory domain with sufficient permissions to reset user passwords and unlock user accounts. A service account with appropriate AD permissions is necessary.
- **HelloID Agent**:<br>
  A HelloID Agent must be installed and configured to communicate with the Active Directory domain.
- **PowerShell Support**:<br>
  The HelloID Agent must have PowerShell available with Active Directory module support.

### Connection settings

The following user-defined variables are used by the connector.

| Setting  | Description                        | Mandatory |
| -------- | ---------------------------------- | --------- |
| ADusersSearchOU | Array of Active Directory OUs for scoping AD user accounts in the search result of this form | Yes |

## Remarks
 
### Password Policy
- The delegated form allows administrators to reset user passwords according to the organization's password policy requirements.
- Password complexity requirements are enforced by the Active Directory domain policy.
 
### Account Unlock
- The unlock account functionality is optional and can be enabled independently from the password reset.
- If an account is not locked, the unlock operation will be skipped without errors.
 
### User Search
- Search Functionality: Users can search for accounts using a wildcard (`*`) to return all users within the specified OUs, or by entering partial text to search across user attributes.
- The search scope is limited to the OUs defined in the `ADusersSearchOU` variable.

### PowerShell Module
This connector uses the **ActiveDirectory** PowerShell module for managing Active Directory user accounts.
 
- [ActiveDirectory Module Documentation](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)
 
### Cmdlets
The following PowerShell cmdlets are used by the connector:
 
| Cmdlet | Description |
| ------ | ----------- |
| Get-ADUser | Retrieves Active Directory user accounts |
| Set-ADAccountPassword | Resets the password for an Active Directory account |
| Set-ADUser | Modifies properties of an Active Directory user |
| Unlock-ADAccount | Unlocks an Active Directory account that has been locked out |
 
### Cmdlet documentation
- [Get-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser)
- [Set-ADAccountPassword](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword)
- [Set-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-aduser)
- [Unlock-ADAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/unlock-adaccount)

## Getting help
> :bulb: **Tip:**  
> _For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages_.

## HelloID docs
The official HelloID documentation can be found at: [https://docs.helloid.com/](https://docs.helloid.com/)
