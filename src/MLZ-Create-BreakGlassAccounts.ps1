#MLZ-CreateBreakGlassAccounts.ps1
<#
.SYNOPSIS

Creates 2 Emergency Access accounts and adds them to the Azure AD Global Administrator Role.

.DESCRIPTION

Creates an Emergency Access account group, 2 Azure AD users added to Global Administrator Role. The script provides `
Optional inputs for AccountNameBase, PWDLength, and EAGroupName.

.INPUTS

AccountNameBase,PWDLength,EAGroupName

.OUTPUTS

System.String

.EXAMPLE

PS> ./MLZ-CreateBreakGlassAccounts.ps1 -AccountNameBase "MLZEAAcct" -PWDLength 16 -EAGroupName "Emergency Access Accounts"

.LINK

Placeholder

#>

Param($AccountNameBase,$PWDLength,$EAGroupName)

#functions
function randompwd {

}

#Connect to Microsoft Graph

#