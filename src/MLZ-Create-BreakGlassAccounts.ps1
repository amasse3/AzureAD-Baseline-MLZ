#MLZ-CreateBreakGlassAccounts.ps1
<#
.SYNOPSIS

Creates 2 Emergency Access accounts and adds them to the Azure AD Global Administrator Role.

.DESCRIPTION

Creates an Emergency Access account group, 2 Azure AD users added to Global Administrator Role. The script provides `
Optional inputs for AccountNameBase, PWDLength, EAGroupName, and Environment.

.INPUTS

AccountNameBase,PWDLength,EAGroupName,Environment

.OUTPUTS

System.String

.EXAMPLE

PS> ./MLZ-CreateBreakGlassAccounts.ps1 -AccountNameBase "MLZEAAcct" -PWDLength 16 -EAGroupName "Emergency Access Accounts"

.LINK

Placeholder

#>

Param(
    [Array]$AccountNameBase,
    [String]$EAGroupName,
    [Parameter(Mandatory=$false)]
    [ValidateRange(8,256)]
    [Int]$PWDLength,
    [Parameter(Mandatory=$false)]
    [ValidateSet("Global","USGov","USGovDoD")]
    [string]$Environment
)

#region defaultvalues
$DefaultEAAccountNames = @("MLZ-EA01","MLZ-EA02")
$DefaultEAGroupName = "Emergency Access Accounts"
$DefaultEAMissionCode = "EA"
$DefaultEnvironment = "Global"
$DefaultPWDLength = 16

#if no parameters, use default values
if ($AccountNameBase) {
    $EAccountNames = @($AccountNameBase+"01",$AccountNameBase+"02")
} else {
    $EAccountNames = $DefaultEAAccountNames
}
if (!($EAGroupName)){$EAGroupName=$DefaultEAGroupName}
if (!($PWDLength)){$PWDLength=$DefaultPWDLength}
if (!($Environment)){$Environment=$DefaultEnvironment}
#endregion

#region functions
function New-TempPassword {
    Param([int]$length)
    $ascii=$NULL;For ($a=33;$a –le 126;$a++) {$ascii+=,[char][byte]$a}

    For ($loop=1; $loop –le $length; $loop++) {
        $TempPassword+=($ascii | GET-RANDOM)
    }
    return $TempPassword
}
function New-MLZAADUser {
    Param([object]$user,[string]$MissionCode,[int]$PasswordLength)
    #check for existing user
    try{$userobj = Get-MgUser -UserId $user.UserPrincipalName -ErrorAction SilentlyContinue} catch {} #Catch to be implemented
    if ($user) {
        Write-Host "UPDATE: User $($user.UPN) already exists in directory. Assigning Mission Code $MissionCode" -ForegroundColor Yellow
    } else {
        Write-Host "NEW: Creating user $($user.UserPrincipalName)." -ForegroundColor Yellow
        $TempPassword = New-TempPassword -length $PasswordLength
        $PasswordProfile = @{
            ForceChangePasswordNextSignIn = $true
            Password = $TempPassword
        }
        #Prepare attributes
        $MailNickname = $user.UserPrincipalName.Split("@")[0]
        $userobj = New-MgUser -DisplayName $user.DisplayName -AccountEnabled -PasswordProfile $PasswordProfile -MailNickName $MailNickname -UserPrincipalName $user.UserPrincipalName -Mail $user.Mail -Department $MissionCode
    }
    Return $userobj
}
#endregion

#region main script

#load module
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Identity.DirectoryManagement

#connect MS Graph
Connect-MgGraph -Scopes "User.Read.All","User.ReadWrite.All","Group.ReadWrite.All","Organization.Read.All","RoleManagement.ReadWrite.Directory" -Environment $Environment
Select-MgProfile -Name "beta"

#create accounts
$UserArray = @()
foreach ($acct in $EAccountNames) {
    $userobj = @{"UserPrincipalName" = $EAAccountName;"DisplayName" = $EAAccountName+" (MLZ)"}
    $UserArray += New-MLZAADUser -user $userobj -MissionCode $DefaultEAMissionCode -PasswordLength $PWDLength
}

#create emergency access account group
$domain = $(Get-MgDomain | Where-Object{$_.IsInitial -eq $true}).Id
$group = New-MgGroup -DisplayName $EAGroupName -MailEnabled:$False  -MailNickName $($EAGroupName+"@"+$domain) -SecurityEnabled -Description "Created by MLZ Identity Setup on $(get-date)" -IsAssignableToRole:$true

#add users to group
foreach ($user in $UserArray) {
    Try{
        New-MgGroupMember -GroupID $group.Id -DirectoryObjectId $user.Id -ErrorAction SilentlyContinue
    } Catch {
        #To Do
    }
}

#assign group to the PIM Role (reserved roleID, same for all tenants)
$GA = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId "62e90394-69f5-4237-9190-012177145e10"

$params = @{
    "PrincipalId" = $group.Id
    "RoleDefinitionId" = $GA.Id
    "Justification" = "Add permanent assignment for Emergency Access accounts."
    "DirectoryScopeId" = "/"
    "Action" = "AdminAssign"
    "ScheduleInfo" = @{
        "StartDateTime" = Get-Date
        "Expiration" = @{
            "Type" = "NoExpiration"
        }
    }
}

New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params

Write-Host -ForegroundColor Cyan "Emergency Access Accounts Created:`n  $($UserArray[0].UserPrincipalName)`n  $($UserArray[1].UserPrincipalName)`
`nAdded to Group: $($group.DisplayName) (ID = $($group.Id))`n`nAssigned Permanently to Global Administrator Role."

Write-Host -ForegroundColor Green "Script Complete."

#endregion