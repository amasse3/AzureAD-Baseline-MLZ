#Configure-AADTenantBaseline.ps1
<#
.SYNOPSIS

Applies MLZ identity baseline recommendations for a new Azure AD tenant.

.DESCRIPTION

Installs PowerShell modules, creates break-glass and admin user accounts, configures Authentication Methods, creates RBAC groups, configures Privileged Identity Management, configures Conditional Access, AAD settings for users, groups, and collaboration.

.INPUTS

ParametersJson (PS Object)

.OUTPUTS

System.String

.EXAMPLE

PS> .\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparams -All

PS> .\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparams -PSTools -Accounts -AuthNMethods -Groups -PIM -CA -UserGroupCollabSettings

.LINK

Placeholder

#>

Param(
    [Parameter(Mandatory=$false)]
    [PSCustomObject]$ParametersJson,
    [Parameter(Mandatory=$false)]
    [Switch]$All,
    [Parameter(Mandatory=$false)]
    [Switch]$PSTools,
    [Parameter(Mandatory=$false)]
    [Switch]$AdminUnits,
    [Parameter(Mandatory=$false)]
    [Switch]$EmergencyAccess,
    [Parameter(Mandatory=$false)]
    [Switch]$NamedAccounts,
    [Parameter(Mandatory=$false)]
    [Switch]$AuthNMethods,
    [Parameter(Mandatory=$false)]
    [Switch]$Groups,
    [Parameter(Mandatory=$false)]
    [Switch]$PIM,
    [Parameter(Mandatory=$false)]
    [Switch]$ConditionalAccess,
    [Parameter(Mandatory=$false)]
    [Switch]$UserGroupCollabSettings,
)


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

function UpdateUserCertIDs {
    Param ([string]$UPN,[string]$CACPrincipalName)
    $certids = "X509:<PN>$CACPrincipalName"
    $body=@{
        "@odata.context"= "https://graph.microsoft.us/beta/$metadata#users/$entity"
        "authorizationInfo"= @{
            "certificateUserIds"= @(
                $certids
            )
        }
    }
    write-host -ForegroundColor Yellow "UPDATE: Adding userCertificateIds for $UPN. New Value: $CACPrincipalName"
    Update-MgUser -UserId $UPN -BodyParameter $body
}

#TO DO - Is there a way to do this?
function FindLicenseSKUID {
    Param([String]$SKUName)
    

    #find license
    Return $LicenseSKUID
}

function AssignLicenseToGroup {
    Param([String]$GroupID,[String]$SKUID,[Array]$DisabledPlans)
    $params = @{
        AddLicenses = @(
            @{
                DisabledPlans = $DisabledPlans
                SkuId = $SKUID
            }
        )
	    RemoveLicenses = @(
	    )
    }
}




Set-MgGroupLicense -GroupId $groupId -BodyParameter $params
#endregion

#region parameters
$Environment = $ParametersJson.GlobalParemeterSet.Environment
$AUs = $mlzparams.GlobalParemeterSet.MissionAUs
$DefaultEAMissionCode = "EA"
$PWDLength = $mlzparams.GlobalParemeterSet.PWDLength


#endregion

#region PSTools

#endregion

#region Accounts

#import modules
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Identity.DirectoryManagement

#connect MS Graph
Connect-MgGraph -Scopes "User.Read.All","User.ReadWrite.All","Group.ReadWrite.All","Organization.Read.All","RoleManagement.ReadWrite.Directory" -Environment $Environment
Select-MgProfile -Name "beta"

#create MLZ AU

$params = @{
        DisplayName = "MLZ Core Users"
        Description = "Created by MLZ identity add-on ($(get-date))"
        MembershipRule = "(user.Department -match `"MLZ`")"
    }
New-MgAdministrativeUnit -BodyParameter $params

$params = @{
        DisplayName = "MLZ Core RBAC Groups",
        Description = "Created by MLZ identity add-on ($(get-date))",
        Visibility = "HiddenMembership",
        MembershipRule = "(user.Department -match `"MLZ`")"
    }
New-MgAdministrativeUnit -BodyParameter $params

#create Mission AUs
foreach ($AU in $AUs) {
    $params = @{
        DisplayName = "$AU Users"
        Description = "Created by MLZ identity add-on ($(get-date))"
        MembershipType = "Dynamic"
        MembershipRule = "(user.Department -match `"$AU`")"
        MembershipRuleProcessingState = "On"
    }

    New-MgAdministrativeUnit -BodyParameter $params

    $params @{
        DisplayName = "$AU RBAC Groups"
	    Description = "Created by MLZ identity add-on ($(get-date))"
        Visibility = "HiddenMembership",
    }

    New-MgAdministrativeUnit -BodyParameter $params

    $params @{
        DisplayName = "$AU Devices"
	    Description = "Created by MLZ identity add-on ($(get-date))"
    }

    New-MgAdministrativeUnit -BodyParameter $params
}

#create break glass users
$breakglassusers = $ParametersJson.StepParameterSet.Accounts.Parameters.EAAccountNames 
foreach ($user in $breakglassusers) {
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
        #To Do: Catch group already existing
    }
}

#TO DO - Add license to users or groups

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

#create named admin accounts


#endregion

#region AuthNMethods

#endregion

#region Groups

#endregions

#region PIM

#endregion

#region CA

#endregion

#region UserGroupCollabSettings

#endregion