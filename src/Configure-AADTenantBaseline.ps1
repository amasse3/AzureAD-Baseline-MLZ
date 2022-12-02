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

PS> .\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparams -PSTools -Accounts -AuthNMethods -Groups -PIM -ConditionalAccess -TenantPolicies -Verbose

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
    [Switch]$TenantPolicies,
    [Parameter(Mandatory=$false)]
    [Switch]$Verbose
)


#region functions
function New-TempPassword {
    Param([int]$length)
    $ascii=$NULL;For ($a=33;$a -le 126;$a++) {$ascii+=,[char][byte]$a}

    For ($loop=1; $loop -le $length; $loop++) {
        $TempPassword+=($ascii | GET-RANDOM)
    }
    return $TempPassword
}

function New-MLZAADUser {
    Param(
        [object]$user,
        [int]$PasswordLength
    )
    #check for existing user
    try{
        $userobj = Get-MgUser -UserId $user.UserPrincipalName -ErrorAction SilentlyContinue
    } catch {} #Catch to be implemented
    
    if ($userobj) {
        Write-Host "UPDATE: User $($user.UserPrincipalName) already exists in directory. Assigning Mission Code $MissionCode" -ForegroundColor Yellow
    } else {
        Write-Host "NEW: Creating user $($user.UserPrincipalName)." -ForegroundColor Yellow
        $TempPassword = New-TempPassword -length $PasswordLength
        $PasswordProfile = @{
            ForceChangePasswordNextSignIn = $true
            Password = $TempPassword
        }

        if (!($user.MailNickname)) {$MailNickname = $user.UserPrincipalName.split("@")[0]}else{$MailNickname = $user.MailNickname}
        if (!($user.UsageLocation)) {$usagelocation = "US"} else {$usagelocation = $user.UsageLocation}
        
        $userobj = New-MgUser -DisplayName $user.DisplayName -AccountEnabled -PasswordProfile $PasswordProfile -MailNickName $MailNickname -UserPrincipalName $user.UserPrincipalName -Mail $user.Mail -Department $user.MissionCode -BusinessPhones @($user.PhoneNumber)
    }

    Return $userobj
}

function Update-UserCertIDs {
    Param ([string]$UPN,[string]$CACPrincipalName,[string]$MSGraphURI)
    $certids = "X509:<PN>$CACPrincipalName"
    $body=@{
        "@odata.context"= "$MSGraphURI/$metadata#users/$entity"
        "authorizationInfo"= @{
            "certificateUserIds"= @(
                $certids
            )
        }
    }
    write-host -ForegroundColor Yellow "UPDATE: Adding userCertificateIds for $UPN. New Value: $CACPrincipalName"
    Update-MgUser -UserId $UPN -BodyParameter $body
}

function New-MLZAdminUnit {
    Param([object]$BodyParameter)

    Try{
        $AU = Get-MgAdministrativeUnit | ?{$_.DisplayName -eq $($BodyParameter.displayName)} -ErrorAction SilentlyContinue
    } Catch {}

    if ($AU) {
        $msg = "Administrative unit " + $AU.DisplayName + " already exists."
        Write-Host $msg
    } else {
        Write-host -ForegroundColor yellow "Adding Administrative Unit $($BodyParameter.displayName)."
        $AU = New-MgAdministrativeUnit -BodyParameter $($BodyParameter | convertto-json)
    }
    Return $AU
}

function Convert-MLZAUFromTemplate {
    Param([object]$template,[string]$missionAU)
    #Deep copy object
    $mt = $template | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv

    #update fields
    $mt.displayName = $mt.displayName -replace "ZZZ",$missionAU
    $mt.description = $mt.description -replace "ZZZ",$missionAU  
    Return $mt
}

function Build-MemberberArrayParams {
    Param([Array]$members,$MSGraphURI,$objectType)
    $out = @()
    foreach ($member in $members) {
        $out += "$MSGraphURI/$objectType/$member"
    }

    $params = @{"Members@odata.bind" = $out}

    Return $params
}
#endregion

### Testing - comment this line
$ParametersJson = $(Get-Content .\mlz-aad-parameters.json) | ConvertFrom-Json
###

#region parameters
#sets variables for some global parameters
$Environment = $ParametersJson.GlobalParameterSet.Environment
$PWDLength = $ParametersJson.GlobalParameterSet.PWDLength
$MissionAUs = $ParametersJson.GlobalParameterSet.MissionAUs
$License = $ParametersJson.GlobalParameterSet.License | ConvertTo-Json

$upnsuffix = $(Get-MgDomain | ?{$_.IsInitial -eq $true}).Id
Switch ($Environment) {
    Global {$MSGraphURI = "https://graph.microsoft.com/beta"}
	USGov {$MSGraphURI = "https://graph.microsoft.us/beta"}
    USGovDoD {$MSGraphURI = "https://graph.microsoft.us/beta"}
}
#endregion

#region PSTools
if ($PSTools -or $All) {
    $modules = $mlzparams.StepParameterSet.PSTools.parameters.Modules
    foreach ($module in $modules) {
        if ($Verbose) {
            Install-Module $modules -Verbose
        } else {
            Install-Module $modules -Confirm
        }
    }
}
#endregion

#region AdminUnits
if ($AdminUnits -or $All) {
    Import-Module Microsoft.Graph.Identity.DirectoryManagement
    Connect-MgGraph -Scopes AdministrativeUnit.ReadWrite.All -Environment $Environment

    #create core AU
    $CoreAU = $ParametersJson.StepParameterSet.AdminUnits.parameters.CoreAU
    $CoreAUObj = New-MLZAdminUnit -BodyParameter $CoreAU

    #read in templates
    $MissionAUGroupTemplate = $ParametersJson.StepParameterSet.AdminUnits.parameters.MissionAUGroupTemplate
    $MissionAUUserTemplate = $ParametersJson.StepParameterSet.AdminUnits.parameters.MissionAUUserTemplate

    #Add Mission AUs
    foreach ($missionAU in $MissionAUs) {
        #Add Groups AU
        $GroupsAU = Convert-MLZAUFromTemplate -template $MissionAUGroupTemplate -missionAU $MissionAU
        New-MLZAdminUnit -BodyParameter $GroupsAU | Out-Null
       
        #Add Users AU
        $UsersAU = Convert-MLZAUFromTemplate -template $MissionAUUserTemplate -missionAU $MissionAU
        New-MLZAdminUnit -BodyParameter $UsersAU | Out-Null
    }
}
#endregion

#region EmergencyAccess
if ($EmergencyAccess -or $All) {
    Import-Module Microsoft.Graph.Identity.DirectoryManagement
    Import-Module Microsoft.Graph.Users
    Import-Module Microsoft.Graph.Groups
    Connect-MgGraph -Scopes AdministrativeUnit.ReadWrite.All,User.ReadWrite.All,Group.ReadWrite.All -Environment $Environment

    $EAUsers = $ParametersJson.StepParameterSet.EmergencyAccess.parameters.Users
    $EAGroup = $ParametersJson.StepParameterSet.EmergencyAccess.parameters.EAGroup | ConvertTo-Json
    $EAAU = $ParametersJson.StepParameterSet.EmergencyAccess.parameters.AdministrativeUnit | ConvertTo-Json

    #Create Emergency Access Accounts
    $EAAccountObjects = @()
    foreach ($EAUser in $EAUsers) {
        $NewUPN = $EAUser.userPrincipalName + "@" + $upnsuffix
        $EAUser.userPrincipalName = $NewUPN
        $EAAccountObjects += New-MLZAADUser -user $EAUser -PasswordLength $PWDLength
    }

    #Create the Admin Unit
    $EAAUObj = New-MgAdministrativeUnit -BodyParameter $EAAU

    #Create Emergency Access Accounts group
    $EAGroupObj = New-MgGroup -BodyParameter $EAGroup

    #Add users to the group and AU
    $params = Build-MemberberArrayParams -members $EAAccountObjects.Id -MSGraphURI $MSGraphURI -objectType "users"

    Update-MgAdministrativeUnit -AdministrativeUnitId $EAAUObj.Id -BodyParameter $params
    Update-MgGroup -GroupId $EAGroupObj.Id -BodyParameter $params

    #Assign licenses to the group
    Set-MgGroupLicense -GroupId $EAGroupObj.Id -BodyParameter $License

    #Assign Global Admin role
    $GARoleObj = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId "62e90394-69f5-4237-9190-012177145e10"

    $params = @{
        "PrincipalId" = $EAGroupObj.Id
        "RoleDefinitionId" = $GARoleObj.Id
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
}

Write-Host -ForegroundColor Green "Completed creating EA accounts"
#endregion

#region NamedAccounts
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Connect-MgGraph -Scopes AdministrativeUnit.ReadWrite.All,User.ReadWrite.All,Group.ReadWrite.All -Environment $Environment

$UserCSV = Import-Csv $ParametersJson.GlobalParameterSet.UserCSVRelativePath

<#testing
$UserCSV = Import-Csv -Path .\mlztest.csv
#>

$validdomains = Get-MgDomain | ?{$_.IsVerified -eq $true}
$initialdomain = $validdomains | ?{$_.IsInitial -eq $true}

$NamedAdmins = @()
foreach ($user in $UserCSV) {
    #verify domain suffix is correct, set to intial domain otherwise
    $suffix = $user.UserPrincipalName.Split("@")[1]
    if (!($validdomains.id -match $suffix)) {
        $user.UserPrincipalName = $user.UserPrincipalName.Split("@")[0]+"@"+$initialdomain
    }
    #create the admin account
    $NamedAdmins += New-MLZAADUser -user $user -PasswordLength $PWDLength
}

#update users that have certificateUserIds value
$certificateUserIDUsers = $UserCSV | ?{$_.CACPrincipalName}

#if ($certificateUserIDUsers) {write-host "waiting 5 seconds...";Start-Sleep -s 5}
foreach ($user in $certificateUserIDUsers) {
    Update-UserCertIDs -UPN $user.UserPrincipalName -CACPrincipalName $user.CACPrincipalName -MSGraphURI $MSGraphURI
}

#create license group and assign licenses
$LicenseGroup = $ParametersJson.StepParameterSet.NamedAccounts.parameters.LicenseGroup | ConvertTo-Json
$LicenseGroupObj = New-MgGroup -BodyParameter $LicenseGroup
Set-MgGroupLicense -GroupId $LicenseGroupObj.Id -BodyParameter $License

#add to MLZ core admin unit
$CoreAU = $ParametersJson.StepParameterSet.AdminUnits.parameters.CoreAU
$CoreAUObj = Get-MgAdministrativeUnit -Filter "startsWith(DisplayName, `'$($CoreAU.displayName)`')"
$CoreUserObj = Get-MgUser -Filter "startsWith(Department,`'MLZ`')"
$CoreUserRefArray = @($CoreUserObj.Id)
$params = Build-MemberberArrayParams -members $CoreUserRefArray -MSGraphURI $MSGraphURI -objectType "users"
Update-MgAdministrativeUnit -AdministrativeUnitId $CoreAUObj.Id -BodyParameter $params
#endregion

#region AuthNMethods
Import-Module Microsoft.Graph.Identity.SignIns
Connect-MgGraph -Scopes Policy.ReadWrite.AuthenticationMethod
$AuthNMethodsConfiguration = $ParametersJson.StepParameterSet.AuthNMethods.parameters.AuthenticationMethodsConfigurations

#Turn on FIDO2
Write-Host -ForegroundColor Yellow "Enabling FIDO2 Authentication Method"
$fido2 = $AuthNMethodsConfiguration | ?{$_.id -eq "fido2"}

$params = @{
	"@odata.context" = "$MSGraphURI/$metadata#authenticationMethodsPolicy"
	AuthenticationMethodConfigurations = @(
		@{
			"@odata.type" = $fido2.'@odata.type'
			Id = $fido2.id
			State = $fido2.state
			IsSelfServiceRegistrationAllowed = $fido2.isSelfServiceRegistrationAllowed
			IsAttestationEnforced = $fido2.isAttestationEnforced
            IncludeTargets = @(
                @{
                    targetType = "group"
                    Id = "all_users"
                }
            )
		}
	)
}
Update-MgPolicyAuthenticationMethodPolicy -BodyParameter $params

#Turn on MS Authenticator
Write-Host -ForegroundColor Yellow "Enabling Microsoft Authenticator Authentication Method"
$MicrosoftAuthenticator = $AuthNMethodsConfiguration | ?{$_.id -eq "MicrosoftAuthenticator"}
$params = @{
	"@odata.context" = "$MSGraphURI/$metadata#authenticationMethodsPolicy"
	AuthenticationMethodConfigurations = @(
		@{
			"@odata.type" = $MicrosoftAuthenticator.'@odata.type'
			Id = $MicrosoftAuthenticator.id
			State = $MicrosoftAuthenticator.state
			IncludeTargets = @(
                @{
                    targetType = "group"
                    Id = "all_users"
                }
            )
		}
	)
}
Update-MgPolicyAuthenticationMethodPolicy -BodyParameter $params

#Turn on x509certificates
Write-Host -ForegroundColor Yellow "Enabling Azure AD native CBA Authentication Method"
$X509Certificate = $AuthNMethodsConfiguration | ?{$_.id -eq "X509Certificate"}
$params = @{
	"@odata.context" = "$MSGraphURI/$metadata#authenticationMethodsPolicy/$entity"
	AuthenticationMethodConfigurations = @(
		@{
			"@odata.type" = $X509Certificate.'@odata.type'
			Id = $X509Certificate.id
			State = $X509Certificate.state
            CertificateUserBindings = @(
                @{ 
                    x509CertificateField = "PrincipalName" 
                    userProperty = "certificateUserIds" 
                    priority = 1 
                },
                @{ 
                    x509CertificateField = "PrincipalName"
                    userProperty= "onPremisesUserPrincipalName"
                    priority= 2 
                }
            )
			IncludeTargets = @(
                @{
                    targetType = "group"
                    Id = "all_users"
                }
            )
            AuthenticationModeConfiguration = @{
                X509CertificateAuthenticationDefaultMode = $X509Certificate.authenticationModeConfiguration.x509CertificateAuthenticationDefaultMode
            }
        }
	)
}
$body = $params | ConvertTo-Json
Update-MgPolicyAuthenticationMethodPolicy -BodyParameter $body

#disable other policies
Write-Host -ForegroundColor Yellow "Disabling Softrware Oath, SMS, TAP, Email"
$params = @{
	"@odata.context" = "$MSGraphURI/$metadata#authenticationMethodsPolicy"
	AuthenticationMethodConfigurations = @(
		@{
			"@odata.type" = "#microsoft.graph.softwareOathAuthenticationMethodConfiguration"
			Id = "SoftwareOath"
			State = "disabled"
        }
        @{
            "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
			Id = "TemporaryAccessPass"
			State = "disabled"
        }
        @{
            "@odata.type" = "#microsoft.graph.smsAuthenticationMethodConfiguration"
			Id = "Sms"
			State = "disabled"
        }
         @{
            "@odata.type" = "#microsoft.graph.emailAuthenticationMethodConfiguration"
			Id = "Email"
			State = "disabled"
        }
	)
}
Update-MgPolicyAuthenticationMethodPolicy -BodyParameter $params
#endregion

### Left off here

#region Groups

#endregions

#region PIM

#endregion

#region CA

#endregion

#region UserGroupCollabSettings

#endregion