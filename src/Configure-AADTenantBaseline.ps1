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
    [Switch]$SkipTools,
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

function New-MLZGroup {
    Param([object]$Group,[Array]$MissionAUs,[Switch]$PAG)
    
    if ($group.core) {
        $displayName = $group.name + " MLZ"
        $mailNickname = $group.mailNickname + "-MLZ"

        Try {
            $groupobj = Get-MgGroup -Filter "DisplayName eq `'$displayName`'" -ErrorAction SilentlyContinue
        } Catch {} #to do

        if ($groupobj) {
            write-host "Group with displayname $displayname already exists...skipping"
        } else {
            
            Switch($PAG) {
                $true {New-MgGroup -DisplayName $Group.name -MailEnabled:$False -MailNickName $group.mailNickname -SecurityEnabled -IsAssignableToRole}
                $false {New-MgGroup -DisplayName $Group.name -MailEnabled:$False -MailNickName $group.mailNickname -SecurityEnabled}
            }
        }
    }

    if ($group.mission) {
        foreach ($mission in $MissionAUs) {
            $displayName = $group.name + " $mission"
            $mailNickname = $group.mailNickname + "-" + $mission
            Try {
                $groupobj = Get-MgGroup -Filter "DisplayName eq `'$displayName`'" -ErrorAction SilentlyContinue
            } Catch {} #to do

            if ($groupobj) {
                write-host "Group with displayname $displayname already exists...skipping"
            } else {
                Write-Host -ForegroundColor Yellow "Creating new group with displayName $displayName"
                Switch($PAG) {
                    $true {New-MgGroup -DisplayName $displayName -MailEnabled:$False -MailNickname $mailNickname -SecurityEnabled -Description $group.description -IsAssignableToRole}
                    $false {New-MgGroup -DisplayName $displayName -MailEnabled:$False -MailNickname $mailNickname -SecurityEnabled -Description $group.description}
                }
            }
        }
    }
}

function New-MLZCAPolicy {
    Param([Object]$policy,[String]$CurrentUserID,[String]$EAGroupID)

    if ($policy.grantControls.authenticationStrength) {
        Write-Host -ForegroundColor Cyan "UPDATE - Manually add authentication strength using Azure Portal"
        $policy.grantControls.authenticationStrength

        $policy.grantControls.builtInControls = "mfa"
    }

    $params = @{
        DisplayName = $policy.displayname
        State = $policy.state
        Conditions = @{
            UserRiskLevels = @(
                $policy.conditions.userRiskLevels
            )
            ClientAppTypes = @(
                $policy.conditions.clientAppTypes
            )
            Applications = @{
                IncludeApplications = @(
                    $policy.conditions.applications.includeApplications
                )
                IncludeUserActions = @(
                    $policy.conditions.applications.includeUserActions
                )
            }
            Users = @{
                IncludeUsers = @(
                    $policy.conditions.users.includeUsers
                )
                ExcludeUsers = @(
                    $CurrentUserID
                )
                ExcludeGroups = @(
                    $EAGroupID
                )
                IncludeRoles = @(
                    $policy.conditions.users.includeRoles
                )
                ExcludeRoles = @(
                    $policy.conditions.users.excludeRoles
                )
            }
        }
        GrantControls = @{
            Operator = $policy.grantControls.operator
            BuiltInControls = @(
                $policy.grantControls.builtInControls
            )
        }
    }

   <# if ($policy.grantControls.authenticationStrength) {
        $params.GrantControls.authenticationStrength = @{
            ID = $policy.grantControls.authenticationStrength.id
            DisplayName = $policy.grantControls.authenticationStrength.displayName
            Description = $policy.grantControls.authenticationStrength.description
            PolicyType = $policy.grantControls.authenticationStrength.policyType
            RequirementsSatisfied = $policy.grantControls.authenticationStrength.requirementsSatisfied
            AllowedCombinations = $policy.grantControls.authenticationStrength.allowedCombinations
        }
    } #>

    if ($policy.conditions.locations) {
        $params.locations = @{
            IncludeLocations = @(
                $policy.conditions.locations.includeLocations
            )
            ExcludeLocations = @(
                $policy.conditions.locations.excludeLocations
            )
        }
    }


    Try {
        $CAObj = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq `'$($policy.displayname)`'" -ErrorAction SilentlyContinue
    } Catch {} #To do: Implement message

    if ($CAObj) {
        Write-Host "CA Rule $($policy.displayname) already exists."
    } else {
        Write-Host "Creating new Conditional Access Rule: $($policy.displayname)." -ForegroundColor Yellow
        New-MgIdentityConditionalAccessPolicy -BodyParameter $params
    }
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
    if (!($SkipTools)) {
        $modules = $mlzparams.StepParameterSet.PSTools.parameters.Modules
        foreach ($module in $modules) {
            if ($Verbose) {
                Install-Module $modules -Verbose
            } else {
                Install-Module $modules -Confirm
            }
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
$fido2 = $AuthNMethodsConfiguration.Fido2
$microsoftauthenticator = $AuthNMethodsConfiguration.MicrosoftAuthenticator
$X509certificate = $AuthNMethodsConfiguration.X509Certificate
$registrationConfiguration = $ParametersJson.StepParameterSet.AuthNMethods.parameters.RegistrationSettings

$EAGroupName = $ParametersJson.StepParameterSet.EmergencyAccess.parameters.EAGroup.mailNickname
$EAGroupObj = Get-MgGroup -Filter "MailNickname eq `'$EAGroupName`'"

Write-Host -ForegroundColor Yellow "Setting Authentication Methods:"
$($ParametersJson.StepParameterSet.AuthNMethods.parameters.AuthenticationMethodsConfigurations)
Write-Host -ForegroundColor Yellow "Configuring Registration:"
$($ParametersJson.StepParameterSet.AuthNMethods.parameters.RegistrationSettings)
$params = @{
	"@odata.context" = "$MSGraphURI/$metadata#authenticationMethodsPolicy"
	AuthenticationMethodConfigurations = @(
		@{
			"@odata.type" = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
			Id = "fido2"
			State = $fido2.state
			IsSelfServiceRegistrationAllowed = $fido2.isSelfServiceRegistrationAllowed
			IsAttestationEnforced = $fido2.isAttestationEnforced
            IncludeTargets = @(
                @{
                    targetType = $fido2.targetType
                    Id = $fido2.targetId
                }
            )
		}
        @{
			"@odata.type" = "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration"
			Id = "MicrosoftAuthenticator"
			State = $microsoftauthenticator.state
			IncludeTargets = @(
                @{
                    targetType = $microsoftauthenticator.targetType
                    Id = $microsoftauthenticator.targetId
                }
            )
        }
        @{
            "@odata.type" = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
            Id = "X509Certificate"
            State = $X509certificate.state
			IncludeTargets = @(
                @{
                    targetType = $X509certificate.targetType
                    Id = $X509certificate.targetId
                }
            )
            IsRegistrationRequired = $X509certificate.isRegistrationRequired
            CertificateUserBindings = @(
                @{
                    X509CertificateField = $($X509certificate.certificateUserBindings[0]).x509CertificateField
                    UserProperty = $($X509certificate.certificateUserBindings[0]).userProperty
                    Priority =  $($X509certificate.certificateUserBindings[0]).priority
                }
            )
            AuthenticationModeConfiguration = @{
                X509CertificateAuthenticationDefaultMode = $X509certificate.authenticationModeConfiguration.x509CertificateAuthenticationDefaultMode
                Rules = @()
            }
        }
        <# #To do: Figure out why this can't be disabled (invalid odata type specified)
        @{
			"@odata.type" = "#microsoft.graph.softwareOathAuthenticationMethodConfiguration"
			Id = "SoftwareOath"
			State = "disabled"
        }#>
        @{
            "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
			Id = "TemporaryAccessPass"
			State = "disabled"
        }
        <#@{ #To do: Figure out why this can't be disabled (invalid odata type specified)
            "@odata.type" = "#microsoft.graph.smsAuthenticationMethodConfiguration"
			Id = "Sms"
			State = "disabled"
        }#>
         @{
            "@odata.type" = "#microsoft.graph.emailAuthenticationMethodConfiguration"
			Id = "Email"
			State = "disabled"
        }
	)
    RegistrationEnforcement = @{
        AuthenticationMethodsRegistrationCampaign = @{
            SnoozeDurationInDays = $registrationConfiguration.snoozeDurationInDays
            State = $registrationConfiguration.state
            ExcludeTargets = @(
                @{
                    Id = $EAGroupObj.Id
                    TargetType = "group"
                }
            )
            IncludeTargets = @(
                @{
                    Id = "all_users"
                    TargetType = "group"
                    TargetedAuthenticationMethod = $registrationConfiguration.targetAuthenticationMethod
                }
            )
        }
    }
}

Update-MgPolicyAuthenticationMethodPolicy -BodyParameter $params


#endregion

#region Groups
$Groups = $ParametersJson.StepParameterSet.Groups.parameters.SecurityGroups
$PAGs = $ParametersJson.StepParameterSet.Groups.parameters.PAGs
$MissionAUs = $ParametersJson.GlobalParameterSet.MissionAUs

foreach ($group in $Groups) {
    New-MLZGroup -Group $Group -MissionAUs $MissionAUs
}

foreach ($pag in $PAGs) {
   New-MLZGroup -Group $pag -MissionAUs $MissionAUs -PAG
}

#endregions

#region PIM
##### Left off here - figure out how to do this with MS Graph using v3.
Import-Module Microsoft.Graph.Identity.Governance
Connect-MgGraph -Scopes "Directory.AccessAsUser.All","RoleManagement.ReadWrite.Directory"

$roles = $ParametersJson.StepParameterSet.PIM.parameters.Roles
$coreroles = $roles | ?{"tenant" -in $_.scope}
$missionroles = $roles | ?{"mission" -in $_.scope}
$MissionAUs = $ParametersJson.GlobalParameterSet.MissionAUs

$GARoleObj = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId "62e90394-69f5-4237-9190-012177145e10"

New-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId -BodyParameter -Confirm

function New-MLZPIMRoleAssignment {
    Param([String]$RoleID,[String]$PrincipalID,[String]$EligibilityDuration,[STring]$RequestDuration)

    New-MgPrivilegedRole -WhatIf
    $params = @{
        "PrincipalId" = $PrincipalID
        "RoleDefinitionId" = $RoleID
        "Justification" = "Add permanent assignment for Emergency Access accounts."
        "DirectoryScopeId" = "/"
        "Action" = "AdminAssign"
        "ScheduleInfo" = @{
            "StartDateTime" = Get-Date
            "Expiration" = @{
                "Type" = "AfterDuration"
                "Duration" = $EligibilityDuration
            }
        }
    }
    New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
}

foreach ($role in $coreroles) {


}

foreach ($role in $missionroles) {
    foreach ($au in $MissionAUs) {

    }
}

#endregion

#region ConditionalAccess
Write-Host -ForegroundColor Cyan "Configuring Conditional Access Policies for MLZ Baseline."

Connect-MgGraph -Scopes 'Application.Read.All', 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess'
$CAPolicies = $ParametersJson.StepParameterSet.ConditionalAccess.parameters

#get current user
$CurrentUserID = $(Get-MgUser -Filter "UserPrincipalName eq `'$($(Get-MgContext).Account)`'").Id

#get EA Groupname
$EAGroupName = $($ParametersJson.StepParameterSet.EmergencyAccess.parameters.EAGroup).displayName
$EAGroupID = $(Get-MGGroup -Filter "DisplayName eq `'$EAGroupName`'").Id
### All Users MFA

$AllRules = $ParametersJson.StepParameterSet.ConditionalAccess.parameters
New-MLZCAPolicy -policy $AllRules.MLZ01 -CurrentUserID $CurrentUserID -EAGroupID $EAGroupID
New-MLZCAPolicy -policy $AllRules.MLZ02 -CurrentUserID $CurrentUserID -EAGroupID $EAGroupID
New-MLZCAPolicy -policy $AllRules.MLZ03 -CurrentUserID $CurrentUserID -EAGroupID $EAGroupID
New-MLZCAPolicy -policy $AllRules.MLZ04 -CurrentUserID $CurrentUserID -EAGroupID $EAGroupID
New-MLZCAPolicy -policy $AllRules.MLZ05 -CurrentUserID $CurrentUserID -EAGroupID $EAGroupID
New-MLZCAPolicy -policy $AllRules.MLZ06 -CurrentUserID $CurrentUserID -EAGroupID $EAGroupID

function New-MLZCAPolicy {
    Param([Object]$policy,[String]$CurrentUserID,[String]$EAGroupID)

    if ($policy.grantControls.authenticationStrength) {
        Write-Host -ForegroundColor Cyan "UPDATE - Manually add authentication strength using Azure Portal"
        $policy.grantControls.authenticationStrength

        $policy.grantControls.builtInControls = "mfa"
    }

    $params = @{
        DisplayName = $policy.displayname
        State = $policy.state
        Conditions = @{
            UserRiskLevels = @(
                $policy.conditions.userRiskLevels
            )
            ClientAppTypes = @(
                $policy.conditions.clientAppTypes
            )
            Applications = @{
                IncludeApplications = @(
                    $policy.conditions.applications.includeApplications
                )
                IncludeUserActions = @(
                    $policy.conditions.applications.includeUserActions
                )
            }
            Users = @{
                IncludeUsers = @(
                    $policy.conditions.users.includeUsers
                )
                ExcludeUsers = @(
                    $CurrentUserID
                )
                ExcludeGroups = @(
                    $EAGroupID
                )
                IncludeRoles = @(
                    $policy.conditions.users.includeRoles
                )
                ExcludeRoles = @(
                    $policy.conditions.users.excludeRoles
                )
            }
        }
        GrantControls = @{
            Operator = $policy.grantControls.operator
            BuiltInControls = @(
                $policy.grantControls.builtInControls
            )
        }
    }

   <# if ($policy.grantControls.authenticationStrength) {
        $params.GrantControls.authenticationStrength = @{
            ID = $policy.grantControls.authenticationStrength.id
            DisplayName = $policy.grantControls.authenticationStrength.displayName
            Description = $policy.grantControls.authenticationStrength.description
            PolicyType = $policy.grantControls.authenticationStrength.policyType
            RequirementsSatisfied = $policy.grantControls.authenticationStrength.requirementsSatisfied
            AllowedCombinations = $policy.grantControls.authenticationStrength.allowedCombinations
        }
    } #>

    if ($policy.conditions.locations) {
        $params.locations = @{
            IncludeLocations = @(
                $policy.conditions.locations.includeLocations
            )
            ExcludeLocations = @(
                $policy.conditions.locations.excludeLocations
            )
        }
    }


    Try {
        $CAObj = Get-MgIdentityConditionalAccessPolicy -Filter "DisplayName eq `'$($policy.displayname)`'" -ErrorAction SilentlyContinue
    } Catch {} #To do: Implement message

    if ($CAObj) {
        Write-Host "CA Rule $($policy.displayname) already exists."
    } else {
        Write-Host "Creating new Conditional Access Rule: $($policy.displayname)." -ForegroundColor Yellow
        New-MgIdentityConditionalAccessPolicy -BodyParameter $params
    }
}

#endregion

#region TenantPolicies
Connect-MgGraph -Scopes Policy.ReadWrite.Authorization


$authorizationPolicy = $ParametersJson.StepParameterSet.TenantPolicies.parameters.authorizationPolicy
$externalIdentityPolicy = $ParametersJson.StepParameterSet.TenantPolicies.parameters.externalIdentityPolicy
$adminConsentRequestPolicy = $ParametersJson.StepParameterSet.TenantPolicies.parameters.adminConsentRequestPolicy

Write-host -ForegroundColor Cyan "Updating AuthorizationPolicy"

$params = @{
    "@odata.context" = "$MSGraphURI/`$metadata#policies/authorizationPolicy"
    allowInvitesFrom = $authorizationPolicy.allowInvitesFrom
    allowedToSignUpEmailBasedSubscriptions = $authorizationPolicy.allowedToSignUpEmailBasedSubscriptions
    allowedToUseSSPR = $authorizationPolicy.allowedToUseSSPR
    allowEmailVerifiedUsersToJoinOrganization = $authorizationPolicy.allowEmailVerifiedUsersToJoinOrganization
    allowUserConsentForRiskyApps = $authorizationPolicy.allowUserConsentForRiskyApps
    blockMsolPowerShell = $authorizationPolicy.blockMsolPowerShell
    enabledPreviewFeatures = @(
        $authorizationPolicy.enabledPreviewFeatures
    )
    guestUserRoleId = $authorizationPolicy.guestUserRoleId
    permissionGrantPolicyIdsAssignedToDefaultUserRole = @(
        "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
    )
    defaultUserRolePermissions = @{
        AllowedToCreateApps = $authorizationPolicy.defaultUserRolePermissions.allowedToCreateApps
        AllowedToCreateSecurityGroups = $authorizationPolicy.defaultUserRolePermissions.allowedToCreateSecurityGroups
        AllowedToCreateTenants = $authorizationPolicy.defaultUserRolePermissions.allowedToCreateTenants
        AllowedToReadBitlockerKeysForOwnedDevice = $authorizationPolicy.defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice
        AllowedToReadOtherUsers = $authorizationPolicy.defaultUserRolePermissions.allowedToReadOtherUsers
    }
}
Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -BodyParameter $params

Write-host -ForegroundColor Cyan "Updating External Identity Policies"

$params = @{
    "@odata.context" = "$MSGraphURI/`$metadata#policies/externalIdentitiesPolicy/$entity"
    AllowExternalIdentitiesToLeave = $externalIdentityPolicy.allowExternalIdentitiesToLeave
    AllowDeletedIdentitiesDataRemoval = $externalIdentityPolicy.allowDeletedIdentitiesDataRemoval
}

Update-MgPolicyExternalIdentityPolicy -BodyParameter $params

Write-host -ForegroundColor Cyan "Updating Admin Consent Policy"
Update-MgPolicyAdminConsentRequestPolicy -IsEnabled:$adminConsentRequestPolicy.isEnabled

#endregion

Write-Host -ForegroundColor Green "Completed AAD Tenant Baseline Script"