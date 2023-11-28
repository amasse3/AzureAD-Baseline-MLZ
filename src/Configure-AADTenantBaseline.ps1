#Configure-AADTenantBaseline.ps1
#
# Version: 0.6 Test release
# LastModified: 11/27/2023
#
# Warning: Sample scripts in this repository are not supported under any Microsoft support program or service. 
# Scripts are provided AS IS without warranty of any kind. All warranties including, without limitation, any 
# implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of 
# the use of sample scripts or configuration documentation remains with you. In no event shall Microsoft, its 
# authors, or anyone else involved in the creation, production, or delivery of this content be liable for any 
# damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, 
# loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample
# scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
#
<#
.SYNOPSIS

Applies MLZ identity baseline recommendations for a new Azure AD tenant.

.DESCRIPTION

Installs PowerShell modules, creates break-glass and admin user accounts, configures Authentication Methods, creates RBAC groups, configures Privileged Identity Management, configures Conditional Access, AAD settings for users, groups, and collaboration.

.INPUTS

ParametersJson (PS Object)

.OUTPUTS

None

.EXAMPLE

PS> .\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparams -All
PS> .\Configure-AADTenantBaseline.ps1 -All
PS> .\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparams -Accounts -AuthNMethods -Groups -TenantPolicies
PS> .\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparms -All -IncludeTools

.LINK

https://github.com/amasse3/MLZ-Identity-AzureADSetup/blob/main/src/Configure-AADTenantBaseline.ps1

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
    [Switch]$Certificates,
    [Parameter(Mandatory=$false)]
    [Switch]$Groups,
    [Parameter(Mandatory=$false)]
    [Switch]$PIM,
    [Parameter(Mandatory=$false)]
    [Switch]$ConditionalAccess,
    [Parameter(Mandatory=$false)]
    [Switch]$TenantPolicies,
    [Parameter(Mandatory=$false)]
    [Switch]$EntitlementsManagement,
    [Parameter(Mandatory=$false)]
    [Switch]$IncludeTools
)

#region warning
$msg = "WARNING:`nSample scripts in this repository are not supported under any Microsoft support program or service. Scripts are provided AS IS without warranty of any kind. All warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use of sample scripts or configuration documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, produciton, or delivery of this content be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages."
Write-Host $msg -ForegroundColor Yellow
write-host "`nThis script is under active development. Do not run in a production environment.`n" -ForegroundColor Red
$response = read-host "If you agree to continue, press `"c`". Press any other key to exit."
$continue = $response -eq "c"
if (!$continue) {
    write-host "Exiting script..."
    start-sleep -Seconds 3
    exit
}

#See if the Parameters JSON file is there
if (!$ParametersJson) {
    #Set parameter value if missing
    $ParametersJson = "mlz-aad-parameters.json"
}

#Check the path
if (!$(Test-Path $ParametersJson)) {
    Write-Host "Cannot find parameters file name $ParametersJson"
    write-host "Exiting script..."
    start-sleep -Seconds 3
    exit
} else {
    #Load the file
    Write-Host "Loading parameters from $ParametersJson..."
    $Parameters = $(Get-Content $ParametersJson) | ConvertFrom-Json -Depth 10
}

#endregion

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
        #$AU = Get-MgAdministrativeUnit | Where-Object{$_.DisplayName -eq $($BodyParameter.displayName)} -ErrorAction SilentlyContinue
        $AU = Get-MgDirectoryAdministrativeUnit -Filter "Displayname eq '$($BodyParameter.displayName)'" -ErrorAction SilentlyContinue
    } Catch {}

    if ($AU) {
        $msg = "Administrative unit " + $($AU.DisplayName) + " already exists."
        Write-Host $msg
    } else {
        Write-host -ForegroundColor yellow "Adding Administrative Unit $($BodyParameter.displayName)."
        #$AU = New-MgAdministrativeUnit -BodyParameter $($BodyParameter | convertto-json)
        $AU = New-MgDirectoryAdministrativeUnit -DisplayName $($BodyParameter.displayName)
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

    if ($mt.membershipType -eq "Dynamic") {
        $mt.membershipRule = $mt.membershipRule -replace "ZZZ",$missionAU
    }
    Return $mt
}

function Convert-MLZCatalogFromTemplate {
    Param([object]$template,[string]$missionAU)
    #Deep copy object
    $mt = $template | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv

    #update fields
    $mt.displayName = $mt.displayName -replace "ZZZ",$missionAU
    $mt.description = $mt.description -replace "ZZZ",$missionAU

    Return $mt
}

function Build-MemberberArrayParams {
    Param([Array]$members,[String]$MSGraphURI,[String]$objectType)
    $out = @()
    foreach ($member in $members) {
        $out += "$MSGraphURI/v1.0/$objectType/$member"
    }

    $params = @{"@odata.id" = $out}

    Return $params
}

function New-MLZGroup {
    Param([object]$Group,[Array]$MissionAUs,[Switch]$PAG)
    
    if ($group.core) {
        $displayName = $group.name + " MLZ-Core"
        $mailNickname = $group.mailNickname + "-MLZ"

        Try {
            $groupobj = Get-MgGroup -Filter "DisplayName eq `'$displayName`'" -ErrorAction SilentlyContinue
        } Catch {} #to do

        if ($groupobj) {
            write-host "Group with displayname $displayname already exists...skipping"
        } else {
            Write-Host -ForegroundColor Yellow "Creating new group with displayName $displayName"
            Switch($PAG) {
                $true {New-MgGroup -DisplayName $displayName -MailEnabled:$False -MailNickName $mailNickname -SecurityEnabled -IsAssignableToRole}
                $false {New-MgGroup -DisplayName $displayName -MailEnabled:$False -MailNickName $mailNickname -SecurityEnabled}
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
    Param([Object]$policy,[String]$CurrentUserID,[String]$EAGroupID,[String]$MSGraphURI)

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

    if ($policy.grantControls.authenticationStrength) {
        $params.GrantControls.authenticationStrength = @{
            ID = $policy.grantControls.authenticationStrength.id
         }
    }

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

function Update-MLZPIMPolicyRules {
    Param([String]$UnifiedRoleManagementPolicyId,[String]$EligibilityMaxDurationInDays,[String]$ActivationMaxDurationInHours)

    $rules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $UnifiedRoleManagementPolicyId
    $eligibilityexpiration = $rules | Where-Object{$_.Id -eq "Expiration_Admin_Eligibility"}
    $activationduration = $rules | Where-Object{$_.Id -eq "Expiration_EndUser_Assignment"}

    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
        Id = "Expiration_EndUser_Assignment"
        isExpirationRequired = $false
        maximumDuration = $ActivationMaxDurationInHours
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = "EndUser"
            Operations = @("all")
            Level = "Assignment"
            InheritableSettings = @()
            EnforcedSettings = @()
          }
        }
    Write-Host "     Updating Max Activation Duration for Policy $UnifiedRoleManagementPolicyId"
    Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $UnifiedRoleManagementPolicyId -UnifiedRoleManagementPolicyRuleId $activationduration.Id -BodyParameter $params

    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
        Id = "Expiration_Admin_Eligibility"
        isExpirationRequired = $false
        maximumDuration = $EligibilityMaxDurationInDays
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = "EndUser"
            Operations = @("all")
            Level = "Assignment"
            InheritableSettings = @()
            EnforcedSettings = @()
          }
        }
    Write-Host "     Updating Max Eligibility Duration for Policy $UnifiedRoleManagementPolicyId"
    Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $UnifiedRoleManagementPolicyId -UnifiedRoleManagementPolicyRuleId $eligibilityexpiration.Id -BodyParameter $params

}

function New-MLZPIMRoleEligibilitySchedule {
    Param([Object]$role,[String]$PrincipalID,[String]$Scope,[Switch]$Permanent)

    #valid scopes: "/administrativeUnits/<Mission AD ID>" or "/"
    $Permanent = $true
    if ($Permanent) {
        $Expiration = @{
            "Type" = "NoExpiration"
        }
    } else {
        $Expiration = @{
            "Type" = "AfterDuration"
            "Duration" = $($role.EligibilityMaxDurationInDays)
        }
    }

    $params = @{
        "PrincipalId" = $PrincipalID
        "RoleDefinitionId" = $role.RoleTemplateId
        "Justification" = "MLZ baseline role eligibility for $($role.EligibilityMaxDurationInDays) configured by script on $(Get-Date)."
        "DirectoryScopeId" = $Scope
        "Action" = "AdminAssign"
        "ScheduleInfo" = @{
            "StartDateTime" = Get-Date
            "Expiration" = $Expiration
        }
    }

    #Look for existing
    $existing = Get-MgRoleManagementDirectoryRoleEligibilitySchedule | Where-Object {($_.DirectoryScopeId -eq "$scope") -and ($_.PrincipalId -eq $PrincipalID) -and ($_.RoleDefinitionId -eq $role.RoleTemplateId)}
    if ($existing) {
        Write-Host "Existing role assignment found for principal:`'$PrincipalId`' role:`'$($role.name)`' scope:`'$scope`'..." 
    } else {
        Write-Host -ForegroundColor Yellow "Creating new role assignment for principal:`'$PrincipalId`' role:`'$($role.name)`' scope:`'$scope`'..." 
        New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
    }
}

function Find-MLZMissionAUObj {
    Param(
    [String]$AU,
    [ValidateSet("user","group")]
    [String]$Type,
    [Object]$Template
    )
        #deep copy template
        $t = $Template | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv
        #build filter
        $f = $t.displayName -replace "ZZZ",$AU
        $obj = Get-MgDirectoryAdministrativeUnit -Filter "DisplayName eq `'$f`'"
    return $obj
}

function New-MLZAccessPackageCatalog {
    Param([object]$BodyParameter)


    Try {
        $exists = Get-MgBetaEntitlementManagementAccessPackageCatalog -Filter "displayName eq `'$($BodyParameter.displayname)`'"
    } Catch {} #to be implemented

    if ($exists) {
        Write-Host "Access Package Catalog $($BodyParameter.displayName) already exists."
    } else {
        Write-Host -ForegroundColor Yellow "Creating Access Package Catalog $($BodyParameter.displayName)."
        New-MgBetaEntitlementManagementAccessPackageCatalog -BodyParameter $BodyParameter
    }
}

function Convert-HexStringToByteArray {
    [CmdletBinding()]Param(
    [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
    [String]$String)
 
    #Clean string
    #$String = $String.ToLower() -replace "[^a-f0-9\\,x\-\:]",""
    #$String = $String -replace "0x|\x|\-|,",":"
    #$String = $String -replace "^:+|:+$|x|\",""
 
    #Convert the rest
    if ($String.Length -eq 0) {,@() ; return}
 
    #Split string with or without colon delimiters.
    if ($String.Length -eq 1) {
        ,@([System.Convert]::ToByte($String,16))
    } elseif (($String.Length % 2 -eq 0) -and ($String.IndexOf(":") -eq -1)) {
        ,@($String -split '([a-f0-9]{2})' | foreach-object {
            if ($_) {[System.Convert]::ToByte($_,16)}
        })
    } elseif ($String.IndexOf(":") -ne -1) {
        ,@($String -split ':+' | foreach-object {[System.Convert]::ToByte($_,16)})
    }
    else {,@()}
}
#endregion

#region parameters
#sets variables for some global parameters
$Environment = $Parameters.GlobalParameterSet.Environment
$PWDLength = $Parameters.GlobalParameterSet.PWDLength
$MissionAUs = $Parameters.GlobalParameterSet.MissionAUs
$License = $Parameters.GlobalParameterSet.License | ConvertTo-Json

Write-Host "Sign in to Azure AD"

Connect-MgGraph -Environment $Environment -Scopes Directory.Read.All
$upnsuffix = $(Get-MgDomain | Where-Object{$_.IsInitial -eq $true}).Id
Switch ($Environment) {
    Global {$MSGraphURI = "https://graph.microsoft.com"}
	USGov {$MSGraphURI = "https://graph.microsoft.us"}
    USGovDoD {$MSGraphURI = "https://graph.microsoft.us"}
}

#endregion

#region PSTools
if ($PSTools -or ($All -and $IncludeTools)) {
    $modules = $Parameters.StepParameterSet.PSTools.parameters.Modules

    foreach ($module in $modules) {
        if ($Verbose) {
            Install-Module $module -Verbose
        } else {
            Install-Module $module -Confirm
        }
    }
}
#endregion

#region AdminUnits
if ($AdminUnits -or $All) {
    Import-Module Microsoft.Graph.Identity.DirectoryManagement
    Connect-MgGraph -Scopes AdministrativeUnit.ReadWrite.All -Environment $Environment
    #Select-MgProfile beta

    #create core AU
    $CoreAU = $Parameters.StepParameterSet.AdminUnits.parameters.CoreAU
    $CoreAUObj = New-MLZAdminUnit -BodyParameter $CoreAU

    #read in templates
    $MissionAUGroupTemplate = $Parameters.StepParameterSet.AdminUnits.parameters.MissionAUGroupTemplate
    $MissionAUUserTemplate = $Parameters.StepParameterSet.AdminUnits.parameters.MissionAUUserTemplate

    #Add Mission AUs
    foreach ($missionAU in $MissionAUs) {
        #Add Groups AU
        $GroupsAU = Convert-MLZAUFromTemplate -template $MissionAUGroupTemplate -missionAU $MissionAU
        New-MLZAdminUnit -BodyParameter $GroupsAU | Out-Null
       
        #Add Users AU
        $UsersAU = Convert-MLZAUFromTemplate -template $MissionAUUserTemplate -missionAU $MissionAU
        New-MLZAdminUnit -BodyParameter $UsersAU | Out-Null
    }

    Write-Host -ForegroundColor Green "Completed creating Administrative Units."
}
#endregion

#region EmergencyAccess
if ($EmergencyAccess -or $All) {
    Import-Module Microsoft.Graph.Identity.DirectoryManagement
    Import-Module Microsoft.Graph.Users
    Import-Module Microsoft.Graph.Groups
    Connect-MgGraph -Scopes AdministrativeUnit.ReadWrite.All,User.ReadWrite.All,Group.ReadWrite.All,RoleManagement.ReadWrite.Directory -Environment $Environment

    $EAUsers = $Parameters.StepParameterSet.EmergencyAccess.parameters.Users
    $EAGroup = $Parameters.StepParameterSet.EmergencyAccess.parameters.EAGroup
    $EAAU = $Parameters.StepParameterSet.EmergencyAccess.parameters.AdministrativeUnit

    #Create Emergency Access Accounts
    $EAAccountObjects = @()
    foreach ($EAUser in $EAUsers) {
        $NewUPN = $EAUser.userPrincipalName + "@" + $upnsuffix
        $EAUser.userPrincipalName = $NewUPN
        $EAAccountObjects += New-MLZAADUser -user $EAUser -PasswordLength $PWDLength
    }

    #Create the Admin Unit
    $EAAUObj = New-MLZAdminUnit -BodyParameter $EAAU

    #Create Emergency Access Accounts group
    Try {
        $EAGroupObj = Get-MgGroup -Filter "displayName eq `'$($EAGroup.displayName)`'"
    } Catch {}

    if ($EAGroupObj) {
        Write-Host "Group `"$($EAGroup.displayName)`" already exists."
    } else {
        write-host -ForegroundColor Yellow "Creating new group $($EAGroup.displayName)."
        $EAGroupObj = New-MgGroup -BodyParameter $($EAGroup | ConvertTo-Json)
        Write-Host "waiting for group creation before continuing."
        Start-Sleep -Seconds 10
    }
    


    foreach ($user in $EAAccountObjects.Id) {

        $params = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($user)"
        }
        Try {
            New-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $EAAUObj.Id -BodyParameter $params
        } Catch [Exception] {
            Write-Host "Member already added. Skipping."
        }
        

    }

    #Add users to the group and AU
    #$params = Build-MemberberArrayParams -members $EAAccountObjects.Id -MSGraphURI $MSGraphURI -objectType "users"

    <#Try {
        Update-MgDirectoryAdministrativeUnit -AdministrativeUnitId $EAAUObj.Id -BodyParameter $params -ErrorAction Stop
    } Catch [Exception] {
        Write-Host "Member already added. Skipping."
    }#>

    Try {
        Update-MgGroup -GroupId $EAGroupObj.Id -BodyParameter $params -ErrorAction Stop
    } Catch [Exception] {
        Write-Host "Member already added. Skipping."
    }

    #Assign licenses to the group
    Try {
        Write-Host -ForegroundColor Yellow "Assigning licenses to $($EAGroupObj.Id)."
        Set-MgGroupLicense -GroupId $EAGroupObj.Id -BodyParameter $License -ErrorAction Stop
    } Catch [Exception] {
        Write-Host "Licenses already applied for group. Skipping."
    }

    #Assign Global Admin role
    $GARoleObj = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId "62e90394-69f5-4237-9190-012177145e10"


    if ($Parameters.StepParameterSet.EmergencyAccess.parameters.PIM.permanentActiveAssignment) {
        Try {
            $obj = Get-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -Filter "PrincipalId eq `'$($EAGroupObj.Id)`'"
        } Catch {}
        
        if ($obj) {
            Write-Host "Global Admin assignment already exists for $($EAGroupObj.displayname)."
        } else {
            Write-Host -ForegroundColor Yellow "Adding permanent active assignment for Global Administrator role."
            $params = @{
	            Action = "adminAssign"
	            Justification = "Add permanent assignment for Emergency Access accounts."
	            RoleDefinitionId = $GARoleObj.Id
	            DirectoryScopeId = "/"
	            PrincipalId = $EAGroupObj.Id
	            ScheduleInfo = @{
		            StartDateTime = Get-Date
		            Expiration = @{
			            Type = "NoExpiration"
		            }
	            }
            }
          
            New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
        }
        
    } else {
        Try {
            $req = Get-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -Filter "PrincipalId eq `'$($EAGroupObj.Id)`'"
        } Catch {}

        if ($req) {
            Write-Host "Global Admin eligibility already exists for $($EAGroupObj.displayname)."
        } else {
            $params = @{
            PrincipalId = $EAGroupObj.Id
            RoleDefinitionId = $GARoleObj.Id
            Justification = "Add permanent assignment for Emergency Access accounts."
            DirectoryScopeId = "/"
            Action = "AdminAssign"
            ScheduleInfo = @{
                StartDateTime = Get-Date
                Expiration = @{
                    Type = "NoExpiration"
                }
            }
        }
            Write-Host -ForegroundColor Yellow "Adding permanent eligibility for Global Administrator role"
            New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params

        }
    }

    Write-Host -ForegroundColor Green "Completed creating EA accounts."
}

#endregion

#region NamedAccounts
if ($NamedAccounts -or $All) {
    Import-Module Microsoft.Graph.Users
    Import-Module Microsoft.Graph.Groups
    Connect-MgGraph -Scopes AdministrativeUnit.ReadWrite.All,User.ReadWrite.All,Group.ReadWrite.All -Environment $Environment

    $UserCSV = Import-Csv $Parameters.GlobalParameterSet.UserCSVRelativePath

    <#testing
    $UserCSV = Import-Csv -Path .\mlztest.csv
    #>

    $validdomains = Get-MgDomain | Where-Object{$_.IsVerified -eq $true}
    $initialdomain = $validdomains | Where-Object{$_.IsInitial -eq $true}

    $NamedAdmins = @()
    foreach ($user in $UserCSV) {
        #verify domain suffix is correct, set to intial domain otherwise
        $suffix = $user.UserPrincipalName.Split("@")[1]
        if (!($validdomains.id -match $suffix)) {
            $user.UserPrincipalName = $user.UserPrincipalName.Split("@")[0]+"@"+$initialdomain.Id
        }
        #create the admin account
        $NamedAdmins += New-MLZAADUser -user $user -PasswordLength $PWDLength
    }

    #update users that have certificateUserIds value
    $certificateUserIDUsers = $UserCSV | Where-Object{$_.CACPrincipalName}

    #if ($certificateUserIDUsers) {write-host "waiting 5 seconds...";Start-Sleep -s 5}
    foreach ($user in $certificateUserIDUsers) {
        Update-UserCertIDs -UPN $user.UserPrincipalName -CACPrincipalName $user.CACPrincipalName -MSGraphURI $MSGraphURI
    }

    #create license group and assign licenses
    Write-host -ForegroundColor Yellow "Creating licensing group"
    $LicenseGroup = $Parameters.StepParameterSet.NamedAccounts.parameters.LicenseGroup | ConvertTo-Json
    $LicenseGroupObj = New-MgGroup -BodyParameter $LicenseGroup
    Set-MgGroupLicense -GroupId $LicenseGroupObj.Id -BodyParameter $License

    #add to MLZ core admin unit
    Write-host -ForegroundColor Yellow "Adding MLZ core users to an Administrative Unit"
    $CoreAU = $Parameters.StepParameterSet.AdminUnits.parameters.CoreAU
    $CoreAUObj = Get-MgDirectoryAdministrativeUnit -Filter "startsWith(DisplayName, `'$($CoreAU.displayName)`')"
    $CoreUserObj = Get-MgUser -Filter "startsWith(Department,`'MLZ`')"
    $CoreUserRefArray = @($CoreUserObj.Id)

    <#$params = Build-MemberberArrayParams -members $CoreUserRefArray -MSGraphURI $MSGraphURI -objectType "users"
    Update-MgDirectoryAdministrativeUnit -AdministrativeUnitId $CoreAUObj.Id -BodyParameter $params#>

    foreach ($user in $CoreUserObj.Id) {

        $params = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($user)"
        }
        Try {
            New-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $CoreAUObj.Id -BodyParameter $params
        } Catch [Exception] {
            Write-Host "Member already added. Skipping."
        }
        

    }

    Write-Host -ForegroundColor Green "Completed creating Named Accounts."
}

#endregion

#region AuthNMethods
if ($AuthNMethods -or $All) {
    Import-Module Microsoft.Graph.Identity.SignIns
    Connect-MgGraph -Scopes Policy.ReadWrite.AuthenticationMethod
    #Select-MgProfile beta
    $AuthNMethodsConfiguration = $Parameters.StepParameterSet.AuthNMethods.parameters.AuthenticationMethodsConfigurations

    #Turn on FIDO2
    Write-Host -ForegroundColor Yellow "Enabling FIDO2 Authentication Method"
    $fido2 = $AuthNMethodsConfiguration.Fido2
    $microsoftauthenticator = $AuthNMethodsConfiguration.MicrosoftAuthenticator
    $X509certificate = $AuthNMethodsConfiguration.X509Certificate
    $registrationConfiguration = $Parameters.StepParameterSet.AuthNMethods.parameters.RegistrationSettings

    $EAGroupName = $Parameters.StepParameterSet.EmergencyAccess.parameters.EAGroup.mailNickname
    $EAGroupObj = Get-MgGroup -Filter "MailNickname eq `'$EAGroupName`'"

    Write-Host -ForegroundColor Yellow "Setting Authentication Methods:"
    $($Parameters.StepParameterSet.AuthNMethods.parameters.AuthenticationMethodsConfigurations)
    Write-Host -ForegroundColor Yellow "Configuring Registration:"
    $($Parameters.StepParameterSet.AuthNMethods.parameters.RegistrationSettings)
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
             #To do: Errors testing in some environments
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
            #To do: Errors testing in some environments
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

    Write-Host -ForegroundColor Green "Completed Authentication Methods configuration."
}

#endregion

<#
#region Certificates
if ($Certificates -or $All) {
    Import-Module AzureAD
    if ($Environment -eq "USGov" -or $Environment -eq "USGovDOD") {
        $AADEnvironment = "AzureUSGovernment"
    } elseif ($Environment -eq "Global") {
        $AADEnvironment = "AzureCloud"
    }

    Try {
        $connected = Get-AzureADTenantDetail -ErrorAction Stop
    } Catch [exception] {}

    #Connect if not already connected
    if (!($connected)) {
        Connect-AzureAD -AzureEnvironmentName $AADEnvironment
    }

    #Load in the configuration
    $CertConfigPath = $Parameters.StepParameterSet.Certificates.parameters.CertJsonRelativePath
    $DisableCrlCheck = $Parameters.StepParameterSet.Certificates.parameters.DisableCrlCheck
    $CertConfig = Get-Content $CertConfigPath | ConvertFrom-Json

    #Get existing certificate configuration
    Write-host "Getting current certificate configuration for the tenant." -ForegroundColor Cyan
    $TenantCertificates = Get-AzureADTrustedCertificateAuthority

    #Check to see if certificates exist, if not add AzureADTrustedCertificateAuthority
    Write-host "Uploading certificates to the tenant." -ForegroundColor Cyan
    foreach ($cert in $Certconfig) {
        if ($cert.Subject -in $TenantCertificates.TrustedIssuer) {
            Write-host "Certificate $($cert.Subject) already exists."
        } else {
            $new_ca=New-Object -TypeName Microsoft.Open.AzureAD.Model.CertificateAuthorityInformation
            $new_ca.AuthorityType=$($cert.authority)
            $new_ca.TrustedCertificate=$(Convert-HexStringToByteArray -String $cert.RawData)

            if ($DisableCrlCheck) {
                $new_ca.crlDistributionPoint=''
            } else {
                $new_ca.crlDistributionPoint=$($cert.crl)
            }
        
            New-AzureADTrustedCertificateAuthority -CertificateAuthorityInformation $new_ca
        }
        
    }

    Write-Host -ForegroundColor Green "Completed Certificate configuration."
}
#endregion
#> 

#region Groups
if ($Groups -or $All) {
    $SGs = $Parameters.StepParameterSet.Groups.parameters.SecurityGroups
    $PAGs = $Parameters.StepParameterSet.Groups.parameters.PAGs
    $MissionAUs = $Parameters.GlobalParameterSet.MissionAUs

    foreach ($group in $SGs) {
        New-MLZGroup -Group $Group -MissionAUs $MissionAUs
    }

    foreach ($pag in $PAGs) {
       New-MLZGroup -Group $pag -MissionAUs $MissionAUs -PAG
    }
}
#endregion

#region PIM
if ($PIM -or $All) {
    Import-Module Microsoft.Graph.Identity.Governance
    Import-Module Microsoft.Graph.Identity.DirectoryManagement
    Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

    $roles = $Parameters.StepParameterSet.PIM.parameters.Roles
    #$coreroles = $roles | ?{"tenant" -in $_.scope}
    #$missionroles = $roles | ?{"mission" -in $_.scope}
    $PAGs = $Parameters.StepParameterSet.Groups.parameters.PAGs

    #find the role definition templates and assigned policies
    Write-Host "Finding role templates and policy assignments. This may take a few minutes..."
    $roles | Add-Member -MemberType NoteProperty -Name "RoleTemplateId" -value "" -Force
    $roles | Add-Member -MemberType NoteProperty -Name "AssignedPolicies" -value "" -Force
    $roles | Add-Member -MemberType NoteProperty -Name "RoleId" -Value "" -Force

    foreach ($role in $roles) {
        $role.RoleTemplateId = $(Get-MgRoleManagementDirectoryRoleDefinition -Property "DisplayName","TemplateId" | Where-Object{$_.Displayname -eq $role.name}).TemplateId
        $role.AssignedPolicies = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'Directory' and RoleDefinitionId eq `'$($role.RoleTemplateId)`'"
        $role.RoleId = $(Get-MgDirectoryRole -Filter "DisplayName eq `'$($role.name)`'").Id
    }

    #update rules for the assigned policies
    foreach ($role in $roles) {
        Write-Host -ForegroundColor Yellow "Updating Role Policy Settings for $($role.name)..."
        Update-MLZPIMPolicyRules -UnifiedRoleManagementPolicyId $role.AssignedPolicies.PolicyId -EligibilityMaxDurationInDays $role.EligibilityMaxDurationInDays -ActivationMaxDurationInHours $role.ActivationMaxDurationInHours
    }

    #assign eligibility schedule

    #find the groups and roles to add to PAG
    $PAGs | Add-Member -MemberType NoteProperty -Name "Groups" -Value "" -Force
    $PAGs | Add-Member -MemberType NoteProperty -Name "Role" -Value "" -Force
    foreach ($PAG in $PAGs) {
        $PAG.Groups = Get-MgGroup -Filter "StartsWith(MailNickname, '$($PAG.mailNickname)`')" -Property "MailNickname","DisplayName","GroupTypes","Id"
        $PAG.Role = $roles | Where-Object{$_.name -eq $PAG.aadrole}
    }

    $CoreAU = $Parameters.StepParameterSet.AdminUnits.parameters.CoreAU
    $CoreAUObj = Get-MgDirectoryAdministrativeUnit -Filter "DisplayName eq `'$($CoreAU.displayName)`'"
    $MissionAUs = $Parameters.GlobalParameterSet.MissionAUs
    $UserTemplate = $Parameters.StepParameterSet.AdminUnits.parameters.MissionAUUserTemplate
    $GroupTemplate = $Parameters.StepParameterSet.AdminUnits.parameters.MissionAUGroupTemplate

    #Find the right PAG
    $groupPAG = $($PAGs | Where-Object{$_.mission -eq $true -and $_.aadrole -eq "Groups Administrator"})
    $userPAG = $($PAGs | Where-Object{$_.mission -eq $true -and $_.aadrole -eq "User Administrator"})

    #Loop through each AU and make assignments for each Mission
    foreach ($AU in $MissionAUs) {

        #Find AU objects for the Mission
        $GroupAUObj = $(Find-MLZMissionAUObj -AU $AU -Type group -Template $GroupTemplate)
        $UserAUObj = $(Find-MLZMissionAUObj -AU $AU -Type user -Template $UserTemplate)

        #Find the groups
        $GAdminGroup = $groupPAG.Groups | Where-Object{$_.MailNickName -match "$($AU)$"}
        $UAdminGroup = $userPAG.Groups | Where-Object{$_.MailNickName -match "$($AU)$"}

        #Create eligibility schedules
        New-MLZPIMRoleEligibilitySchedule -role $groupPAG.Role -PrincipalID $GAdminGroup.Id -Scope "$($groupPAG.scope)$($GroupAUObj.Id)" -Permanent
        New-MLZPIMRoleEligibilitySchedule -role $userPAG.Role -PrincipalID $UAdminGroup.Id -Scope "$($userPAG.scope)$($UserAUObj.Id)" -Permanent
    }

    #Assign Core roles
    Write-Host -ForegroundColor Cyan "Assigning eligibility to core roles"
    $groupPAG = $($PAGs | Where-Object{$_.core -eq $true -and $_.aadrole -eq "Groups Administrator"})
    $userPAG = $($PAGs | Where-Object{$_.core -eq $true -and $_.aadrole -eq "User Administrator"})
    $GAdminGroup = $groupPAG.Groups | Where-Object{$_.MailNickName -match "MLZ"}
    $UAdminGroup = $userPAG.Groups | Where-Object{$_.MailNickName -match "MLZ"}

    New-MLZPIMRoleEligibilitySchedule -role $groupPAG.Role -PrincipalID $GAdminGroup.Id -Scope "$($groupPAG.scope)$($CoreAUObj.Id)" -Permanent
    New-MLZPIMRoleEligibilitySchedule -role $userPAG.Role -PrincipalID $UAdminGroup.Id -Scope "$($userPAG.scope)$($CoreAUObj.Id)" -Permanent

    #To Do - Add a 6 month access review.

    Write-Host -ForegroundColor Green "Completed PIM configuration."
}

#endregion

#region ConditionalAccess
if ($ConditionalAccess -or $All) {
    Write-Host -ForegroundColor Cyan "Configuring Conditional Access Policies for MLZ Baseline."

    Connect-MgGraph -Scopes 'Application.Read.All','Policy.Read.All','Policy.ReadWrite.ConditionalAccess'
    #Select-MgProfile beta

    #get current user
    $CurrentUserID = $(Get-MgUser -Filter "UserPrincipalName eq `'$($(Get-MgContext).Account)`'").Id

    #get EA Groupname
    $EAGroupName = $($Parameters.StepParameterSet.EmergencyAccess.parameters.EAGroup).displayName
    $EAGroupID = $(Get-MGGroup -Filter "DisplayName eq `'$EAGroupName`'").Id

    #Get the policies from template
    $CAPolicies = $Parameters.StepParameterSet.ConditionalAccess.parameters.Policies

    #Iterate through and create
    foreach ($policy in $CAPolicies) {
        New-MLZCAPolicy -policy $policy -CurrentUserID $CurrentUserID -EAGroupID $EAGroupID
    }
    Write-Host -ForegroundColor Green "Completed Conditional Access Policy creation."
}
#endregion

#region TenantPolicies
if ($TenantPolicies -or $All) {
    Connect-MgGraph -Scopes Policy.ReadWrite.Authorization,Policy.ReadWrite.ExternalIdentities

    $authorizationPolicy = $Parameters.StepParameterSet.TenantPolicies.parameters.authorizationPolicy
    $externalIdentityPolicy = $Parameters.StepParameterSet.TenantPolicies.parameters.externalIdentityPolicy
    $consentPolicySettings = $Parameters.StepParameterSet.TenantPolicies.parameters.consentPolicySettings
    $xtapDefaultPolicy = $Parameters.StepParameterSet.TenantPolicies.parameters.crossTenantAccessPolicy
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
    #Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -BodyParameter $params
    Update-MgPolicyAuthorizationPolicy -BodyParameter $params

    Write-host -ForegroundColor Cyan "Updating External Identity Policies"

    $params = @{
        "@odata.context" = "$MSGraphURI/`$metadata#policies/externalIdentitiesPolicy/$entity"
        AllowExternalIdentitiesToLeave = $externalIdentityPolicy.allowExternalIdentitiesToLeave
        AllowDeletedIdentitiesDataRemoval = $externalIdentityPolicy.allowDeletedIdentitiesDataRemoval
    }

    #Update-MgPolicyExternalIdentityPolicy -BodyParameter $params
    Update-MgBetaPolicyExternalIdentityPolicy -BodyParameter $params

    Write-host -ForegroundColor Cyan "Updating Admin Consent Polices"
    
    #$ConsentSettings = Get-MgDirectorySetting | Where-Object{$_.DisplayName -eq "Consent Policy Settings"}
    $consentSettingsTemplateId = "dffd5d46-495d-40a9-8e21-954ff55e198a" # Consent Policy Settings
    $ConsentSettings = Get-MgBetaDirectorySetting | ?{ $_.TemplateId -eq $consentSettingsTemplateId }
    
    #set params
    $params = @{
        Values = @(
            @{
                Name = "EnableGroupSpecificConsent"
                Value = $consentPolicySettings.enableGroupSpecificConsent
            }
            @{
                Name = "BlockUserConsentForRiskyApps"
                Value = $consentPolicySettings.BlockUserConsentForRiskyApps
            }
            @{
                Name = "EnableAdminConsentRequests"
                Value = $consentPolicySettings.EnableAdminConsentRequests
            }
            @{
                Name = "ConstrainGroupSpecificConsentToMembersOfGroupID"
                Value = $consentPolicySettings.ConstrainGroupSpecificConsentToMembersOfGroupId
            }
        )
    }

    if (!$ConsentSettings) {
        #create the new setting if there is not one existing
        #$TemplateId = $(Get-MgDirectorySettingTemplate | Where-Object {$_.DisplayName -eq "Consent Policy Settings"}).Id
        #New-MgDirectorySetting -TemplateId $TemplateId -Values $params.Values -DisplayName "Consent Policy Settings"

        New-MgBetaDirectorySetting -TemplateId $consentSettingsTemplateId -Values $params.Values -DisplayName "Consent Policy Settings"
    } else {
        Update-MgBetaDirectorySetting -DirectorySettingId $ConsentSettings.Id  -BodyParameter $params 
    }

    Write-Host -ForegroundColor Cyan "Updating Cross-Tenant Access Policy Default Inbound Settings"
    $params = @{
        "@odata.context" = "#microsoft.graph.crossTenantAccessPolicyInboundTrust"
        IsMfaAccepted = $xtapDefaultPolicy.isMfaAccepted 
        IsCompliantDeviceAccepted = $xtapDefaultPolicy.isCompliantDeviceAccepted
        IsHybridAzureADJoinedDeviceAccepted = $xtapDefaultPolicy.isHybridAzureADJoinedDeviceAccepted
    }

    Update-MgBetaPolicyCrossTenantAccessPolicyDefault -BodyParameter $params

    Write-Host -ForegroundColor Green "Completed configuration of Cross-Tenant Access Policy"
}
#endregion

#region EntitlementsManagement
if ($EntitlementsManagement -or $All) {
    
    #Import module and connect to MS Graph
    Import-Module Microsoft.Graph.Identity.Governance
    Connect-MgGraph -Environment $Environment -Scopes EntitlementManagement.ReadWrite.All
    
    #Get the catalog settings from JSON parameters
    $CoreCatalog = $Parameters.StepParameterSet.EntitlementsManagement.parameters.CoreCatalog
    $MissionCatalogTemplate = $Parameters.StepParameterSet.EntitlementsManagement.parameters.MissionCatalogTemplate
    
    Write-Host -ForegroundColor Cyan "Creating Access Package Catalogs"

    #Create the Core Catalog
    
    $params = @{
	    displayName = $CoreCatalog.displayName
	    description = $CoreCatalog.description
	    isExternallyVisible = $CoreCatalog.isExternallyVisible
    }

    #New-MgEntitlementManagementAccessPackage -BodyParameter $params
    New-MgEntitlementManagementCatalog -BodyParameter $params

    #Create the Mission Catalogs
    foreach ($MissionAU in $MissionAUs) {
        $params = Convert-MLZCatalogFromTemplate -template $MissionCatalogTemplate -missionAU $MissionAU | ConvertTo-Json
        New-MLZAccessPackageCatalog -BodyParameter $params
    }
    
    Write-Host -ForegroundColor Green "Completed creation of Access Package catalogs."

}
#endregion

if ($all) {
    Write-Host -ForegroundColor Green "Completed AAD Tenant Baseline Script"
}