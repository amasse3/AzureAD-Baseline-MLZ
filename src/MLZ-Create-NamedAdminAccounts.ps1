#MLZ-Create-NamedAdminAccounts.ps1
<#
.SYNOPSIS

Creates cloud-only uuser accounts in Azure Active Directory.

.DESCRIPTION

Creates a licensing group and cloud-only administrator accounts.

.INPUTS

UserCSV,LicenseGroupName,PWDLength

.OUTPUTS

System.String

.EXAMPLE

PS> ./MLZ-Create-NamedAdminAccounts.ps1 -UserCSV ".\MLZ-Admin-List.csv" -LicenseGroupName "MLZ-License-AADP2"

.LINK

Placeholder

#>

Param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [string]$UserCSV,
    [String]$LicenseGroupName,
    [Parameter(Mandatory=$false)]
    [ValidateRange(8,256)]
    [Int]$PWDLength,
    [Parameter(Mandatory=$false)]
    [ValidateSet("Global","USGov","USGovDoD")]
    [string]$Environment,
    [Parameter(Mandator=$false)]
    [string]$EAGroupName
)

#region defaultvalues
$DefaultLicenseGroupName = "MLZ-License-AADP2"
$DefaultEnvironment = "Global"
$DefaultPWDLength = 16
$DefaultEAGroupName = "Emergency Access Accounts"

#if no parameters, use default values
if (!($LicenseGroupName)){$LicenseGroupName=$DefaultLicenseGroupName}
if (!($PWDLength)){$PWDLength=$DefaultPWDLength}
if (!($Environment)){$Environment=$DefaultEnvironment}
if (!($EAGroupName)){$EAGroupName=$DefaultEAGroupName}
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
}
#endregion

#region main script

#load module
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Identity.SignIns

#connect MS Graph
Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All" -Environment $Environment
Select-MgProfile -Name "beta"

#read CSV file and create users
Write-Host "Importing CSV File from $MissionUserCSVFile" -ForegroundColor Cyan
$CSV = Import-Csv $UserCSV

$adminlist = @()
foreach ($userobj in $CSV) {
    $adminlist += New-MLZAADUser -user $userobj -MissionCode "MLZ" -PasswordLength $PasswordLength
}

#set userCertIdsvalues
$CBAUsers = $CSV | Where-Object{$_.UserCertificateIds -ne $null}
foreach ($userobj in $CBAUsers) {
    UpdateUserCertIDs -UPN $userobj.UserPrincipalName -CACPrincipalName $userobj.UserCertificateIds
}

#Create dynamic group for licensing
$params = @{
	Description = "Licensing group for MLZ administrators. Created for MLZ on $(get-date)."
	DisplayName = $LicenseGroupName
	GroupTypes = @(
		"DynamicMembership"
	)
    MembershipRule = '(user.department -match "MLZ")'
    MembershipRuleProcessingState = "On"
	MailEnabled = $true
	MailNickname = $LicenseGroupName
	SecurityEnabled = $true
}

Try {
    $LicenseGroup = New-MgGroup -BodyParameter $params -ErrorAction SilentlyContinue
} Catch {} #To Do

Write-Host -ForegroundColor Cyan "Created users with Department `"MLZ`".`nCreated dynamic security group $LicenseGroupName for assigning licenses with Group-Based Licensing feature."

#Enable CBA and FIDO2 authentication methods, target initial admins with registration campaign.
Import-Module Microsoft.Graph.Identity.SignIns

$EAGroupID = $(Get-MgGroup -Filter "DisplayName eq `'$EAGroupName`'").Id

$params = @{
	"@odata.context" = "https://graph.microsoft.com/beta/$metadata#authenticationMethodsPolicy"
	RegistrationEnforcement = @{
		AuthenticationMethodsRegistrationCampaign = @{
			SnoozeDurationInDays = 1
			State = "enabled"
			ExcludeTargets = @(
                @{
                    Id = $EAGroupID
                    TargetType = "group"
                }
			)
			IncludeTargets = @(
				@{
					Id = $LicenseGroup.Id
					TargetType = "group"
					TargetedAuthenticationMethod = "microsoftAuthenticator"
				}
			)
		}
	}
	AuthenticationMethodConfigurations = @(
		@{
			"@odata.type" = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
			Id = "Fido2"
			State = "enabled"
			IsSelfServiceRegistrationAllowed = $true
			IsAttestationEnforced = $false
            excludeTargets = @()
            includeTargets = @(
                @{
                    targetType = "group"
                    id = "all_users"
                    isRegistrationRequired = $false
                }
            )
		},
        @{
			"@odata.type" = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
			Id = "X509Certificate"
			State = "enabled"
			certificateUserBindings = @(
                @{
                    x509CertificateField = "PrincipalName"
                    userProperty = "certificateUserIds"
                    priority = 1
                }
            )
            authenticationModeConfiguration = @{
                x509CertificateAuthenticationDefaultMode = "x509CertificateMultiFactor"
            }
            excludeTargets = @()
            includeTargets = @(
                @{
                    targetType = "group"
                    id = "all_users"
                    isRegistrationRequired = $false
                }
            )
		}
	)
}

Update-MgPolicyAuthenticationMethodPolicy -BodyParameter $params

Write-Host -ForegroundColor Cyan "Enabled FIDO2 and Certificate-Based Authentication methods. Targeted $($LicensGroup.DisplayName) for MFA registration campaign. Excluded $($EAGroupName) from registration campaign (break glass accounts)."

Write-Host -ForegroundColor Green "Script complete."