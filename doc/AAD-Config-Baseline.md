# Azure Active Directory Baseline Configuration for MLZ
This document provides key steps for deploying and securing a new Azure Active Directory environments using a JSON configuration parameters file and Microsoft Graph PowerShell.

Azure AD is constantly evolving, exposing new settings and enabling new security features. The settings baselined here are by no means an exhaustive list. At minimum, the recommendations and feature settings described here should be evaluated for implementation in existing tenants.

While much of this content and sample configuration was developed as an unofficial "add-on" for Mission Landing Zone deployments, the general approach using MS Graph and a declarative AAD configuration can be used to baseline any Azure AD tenant. Individual settings for each design area in the scripted configuration can be modified by adjusting the parameters file.

> **Warning**: It is **not** recommended to run through the configuration end-to-end in existing production tenants as the setting changes could disrupt access to the Azure environment. For more information, see the disclaimer [here](/../MLZ-Identity-AzureADSetup/README.md).

## Table of Contents
- [About the baseline configuration](#about-the-baseline-configuration)
- [Prepare to manage Azure AD](#prepare-to-mange-azure-ad)
- [Scripted Configuration](#scripted-configuration)
  - [Administrative Units](#administrative-units)
  - [Emergency Access](#emergency-access)
  - [Named Accounts](#named-accounts)
  - [Authentication Methods](#authentication-methods)
  - [Certificates](#certificates)
  - [Security Groups](#security-groups)
  - [Privileged Identity Management](#privileged-identity-management)
  - [Conditional Access](#conditional-access)
  - [Tenant Policies](#tenant-policies)
  - [Entitlements Management](#entitlements-management)
- [Post Deployment](#post-deployment)
  - [Configure Certificate-Based Authentication](#configure-certificate-based-authentication)
  - [Verify and enable Conditional Access](#verify-and-enable-the-conditional-access-policies)
  - [Domain verification and hybrid identity configuration](#domain-verification-and-hybrid-identity-configuration)
  - [Adding a Mission Spoke](#adding-a-new-mission-spoke)
  - [Plan for Zero Trust](#plan-for-zero-trust)
- [See Also](#see-also)

## About the baseline configuration

The script uses switches for each configuration item outlined in [scripted configuration](#scripted-configuration). 

Each switch can be run individually, multiple switches can be included, or the `-All` switch can be used to apply everything in the configuration.

> **Note**: Do not use the `-All` switch unless the `mlz-aad-parameters.json` file has been updated and validated for your organization.

To learn about the deployment process, see the [about page](/doc/baseline/AAD-Config-Baseline-About.md).

## Prepare to mange Azure AD
Before we can get started with the scripted configuration, we need to validate Azure AD tenant access, licensing, and other prerequisites for managing Azure AD.

Steps to get started are outlined in [Prepare to manage Azure AD](/doc/baseline/Prepare-AAD-Managment.md).

# Scripted Configuration
The document layout matches each section in the `Configure-AADTenantBaseline.ps1` PowerShell script.
- [Administrative Units](#administrative-units)
- [Emergency Access](#emergency-access)
- [Named Accounts](#named-accounts)
- [Authentication Methods](#authentication-methods)
- [Security Groups](#security-groups)
- [Privileged Identity Management](#privileged-identity-management)
- [Conditional Access](#conditional-access)
- [Tenant Policies](#tenant-policies)
- [Entitlements Management](#entitlements-management)

## Administrative Units
Administrative Units allow for scoping Azure AD privileges to certain resources. This section sets a baseline framework for delegated management in Azure AD. Once applied, the baseline will allow each Mission to manage their own users and RBAC groups for assigning access to resources in their own Azure subscription.

 - [ ] [🗒️ Modify AdminUnits parameters](#🗒️-modify-adminunits-parameters)
 - [ ] [⚙️ Run the script: AdminUnits](#⚙️-run-the-script-adminunits))

<details><summary><b>Show Content</b></summary>
<p>

### 🗒️ Modify AdminUnits parameters
In `mlz-aad-parameters.json`, modify the array in `GlobalParameterSet.MissionAUs` to create Administrative Units for separate mission subscriptions. If you do not plan on using administrative units for delegated administration, leave the parameter as an empty set, e.g. `"MissionAUs": []`.

Some Administrative Units are created for other sections of the configuration script. These are `MLZ Core Users and Groups` which gets created in addition to the set specifified in `MissionAUs` parameter, and `MLZ EA`, which is a restricted Administrative Unit containing the accounts created in the [emergency access](#emergency-access) section.

### ⚙️ Run the script: AdminUnits
Run the script to create Administrative Units.
`Configure-AADTenantBaseline.ps1 -AdminUnits`

The script will:
1. Create AU for MLZ Core Administration
2. For each Mission AU in `[GlobalParameterSet.MissionAUs]`, create 
  1. Mission Users (dynamic based on Department)
  2. Mission RBAC Groups

These Admin Units will be used to scope the directory role assignments in [Confiure Privileged Identity Management](#9-configure-privileged-identity-management-pim)

> 📘 [Administrative units in Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/roles/administrative-units)

</p>
</details>

## Emergency Access
One of the first things we need to do is create Emergency Access Accounts. These accounts will be excluded from Conditional Access and provide a means to access Azure AD if all other admins are locked out due to misconfiguration or service outage.

This section covers account creation for Emergency Access and day-to-day Azure AD administration.

- [ ] [Develop emergency access procedures](#develop-emergency-access-procedures)
- [ ] [Plan for monitoring and alerting emergency access account usage](#plan-for-monitoring-and-alerting-on-emergency-access-account-usage)
- [ ] [🗒️ Modify EmergencyAccess parameters](#🗒️-modify-emergencyaccess-parameters)
- [ ] [⚙️ Run the script: EmergencyAccess](#3-⚙️-run-the-script-emergencyaccess)
- [ ] [Complete setup for emergency access accounts](#4-complete-setup-for-emergency-access-accounts)

<details><summary><b>Show Content</b></summary>
<p>

### Develop Emergency Access procedures
Creating and safeguarding emergency access account credentials is an important step in Azure AD tenant setup. Establishing, disseminating, and testing emergency procedures is equally important.

> **Note**: Consult your Information Systems Security Officer (ISSO) for proper handling procedures for Emergency Access accounts.

> 💡 **Recommendations**:
> - [x] Record passwords for Emergency Access accounts legibly by hand (do not type or send to a printer)
> - [x Store passwords for Emergency Access accounts in a safe that resides in a physically secure location.
> - [x] Do not save passwords to an Enterprise password vault or Privleged Access Management (PAM) system.
> - [x] Do not save passwords to a personal password vault (LastPass, Apple Keychain, Google, OnePassword, Microsoft Authenticator, etc.)
> - [x] Store backup copies for Emergency Access account credentials in a geographic distant location.
> - [x] Exclude at least one (1) Emergency Access account from Azure MFA.
> - [x] Monitor and alert on Emergency Access account usage.
> - [x] Register FIDO2 security keys as another authentication mechanism (2 per account), storing the keys and PIN in separate physical safes.
> - [x] Be sure to check the latest Microsoft recommendation for managing emergency access from the reference below.

> 📘 [Manage Emergency Access Accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

### Plan for monitoring and alerting on emergency access account usage
Azure AD logs must be connected to the Microsoft SIEM, Sentinel, to set up automated alerting based on Emergency Access Account usage.

> **Warning**: Remember to revisit these steps once Mission Landing Zone is deployed and Microsoft Sentinel is enabled.

1. [Connect Azure AD Sign-In Logs to Microsoft Sentinel](https://docs.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory)
2. [Configure an Analytics Rule to alert when Emergency Access account is used](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access#monitor-sign-in-and-audit-logs)

### 🗒️ Modify EmergencyAccess parameters
In `mlz-aad-parameters.json`, modify the configuration for `StepParameterSet.EmergencyAccess.Users` as needed. For example, you may want to modify the PhoneNumber attribute.

### ⚙️ Run the script: EmergencyAccess
Run the script to create Emergency Access accounts in Azure AD:

```PowerShell
Configure-AADTenantBaseline.ps1 -EmergencyAccess
```

The script will:
1. Create two Emergency Access accounts, `MLZEA01, MLZEA02`
2. Create an `Emergency Access Accounts` Privileged Access Group.
3. Permanently assign `Global Administrator` role using Privileged Identity Management.
4. Apply licenses for AAD Premium P2 / E5.

### Complete setup for Emergency Access accounts
Perform the following manual steps to complete the configuration:
1. Using the first admin account, reset the password on the newly created EA accounts using the Azure Portal.
2. Sign in with each account and reset the password (see recommendations in the next section).
3. Optional: register two (2) FIDO2 security keys for each account.
3. Once passwords are set and stored in a secure location, sign out of the Azure Portal.

> 📘 [Manage emergency access accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

</p>
</details>

## Named Accounts
This step will create "named" administrator accounts. These are cloud-only Azure AD users mapped to individual administrators in the organization. Attributes should align to real people to assist in assigning least-privilege permissions and correlating admin activities.

- [ ] [🗒️ Create a named admin list CSV](#🗒️-create-named-admin-list-csv-file)
- [ ] [⚙️ Run the script: NamedAccounts](#⚙️-run-the-script-namedaccounts)
- [ ] [Complete setup for named administrator acccounts](#complete-setup-for-named-administrator-accounts)

<details><summary><b>Show Content</b></summary>
<p>

### 🗒️ Create Named Admin List CSV file
This step prepares the [MLZ-Admin-List.csv](/MLZ-Identity-AzureADSetup/src/MLZ-Admin-List.csv) CSV file. 

#### Choose a naming convention
Choose a naming convention for cloud-only administrative accounts. For example:
- FirstName+"."+LastName
- FirstInitial+LastName
- "adm." + FirstInitial+LastName
- "mlz."+FirstInitial+LastName

#### Update CSV for cloud-only administrators
Download and edit [MLZ-Admin-List.csv](/MLZ-Identity-AzureADSetup/src/MLZ-Admin-List.csv) for your administrators. The CSV file location relative to the **Configure-AADTenantBaseline.ps1** script is set by `StepParameterSet.NamedAccounts.parameters.Users.UserCSV` in the JSON parameters file.

Description for the CSV file schema:
|LastName|FirstName|DisplayName|UserPrincipalName|Mail|PhoneNumber|MissionCode|CACPrincipalName|UsageLocation|
|--------|---------|-----------|-----------------|----|-----------|-----------|----------------|-------------|
|User's last name|User's first name|Display Name|sign-in name for AAD. If domain suffix is invalid, the initial domain will be used.|Contact email address|Phone number|Mission code for the user. This should match an AU set in GlobalParameters.|Certificate name value (see note)|Usage location for applying licenses. e.g. "US"|

> **Note**: The **UserCertificateIds** field is needed for configuring Azure AD Certificate-based authentication. Setting this value upon user creation is optional.

DisplayName and UserPrincipalName can be set programatically using PowerShell. See the following example:
```PowerShell
function upn {
    Param($FirstName,$LastName,$Suffix)
    $upn = "mlz."+$($FirstName.ToLower()[0])+$($LastName.SubString(0,$LastName.Length).ToLower()) + $Suffix
    Return $upn
}

function displayName {
    Param($FirstName,$LastName)
    $displayName = $FirstName+" "+$LastName+" (MLZ)"
    return $displayName
}

$CSV = Import-Csv -Path .\MLZ-Admin-List.csv
$Suffix = "@contoso.onmicrosoft.us" 

#Find the suffix by looking for the initial domain of the tenant.
<#
Connect-MgGraph -Environment Global
$Suffix = "@$((Get-MgDomain | ?{$_.IsInitial -eq 'true'}).Id)"
#>

foreach ($row in $CSV) {
    $row.UserPrincipalName = upn -FirstName $row.FirstName -LastName $row.LastName -Suffix $Suffix
    $row.DisplayName = displayName -FirstName $row.FirstName -LastName $row.LastName
}

#Optional: use Export-Csv to write the new values back to CSV.
```

### ⚙️ Run the script: NamedAccounts
Run the script to create named administrator accounts in Azure AD:

```PowerShell
Configure-AADTenantBaseline.ps1 -NamedAccounts
```

The script will:
1. Create named administrator accounts from **MLZ-Admin.List.csv**
2. Create a Dynamic Security Group for licensing using the definition from `StepParameterSet.NamedAccounts.parameters.LicenseGroup`.
  1. displayName = **MLZ-Licensing-AADP2**
  2. membershipRule: "(user.userType -eq \"Member\")"
  3. Group based licensing for Azure AD Premium P2/E5
3. Add the users to a new, protected Administrative Unit named **MLZ-Core Admins**

### Complete setup for named administrator accounts
Day-to-day operations requiring administrative privileges should be performed by named administrator accounts, assigned to individual users (not shared), separate from accounts used to access productivity services like Email, SharePoint, and Teams.

> 💡 **Recommendations**:
> - Administration for Azure and Azure AD should use cloud-only identities and Azure AD native authentication mechanism, like FIDO2 security keys or smartcard certificates.
> - Limit the number of Global Administrators, referring to [least privileged roles by task](https://docs.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task) to assign the proper limited administrator role
> - Assign permissions Just-In-Time using [Azure AD Privileged Identity Management](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)
> - Periodically review role eligibility
> - Leverage PIM [insights](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-security-wizard) and [alerts](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-configure-security-alerts) to further secure your organization
> - Review [Privileged Access Groups](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/groups-features) and [Administrative Units](https://docs.microsoft.com/en-us/azure/active-directory/roles/administrative-units)

#### Set password protection policy
Configure banned password list using [Azure AD Password Protection](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad).

#### Choose a strong authentication method for administrators
The AAD basline scripts automatically enable phishing-resisitant methods FIDO2 and CBA for all users. Consider the MFA options available in Azure AD when updating organizational policy to use phishing-resistant MFA for administrators.

> 💡 **Recommendations**: Only use phishing-resistant passwordless authentication methods for administration. Review the authenticator options available in Azure AD from the list below:
> - **Bad:** SMS or TwoWayPhone
Some MFA is better than no MFA, but phone-based MFA is the weakest option available. SMS is especially egregious since it is susceptable to [SIM swapping attacks](https://en.wikipedia.org/wiki/SIM_swap_scam).
> - **Good:** Authenticator App TOTP Code or Push notification
These methods are not phishing-resistant or passwordless. In either case, a password is used, followed by an Azure MFA prompt.
> - **Better:** Passwordless Phone Sign-In on Registered Device
Passwordless, but not phishing-resistant. This required registration of an iOS or Android mobile device with the Azure AD tenant.
> - **Best:** Phishing-Resistant MFA FIDO2 Security Key or Azure AD native Certificate-Based Authentication (CBA)
>   - FIDO2 Security Key
>   - Azure AD Native Certificate-Based Authentication
>   - Windows Hello for Business

> **Note**: Microsoft Authenticator App is considered phishing-resistant when deployed to a managed mobile device. Since this guide is for setting up a new tenant, it assumes Microsoft Endpoint Manager is not configured to manage mobile devices.

> 📘 [Authentication methods in Azure AD](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods)\
> 📘 [Phishing-resistant methods](https://docs.microsoft.com/en-us/azure/active-directory/standards/memo-22-09-multi-factor-authentication#phishing-resistant-methods)

#### Distribute accounts for administrators
Complete setup for the named administrator accounts:
1. Manually reset the password from each administrator.
2. Provide the password to the admin.
3. Instruct the admin to change password and [register security info](https://support.microsoft.com/en-us/account-billing/set-up-the-microsoft-authenticator-app-as-your-verification-method-33452159-6af9-438f-8f82-63ce94cf3d29) by setting Microsoft Authenticator App as a verification method.

> 📘 [Reset a user's password using Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-users-reset-password-azure-portal)\
> 📘 [Assign licenses to users by group membership in Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-groups-assign)

</p>
</details>

## Authentication Methods
Azure AD authenticaton methods allow an administrator to configure how users can authenticate to Azure AD.

- [ ] [⚙️ Run the script: AuthNMethods](#⚙️-run-the-script-authnmethods)

> 📘 [What authentication verification methods are available in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods)

<details><summary><b>Show Content</b></summary>
<p>

### ⚙️ Run the script: AuthNMethods
Run the script to configure authentication methods:

```PowerShell
Configure-AADTenantBaseline.ps1 -AuthNMethods
```
The sections below describe the methods enabled. Additionally, weak methods like Software OAuth, SMS, and Email will be disabled.

#### Enable Microsoft authenticator app
The Microsoft Authenticator app for iOS and Android lets users authenticate / complete MFA challenges when Azure AD configuration (Conditional Access or Security Defaults) needs an additional factor. The Microsoft Authenticator app can be used in the following ways:
- Passwordless Phone Sign-in
- Notification
- Time-based One Time Password (TOTP) code

> 📘 [Microsoft Authenticator app](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-authenticator-app)

#### Enable FIDO2 security keys
FIDO2 security keys are an unphishable standards-based passwordless authentication method that come in different form factors. Most security keys resemble a USB thumb drive and communicate with device over USB.

> 📘 [Enable FIDO2 security keys](https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-passwordless-security-key)

#### Enable Certificate-Based authentication
Certificate-Based Authentication allows users to authenticate against Azure AD with a smartcard certificate. When enabled by the baseline scripts, x509Certificate authentication method is set to default as multifactor authentication. 

Bindings are set for certificateUserIds and onPremisesUserPrincipalName. The next section provides additional guidance for setting up CBA Authentication Method.
> 📘 [Azure AD Native Certificate-Based Authentication](https://docs.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication)

### 2. Disable weaker authentication methods
The deployment script will attempt to disable the following Authentication Methods:
- Temporary Access Pass
- Email
- SoftwareOath
- Sms

Sign in to the Azure Portal and verify these Authentication methods are not enabled by navigating to Azure Active Directory --> Security --> Authentication Methods.

</p>
</details>

## Certificates
This section uploads certificates for Azure AD certificate-based authentication.

 - [ ] [🗒️Create certificate JSON file](#🗒️create-certificate-json-file)
 - [ ] [🗒️Modify the parameters JSON file](#🗒️modify-the-parameters-json-file)
 - [ ] [⚙️ Run the script: Certificates](#⚙️-run-the-script-certificates)

<details><summary><b>Show Content</b></summary>
<p>

### 🗒️Create certificate JSON file
The sample file, [DODPKI.json](/src/DODPKI.json), contains the ID CA certificates and roots for the DOD PKI. This PKI is used by DOD Common Access Cards. For step-by-step guidance to manually configure DOD CAC, see [AAD-CertificateBasedAuthentication-DODPKI.md](/doc/quickstart/AAD-CertificateBasedAuthentication-DODPKI.md).

To make your own JSON file, get the string-formatted Raw Data for each certificate using `GetRawCertDataString()` method in PowerShell and create a JSON object with the following format:

```JSON
[
  {
    "Subject":  "CN=Root CA 01, OU=PKI, O=Contoso, C=US",
    "RawData":  "308203733082025B...00820122300D080AB720ECBE24851F2D43",
    "Authority":  0,
    "CRL":  "http://crl.contoso.com/crl/ROOTCA01.crl"
  },
  {
    "Subject":  "CN=Issuing CA 01, OU=PKI, O=Contoso, C=US",
    "RawData":  "308201EB30820281...806B64074C4565DF53AE1EDF143D2F5B7",
    "Authority":  0,
    "CRL":  "http://crl.contoso.com/crl/IDCA01.crl"
  }
]
```

where "Authority" is **0** for root CA and **1** for issuing CA. If the root CA is the issuing CA, use **0**. To add multiple certificate elements to the array, include a comma between each. 

<details><summary><b>Show Example Script</b></summary>
<p>

```PowerShell
#set variables
[string]$certificatePath = "Cert:\LocalMachine\My"
[string]$thumbprint = "D26EE73D697340BA9C72851761DAE52D4A3C977C"
[string]$outfile = $env:USERPROFILE + "\pkiconfig.json"
[array]$certarray = @()

#function
function Create-CBAConfigJson {
    Param([object]$cert,[bool]$root,[string]$crl)

    if ($root) {$authority=0}else{$authority=1}
    New-Object -TypeName PSObject -Property @{"Subject"=$cert.Subject;"RawData"=$cert.GetRawCertDataString();"Authority"=$authority;"CRL"=$crl}
}

#find the certificate objects
$cert = Get-ChildItem -Path $certificatePath | ?{$_.Thumbprint -eq $thumbprint}
$certjson = Create-CBAConfigJson -cert $cert -root $true -crl "http://test.contoso.com/crl" | ConvertTo-Json

#add additional certs to an array, or convert a single json representation to array (expected by Configure-AADTenantBaseline.ps1)
$certarray += $certjson

#finally, export the file
$certarray | Out-File -FilePath $outfile
```

</p>
</details>

### 🗒️Modify the parameters JSON file
Modify `mlz-aad-parameters.json`, updating `StepParameterSet.Certificates.CertJsonRelativePath`. By default, this will point to "DODPKI.json".

### ⚙️ Run the script: Certificates
Run the script below to create certficate authorities configuration in Azure AD:

```PowerShell
Configure-AADTenantBaseline.ps1 -Certificates
```
The script will:
1. Connect to Azure AD using the AzureAD PowerShell module
2. Load certificate details from the JSON file
3. Create new Certificate Authority objects in Azure AD 

> 📘 [Configure certification authorities using PowerShell](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#configure-certification-authorities-using-powershell)

</p>
</details>

## Security Groups
Use this set of Azure AD Security Groups and RBAC role assignments as a baseline.
- [ ] [Azure Resource RBAC](#1-azure-resource-rbac)
- [ ] [Azure AD Directory Roles](#2-azure-ad-directory-roles)
- [ ] [⚙️ Run the script: Groups](#3-⚙️-run-the-script-groups)

<details><summary><b>Show Content</b></summary>
<p>

### 1. Azure resource RBAC
Permissions for Azure resource management are granted through assignments to an Azure RBAC role. In the Azure Portal, RBAC role assignments can be created or viewed by selecting the IAM link. Azure RBAC assignments can apply to users (members and guests), security groups, service principals, and managed identities. 

> 💡 **Recommendation**: Assign permissions to Azure AD security groups. If Azure AD Premium P2 licesing is available, configure the security groups eligble for the Azure RBAC role assignments.

Azure RBAC can be assigned at any of the following scopes:
 - Management Group
   - Subscription
     - Resource Group
       - Resource

|Name|Usage|RBAC Role |Role Type|Scope|
|----|-----|----------|---------|--------------|
|Azure Platform Owner|Management Group and subscription lifecycle management|Owner|Built-in|Management Group|
|Security Operations|View and update permissions for Microsoft Defender for Cloud|Security Admin|Built-in|Subscription|
|Subscription Owner|Grants full access to manage all resources, including ability to assign roles with RBAC |Owner|Built-in|Subscription|
|Subscription Owner no Network Write|Delegated role for subscription owner that prohibits ability to manage role assignments and routes.SubscriptionOwnerNoNetwork|Custom|Subscription|
|Subscription Contributor|insert blurb|Contributor|Built-in|Subscription|
|Subscription Reader|insert blurb|Reader|Built-in|Subscription|
|Application Owners (DevOps)|Contributor role granted at resource group.|DevOpsAppOps|Custom|Resource Group|

### 2. Azure AD directory roles
In addition to Azure AD roles, there are several Azure AD Directory roles that may be needed. These roles can be assigned to users, groups (if group is role-assignable), and service principals.

Azure AD RBAC can be assigned at any of the following scopes:
 - Directory (default)
   - Administrative Unit
   - Azure AD Resource (Group or Application Owner)

 > 💡 **Recommendation**: Start by assigning Global Administrator role for Emergency Access accounts and tenant admins. When other Azure AD permissions are required, assign users using [least-privileged role by task](https://docs.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task). Review the insights and recommendations provided by Azure AD Privileged Identity Management.

|Name|Usage|
|----|-----|
|Application Developer|Register applications with Azure AD.|
|Application Administrator|Manage all Enterprise Applications in Azure AD.|
|Hybrid Identity Administrator|Configure Azure AD Connect to synchronize identities from AD DS to Azure AD|

**Azure AD Free or Premium P1**
Assign users directly to Azure AD roles.

**Azure AD Premium P2**
Create [Role-Assignable Groups](https://learn.microsoft.com/en-us/azure/active-directory/roles/groups-concept) and assign eligibility to Azure AD directory roles using Privileged Identity Management (PIM).

The following role-assignable groups are used in the AAD Configuration Baseline:
|Name|Usage|AAD Role|Role Type|Scope|
|----|-----|--------|---------|-----|
|Groups Administrator|Azure AD role assignment for managing groups|Groups Administrator|Built-in AAD Role|Global|
|Mission RBAC Role Manager|Privileged Access Group|AAD Role for Groups Administrator|Administrative Unit|
|Application Developers|Azure AD role assignment for app registration|Application Developers|Built-in AAD Role|Global|

> **Note**: These security group and role assignments represent baseline configuration. Modify with additional roles as needed, starting with built-in roles when possible.

### 3. ⚙️ Run the script: Groups
Run the script below to create Azure AD security groups:

```PowerShell
Configure-AADTenantBaseline.ps1 -Groups
```

The script will:
1. Create Security Groups for MLZ-Core and each Mission
2. Create Privileged Access Groups for User and Groups Administrator roles for each Administrative Unit

> 📘 [Use Azure AD groups to manage role assignments](https://learn.microsoft.com/en-us/azure/active-directory/roles/groups-concept)\
> 📘 [Best Practices for Azure AD roles](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices)\
> 📘 [Securing privileged access for hybrid and cloud deployments of Azure AD](https://learn.microsoft.com/en-us/azure/active-directory/roles/security-planning)\
> 📘 [Azure role-based access control](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/considerations/roles)

## Privileged Identity Management
Priviliged Access Management (PIM) is an Azure AD feature for providing Just-In-Time administration and eliminating standing privileges within Azure AD and Azure.

We enabled PIM when we signed in with the first AADP2-licensed Global Administrator in the [Prepare to manage Azure AD](#prepare-to-manage-azure-ad) steps.

This section assigns the groups created in the [previous section](#3-🗒️-run-the-script-groups) to Azure and AAD roles using PIM:

- [ ] [⚙️ Run the script: PIM](#1-⚙️-run-the-script-pim)
- [ ] [Review Securing Privileged Access in Azure AD](#2-review-securing-privileged-access-in-azure-ad)

### 1. ⚙️ Run the script: PIM
Run the script below to configure PIM:

```PowerShell
Configure-AADTenantBaseline.ps1 -PIM
```
The script will:
1. Find Role Templates for all roles defined in `mlz-aad-parameters.json`
2. Modify Rules for active PIM assignment Policies
  1. Set maximum role activation duration (change default from 8 hours to 4 hours)
  2. Set maximum role eligibility (change default to 180 Days)
3. Assign PIM eligibility schedule for User and Group Administrator Mission roles (for each Mission AU)
4. Assign PIM eligibility schedule for MLZ Core roles. 

Additional settings for recommended:

> 💡 **Recommended Settings**:
> - Global Administrator
>    - **Elevation Duration:** 2 hours
>    - **Approvals Required:** Yes
>    - **Notification:** Yes
> - Tenant-wide AAD Roles
>    - **Duration:** 4 hours
>    - **Approval Required:** No
>    - **Notification:** Yes
> - Mission-specific RBAC Contributor and Owner Roles
>    - **Duration:** 4 hours
>    - **Approval:** None
>    - **Notification:** None

Use the Azure Portal to edit the configuration for any roles to include notification and approvals as required by the organization.

### 2. Review securing privileged access in Azure AD

> **Warning**: DO NOT SKIP this exercise. This document provides invaluable information for managing Azure and Azure AD.

Familiarize yourself with the Securing Privileged Access guidance for Azure AD and build a plan for handling privileged access to the Mission Landing Zone environment.

> 📘 [Securing privileged access for hybrid and cloud deployments in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning)

</p>
</details>

## Conditional Access
Conditional Access is the main component that makes Azure AD an effective and well-informed Policy Enforcement Point (PEP) for Zero Trust access.

This section enables key recommended access policies for all apps protected by Azure AD. This includes the Azure portal, Microsoft Graph, Azure Resource Manager, M365 applications, and any future applications integrated with Azure AD.

- [⚙️ Run the script: ConditionalAccess](#⚙️-run-the-script-conditionalaccess)
  - [Azure AD Free only - turn on security defaults](#azure-ad-free---turn-on-security-defaults)
  - [Azure AD P2 - CA Policies for MLZ](#azure-ad-premium-p2---create-conditional-access-policies-for-mlz)
- [Review and enable the policies](#review-and-enable-the-policies)

<details><summary><b>Show Content</b></summary>
<p>

### ⚙️ Run the script: ConditionalAccess
Run the script below to configure Conditional Access Policies:

```PowerShell
Configure-AADTenantBaseline.ps1 -ConditionalAccess
```

The baseline script will configure CA policies in the section below: [Azure AD P2 - CA Policies for MLZ](#azure-ad-premium-p2---create-conditional-access-policies-for-mlz)

#### Azure AD Free - Turn on Security Defaults**
Azure AD Free offers a feature called Security Defaults. This feature performs basic security configuration for the Azure AD platform. Azure AD Conditional Access Policies should replace or enhance protections enabled by Security Defaults. 

> 💡**Recommendation**: Azure AD Premium customers should only enable Security Defaults as a stop-gap until CA Policies are configured and tested.

To enable security defaults, see [Enable Security Defaults](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults).

#### Azure AD Premium P2 - Create Conditional Access Policies for MLZ**
Create the Conditional Access Policies aligning to the rules in the table.

The user runnning the script, and Emergency Access Accounts group are excluded from policies.

|ID|Category|Description|Users|Applications|Controls|
|--|--------|------------|-----|------------|--------|
|MLZ001|MFA|Require multifactor authentication for all users|<ul><li>Include</li><ul><li>All Users</li></ul><li>Exclude</li><ul><li>Emergency Access Accounts</li></ul></ul>|All Apps|MFA|
|MLZ002|MFA|Block Legacy Authentication|All|Client Apps: exchangeActiveSync, other|Block|
|MLZ003|MFA|Securing security info registration|<ul><li>Include</li><ul><li>All Users</li></ul><li>Exclude</li><ul><li>Emergency Access Accounts</li></ul></ul>|UserActions: registersecurityinfo|MFA|
|MLZ004|Admins|Require phishing-resistant MFA for Azure AD admins|Directory Roles (from policy template)|All apps|Phishing-resistant MFA<br><ul><li>Fido2</li><li>WindowsHellowForBusiness</li><li>x509Certificate</li></ul>|
|MLZ005|Admins|Require phishing-resistant MFA for Azure Management|<ul><li>Include</li><ul><li>All Users</li></ul><li>Exclude</li><ul><li>Emergency Access Accounts</li></ul></ul>|Azure Management|Phishing-resistant MFA<br><ul><li>Fido2</li><li>WindowsHellowForBusiness</li><li>x509Certificate</li></ul>|
|MLZ006|Risk|Require password change for high risk users|<ul><li>Include</li><ul><li>High Risk Users</li></ul><li>Exclude</li><ul><li>Emergency Access Accounts</li></ul></ul>|All Apps|Require Password Change|
|MLZ007|Device|Require compliant device|<ul><li>Include</li><ul><li>All Users</li></ul><li>Exclude</li><ul><li>Emergency Access Accounts</li></ul></ul>|All Apps|Require multifactor authentication, Require device to be marked as compliant, Require Hybrid Azure AD joined device|

> **Note**: If Microsoft Endpoint Manager (Intune) will be deployed for the Azure AD tenant used by MLZ, enroll privileged access devices and use [Conditional Access](https://docs.microsoft.com/en-us/mem/intune/protect/create-conditional-access-intune) to require a compliant device for Azure Management.

> 📘 [Common Conditional Access Policies](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policy-common)\
> 📘 [Device-based Conditional Access with Intune](https://docs.microsoft.com/en-us/mem/intune/protect/create-conditional-access-intune)\
> 📘 [Risk-based Conditional Access Policies](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-configure-risk-policies)\
> 📘 [Require authentication strength for external users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-authentication-strength-external)

#### Review and Enable the Policies
Sign in to the Azure Portal as an administrator and review the created policies. Ensure the current administrator and break-glass accounts have been excluded from each policy before enabling it.

</p>
</details>

## Tenant Policies
This section contains basic tenant-level settings applicable to all Azure AD versions. The MLZ baseline AAD script will set these configuration items according to the defaults outlined in each section. This configuration can be changed at any time. The baseline settings represent a starting point, and may not be functional for certain scenarios. For example, tenants that will be accessed by guests from another tenant must set the External Collaboration settings accordingly. The baseline offers a most restrictive experience, which turns off these collaboration features.

- [ ] [⚙️ Run the script: TenantPolicies](#⚙️-run-the-script-tenantpolicies)
- [ ] [User Settings](#user-settings)
- [ ] [Group Settings](#group-settings)
- [ ] [External Collaboration Settings](#external-collaboration-settings)

<details><summary><b>Show Content</b></summary>
<p>

### ⚙️ Run the script: TenantPolicies
Run the script below to configure user, group, collaboration settings:

```PowerShell
Configure-AADTenantBaseline.ps1 -TenantPolicies
```
The settings applied by the baseline are outlined below.

> **Note**: Some settings are set during tenant creation and cannot be changed. All settings may not be available in Azure AD Government.

#### User settings
The MLZ AAD baseline will set the following Azure AD user settings:

|Setting|Baseline|
|-------|--------|
|Users can register applications|No|
|Restrict Access to the Azure AD Admin Portal|Yes|
|Users can use preview features for My Apps|Yes|
|Combined Security Registration|Yes (Default)|
|Administrators can access My Staff|Yes (All)|
|Allow users to connect their account to LinkedIn|No|
|Users can add gallery apps to My Apps|No|
|Users can request admin consent for apps|No|

> 📘 [Default user permissions in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions)

#### External collaboration settings
MLZ AAD baseline will set the following Azure AD external collaboration settings:
|Setting|Baseline|
|-------|------------|
|Guest user access|Most Restricted|
|Guest invitations|Most Restrictive (no one can invite)|
|Enable guest self-service|No|
|Allow external users to leave|Yes|
|Invitation restrictions|Most Restrictive|

> 📘 [B2B fundamentals](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/b2b-fundamentals)

#### Cross-Tenant Access Policy
MLZ AAD baseline will set the following inbound XTAP Settings:
|Setting|Baseline|
|-------|------------|
|Accept MFA|True|
|Accept Compliant Device|True|
|Accept Hybrid Azure AD Joined Device|True|

> 📘 [Cross-tenant access overview](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/cross-tenant-access-overview)


</p>
</details>

## Entitlements Management
Entitlements Management adds governance to access granted by Azure AD. Through Access Packages, a delegated administrator can assign eligibility and approve requests for activating entitlements.

- [ ] [⚙️ Run the script: EntitlementsManagement](#🗒️-run-the-script-entitlementsmanagement)

<details><summary><b>Show Content</b></summary>
<p>

### ⚙️ Run the script: EntitlementsManagement
Run the script below to configure user, group, collaboration settings:

```PowerShell
Configure-AADTenantBaseline.ps1 -EntitlementsManagement
```
Every organization is different, so the deployment script simply defines Access Package Catalogs for each Mission. 

> 📘 [What is entitlement management](https://learn.microsoft.com/en-us/azure/active-directory/governance/entitlement-management-overview)

</p>
</details>

# Post-Deployment
This section contains manual configuration and next steps for getting started with Azure AD for Mission Landing Zone deployments.

 - [ ] [Validate Certificate-Based Authentication](#validate-certificate-based-authentication)
 - [ ] [Verify and enable Conditional Access Policies](#verify-and-enable-the-conditional-access-policies)
 - [ ] [Assign delegate administrators for each mission](#assign-a-delegate-admin-for-the-mission)
 - [ ] [Map Azure AD security groups to Azure RBAC roles](#map-azure-ad-security-groups-to-azure-rbac-roles)
 - [ ] [Domain verification and hybrid identity](#domain-verification-and-hybrid-identity-configuration)
 - [ ] [Add a new "mission spoke"](#adding-a-new-mission-spoke)

## Validate Certificate-Based Authentication
Your Azure AD CBA configuration may differ from the baseline setup and should be validated. Make sure you set up the following:
 - upload certificates and setting CRL location for issuing and root CAs
   - upload root CA certifcates first
 - ensure root CA certificates are set with authority 0 (or root via AAD Portal UI)
 - verify the username binding
   - for cloud-only accounts, use "[certificateUserIds](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-certificateuserids)" attribute
   - for DOD customers, use "X509:<PN>" pattern to map a CAC Principal Name to an Azure AD user
 - verify the global setting for CBA is "multi-factor authentication"
   - AAD CBA is a primary authentication method and cannot be used to "step up" other authentication methods, like password.

 - uploading certificates and CRL locations for issuing and root Certification Authorities for the user smartcard certificates.
 - setting the username binding
 - configuring default multi-factor authentication level
 - configuring CA or OID based policies

Steps for setting up Azure AD CBA with the DoD PKI can be found in [AAD-CertificateBasedAuthentication-DODPKI.md](/doc/quickstart/AAD-CertificateBasedAuthentication-DODPKI.md).

> 📘 [Azure AD Native Certificate-Based Authentication](https://docs.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication)

## Verify and enable the Conditional Access Policies
The baseline script enables the **Block Legacy Authentication** Conditional Access policy only. All other policies are Report-Only mode or disabled.

> **Note**: Emergency Access accounts and the first admin user that ran the configuration script are excluded from all policies. This is to ensure you do not get locked out of the tenant.

Once admins have enrolled in a phishing-resistant authentication method, enable the recommended policies below.

> 💡 **Recommendations**: Enable the following policies as soon as possible:
> - MLZ001: MFA - Require multifactor authentication for all users (report-only by default)
> - MLZ002: MFA - Block Legacy Authentication (enabled by default)
> - MLZ003: MFA - Securing security info registration (report-only by default)
> - MLZ004: Admins - Require phishing-resistant MFA for Azure AD admins (report-only by default)
> - MLZ005: Admins - Require phishing-resistant MFA for Azure Management (report-only by default)
> - MLZ006: Risk - Require password change for high risk users (report-only by default)

## Assign delegate administrators for each mission
Delegate administrators are Mission admins with Azure AD permissions. They will not have any privileges by default, so any access should be manually assigned.

 - [ ] [Add delegates to security groups](#add-delegates-to-security-groups)
 - [ ] [Add access package catalog owners](#add-access-package-catalog-owner)
 - [ ] [Add users to application developer privileged access group](#add-users-to-application-developer-privileged-access-group)

<details><summary><b>Show Content</b></summary>
<p>

### Add delegates to security groups
So each Mission can manage their own admin users and groups, an administrator for each Mission should be added to the privileged access groups created by the configuration script for each mission.
- RBAC-GroupAdmins-MISSION
- UserAdmin-MISSION

### add Access package catalog owner
If Entitlements Management will be used, assign the delegate as owner of the Access Package Catalog created for the new mission:
1. Sign in to the Azure Portal as a Global Administrator.
2. Select **Identity Governance** from the left navigation pane.
3. Select **Catalogs** under **Entitlements Management** from the left navigation pane.
4. Select the catalog for each mission.
5. Select **Roles and administrators** and then **Add catalog owner**.
6. Assign the delegate admin for the mission.
7. Repeat steps 4-6 for each mission.

### Add users to application developer privileged access group
The Application Developers role is not scoped to an Administrative Unit. This role lets an application developer create app registrations and service principals. Assign users to the privileged access group `Application Developers MLZ-Core` so they are eligible to request this permission.

</p>
</details>

## Map Azure AD security groups to Azure RBAC Roles
The security groups created by the baseline script will not enable RBAC permissions unless they are assigned to Azure RBAC roles. [Assign roles using the Azure Portal](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal), [PowerShell](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-powershell), [Azure CLI](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-cli), or buy modifying [ARM templates](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-template) used for MLZ deployment.

For just-in-time elevation into Azure RBAC role permissions, assign RBAC roles to the security groups using [Privileged Identity Managegment](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-assign-roles).

## Domain verification and hybrid identity configuration
This section is not applicable for Azure Platform tenants ([Type 2](/MLZ-Identity-AzureADSetup/doc/MLZ-Common-Patterns.md#type-2-mlz-deployed-to-standalone-azure-platform-tenant)).

 - [ ] [Add a custom domain](#add-a-custom-domain-to-azure-ad)
 - [ ] [Evaluate hybrid identity options](#evaluate-hybrid-identity-options)
 - [ ] [Synchronization](#synchronization)
 - [ ] [Authentication](#authentication)

<details><summary><b>Show Content</b></summary>
<p>

### Add a custom domain to Azure AD
When an Azure AD tenant is created, a default domain is assigned that looks like *tenantname.onmicrosoft.com* (*tenantname.onmicrosoft.us* for Azure AD Government). By default, all users in Azure AD get a UserPrincipalName (UPN) with the default domain suffix.

[Custom domains](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-custom-domain) let tenant administrators use an organization's DNS domain for username suffixes, mail routing, etc.

1. Create a custom domain using the Microsoft Portal or MS Graph PowerShell:

```PowerShell
Import-Module Microsoft.Graph.Identity.DirectoryManagement
$params = @{
	Id = "contoso.com"
}
New-MgDomain -BodyParameter $params
```
2. From the Azure Portal, navigate to **Azure Active Directory**.
3. Choose **Custom Domain Names** from the left navigation pane.
4. Select the custom domain name created for your organization.
5. The verification DNS record will be displayed.
6. Add this record to your organization's public DNS zone.
7. Click **verify** to complete adding the custom domain.

Now you can create users with the custom domain as the UPN suffix. Existing cloud-only (managed) users can be modified to use the custom domain suffix.

> **Note**:
Sometimes when custom domains are added to an Azure AD tenant, users who signed up for trial Microsoft services with their organization email address will appear in the tenant once the domain is verified. Do not be alarmed by this. To verify no other users have privileges within the tenant, [view the Azure AD role members](https://docs.microsoft.com/en-us/azure/active-directory/roles/view-assignments).

### Evaluate hybrid identity options
Microsoft’s identity solutions span on-premises and cloud-based capabilities. These solutions create a common user identity for authentication and authorization to all resources. This configuration has 2 parts:
- [ ] [Synchronization](#synchronization)
- [ ] [Authentication](#authentication)

> 📘 [What is hybrid identity with Azure AD?](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-hybrid-identity)

### Synchronization
Hybrid identity should be configured if an organization uses Active Directory Domain Services and wishes to synchronize users and groups to Azure AD. Microsoft offers 2 tools (named very similarly) to accomolish this function:
- [Azure AD Connect](#azure-ad-connect-v2)
- [Azure AD Connect Cloud Sync](#azure-ad-connect-cloud-sync)

Which tool you should use varies depending on the hybrid identity needs for the environment. Use Cloud Sync for simple scenarios if it supports the features your organization needs. For a full breakdown of feature support between the tools, see [Comparison between Azure AD Conect and Cloud Sync](https://docs.microsoft.com/en-us/azure/active-directory/cloud-sync/what-is-cloud-sync#comparison-between-azure-ad-connect-and-cloud-sync).

> **Note**: Synchronizing all identities to Azure AD helps establish an enterprise identity and zero trust surface for all applications. If hybrid identity is already configured for a different tenant, treat that tenant as the enterprise Azure AD for the organization. Review the tenant types.

#### Azure AD Connect v2
[Azure AD Connect Synchronization Service v2](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-azure-ad-connect-v2) is the latest version of Microsoft's on-premises infrastructure based synchronization tool. 

Use Azure AD Connect Sync if:
- You want to synchronize identites from Active Directory Domain Services or a generic LDAP database to Azure AD
- You need to configure a hybrid authentication option other than Password Hash Sync
- You need to synchronize device objects for Hybrid Azure AD Join
- You need to configure Exchange hybrid or group writeback
- You need to synchronize extension attributes
- You need to synchronize large groups with > 250,000 members
- You have over 150,000 objects to synchronize
- You wish to leverage Azure AD Domain Serices (only applicable when used with password hash synchronization)

> 📘 [Choose the right authentication method for your Azure AD hybrid identity solution](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/choose-ad-authn)

#### Azure AD Connect Cloud Sync
[Azure AD Connect Cloud Sync](https://docs.microsoft.com/en-us/azure/active-directory/cloud-sync/what-is-cloud-sync) is an agent-based synchronization tool managed in Azure AD. This tool is expected to replace Azure AD Connect sync for most scenarios.

Use Azure AD Connect Cloud Sync if:
- You want to synchronize identities from Active Directory Domain Services to Azure AD
- You are configuring Password Hash Sync or cloud-native Azure AD authentication with security keys, authenticator app, or certificates.
- You will be joining devices directly to Azure AD and do not need hybrid join functionality
- You do not need to synchronize extension attributes
- You do not need to filter using attribute values (Organizational Unit filtering only)
- You do not need complex or custom attribute synchronization logic

#### Exclude sync account from multi-factor authentication
Once a synchronization tool is configured, you should see initial synchronization fails due to single-factor authentication. Ensure this account is excluded from any MFA requirements set by Conditional Access policy. See [user exclusions](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa#user-exclusions).

### Authentication
Hybrid identity configuration can include [Password Hash Synchronization (PHS)](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-phs) where passwords are replicated from Active Directory to Azure AD. This is only applicable for AD environments where users have and use a password. If users access AD-protected resources with a smartcard (CAC/PIV), there is no need to set up password hash sync.

Pass-Through Authentication (PTA) and federation with ADFS are not recommended. Hybrid authentication is less secure than Azure AD native methods, as the on-premises environment represents a significant identity attack surface.

> 💡 **Recommendation**: Use Azure AD native strong authentication method, like FIDO2 security keys or native certificate-based authentication, for administration of Azure and Azure AD.

</p>
</details>

## Adding a new "mission spoke"
When subscriptions are added for new Missions after initial deployment, the configuration script can be re-run using the parameter switches to skip some of the configuration steps.

- [ ] [Choose a Mission name](#choose-a-mission-name)
- [ ] [Prepare the `mlz-aad-parameters.json` file](#prepare-the-mlz-aad-parametersjson-file)
- [ ] [Prepare the `MLZ-Admin-List.csv` for the new Mission AU users](#prepare-the-mlz-admin-listcsv)
- [ ] [Re-Run the script](#re-run-the-script)

<details><summary><b>Show Content</b></summary>
<p>

### Choose a Mission name
Choose a single word to describe the mission. This value needs to be unique in Mission AUs list.

### Prepare the mlz-aad-parameters.json file
Add the new mission to `GlobalParameterSet.MissionAUs` array. If the current value is `"MissionAUs": ["Alpha","Bravo","Charlie"]`, append a new mission, Delta, to the array: `"MissionAUs": ["Alpha","Bravo","Charlie","Delta"]`

The script will skip creating Administrative Units that already exist in the environment.

### Prepare the MLZ-Admin-List.csv
Repeat the steps for [Creating a named admin list CSV file](#🗒️-create-named-admin-list-csv-file) to include the new users. 

### Re-run the script
The only parameters needed are:
- AdminUnits
- NamedAccounts
- Groups
- PIM
- EntitlementsManagement

Run the script the following sections of the configuration scipt:

```PowerShell
Configure-AADTenantBaseline.ps1 -AdminUnits -NamedAccounts -Groups -PIM -EntitlementsManagement
```

### Assign a delegate admin for the Mission
Add the new delegate admin to the groups created by the script:
- RBAC-GroupAdmins-Delta
- UserAdmin-Delta

If Entitlements Management will be used, assign the delegate as owner of the Access Package Catalog created for the new mission.

</p>
</details>

## Plan for Zero Trust
The Microsoft cloud includes a vast array of tools and security capabilities that enable advanced zero trust outcomes. These capabilities are enhanced by cross-product integration and additional datapoints.

The more Azure AD knows about the context of a user's access, the better it's access control capabilities become. The AI models powering risk-based conditional access with Azure AD Identity Protection, Sentinel User Entity Behavior Analytics, and Insider Risk, are just a few capabilties that get even better with more data.

Make Azure AD Conditional Access a well-informed Policy Enforcement Point (PEP) by integrating signals across identities, endpoints, applications, data, infrastructure, networks, and risk.

Continue to [Zero Trust with Azure AD](/doc/zt/AAD-ZT-Quickstart.md) to get started, and check out the official Microsoft references below.

> 📘 [Zero Trust Rapid Modernization Plan](https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-ramp-overview)\
> 📘 [Zero Trust Resource Center](https://learn.microsoft.com/en-us/security/zero-trust/)

## See Also
### MLZ Identity Add-On
- [Common Deployment Patterns](./MLZ-Common-Patterns.md)
- [Identity for MLZ Applications](./MLZ-Application-Identity.md)
- [Permissions for MLZ](./AAD-Permissions-Management.md)
- [CBA Configuration for DOD PKI](./AAD-CertificateBasedAuthentication-DODPKI.md)
- [MLZ Identity FAQ](./MLZ-AAD-FAQ.md)
- [MLZ Identity Add-On Home](./../README.md)

### Azure AD Deployment Guides
- [Azure Active Directory deployment plans](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-deployment-plans)
- [Azure Security Operations Guide](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)
- [Security Baseline for Azure AD](https://docs.microsoft.com/en-us/security/benchmark/azure/baselines/aad-security-baseline)
- [Protect M365 from On-Premises Attacks](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/protect-m365-from-on-premises-attacks)
- [Secure External Access with Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/secure-external-access-resources)
- [Secure Service Accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-introduction-azure)
- [Best Practices for Azure AD Roles](https://docs.microsoft.com/en-us/azure/active-directory/roles/best-practices)
- [Role Security Planning](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning)
- [Achieving NIST AALs](https://docs.microsoft.com/en-us/azure/active-directory/standards/nist-overview)
- [Meeting M-22-09 with Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/standards/memo-22-09-meet-identity-requirements)