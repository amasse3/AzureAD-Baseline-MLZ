# Azure Active Directory Baseline Configuration for MLZ
This document provides key steps for deploying and securing a new Azure Active Directory environments for Mission Landing Zone deployments using a settings file and Microsoft Graph PowerShell to apply the settings.

While the configuration was created for MLZ, sections of the script can be used for existing tenants or to test automated configuration in a non-production tenant. At minimum, the general approach to configuring the latest Azure AD features can be applied through a fully customized automated deployment using this configuration as a sample.

It is **not** recommended to run through the configuration end-to-end in existing production tenants as the setting changes could disrupt access to the Azure environment.

## Table of Contents
- [About the baseline configuration](#about-the-baseline-configuration)
    - [Documentation layout](#documentation-layout)
    - [Asset inventory](#asset-inventory)
    - [Requirements](#requirements)
- [Prepare to manage Azure AD](#prepare-to-manage-azure-ad)
- [Scripted Configuration](#scripted-configuration)
  - [Administrative Units](#administrative-units)
  - [Emergency Access](#emergency-access)
  - [Named Accounts](#named-accounts)
  - [Authentication Methods](#authentication-methods)
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
- [Zero Trust with Azure AD](#zero-trust-with-azure-ad)
  - [Connect applications to Azure AD](#connect-applications-to-azure-ad)
  - [Use strong cloud-native authentication methods](#use-strong-authentication-methods)
  - [Collaborate with Azure AD](#cross-tenant-access-policies-xtap-and-b2b-cross-cloud-collaboration)
  - [Bring Device signals to Azure AD](#bring-device-signals-to-azure-ad)
  - [Enable Defender for Cloud](#enable-defender-for-cloud)
  - [Use Microsoft Sentinel](#use-microsoft-sentinel)
  - [Least privilege with Azure AD](#least-privilege-with-azure-ad)
- [Plan for Zero Trust](#plan-for-zero-trust)
- [See Also](#see-also)
  - [MLZ Identity Add-On](#mlz-identity-add-on)
  - [Azure AD Deployment Guides](#azure-ad-deployment-guides)

## About the baseline configuration
The Azure AD tenant baseline for MLZ is applied using a parameters file supplied as a parameter to [Configure-AADTenantBaseline.ps1](/src/Configure-AADTenantBaseline.ps1) script.

The script itself includes some features to simplify the deployment including:
- Parameter switches for running individual sections
- Loading modules and connecting to MS Graph with required scope within each section
- Checking for existing resources before creating duplicates
- Parameters file where individual settings can be adjusted
- Load the default parameters file from the relative path if no ParametersJSON argument is passed

### Documentation layout
Each section in [Scripted Configuration](#scripted-configuration) is broken down by the parameter switch for the configuration script. Generally, each section follows this format:
- Brief overview of the configuration section
- Table of contents
- Configuration Steps
- Related recommendations and references

🗒️Modify Configuration: Steps for manually editing parameter or configuration files use 🗒️.

⚙️ Run the script: Steps for running the configuration step use Steps use ⚙️.

To simplify navigation, detailed content for each section is hidden by default. Use the **Show Content** buttons to display this information.
<details><summary><b>Show Content</b></summary>
<p>
Wow! That's a lot of content!
</p>
</details>

> **Note** : Notes will look like this

> 💡**Recommendations**: will include the light bulb emoji

> **Warning**: Priority notes, including ones with security implication, will be displayed like this.

> 📘 **References**: References will use the blue book emoji

Checklist format is used to draw attention to required steps.
- [ ] Do this first
- [ ] Then this

To get started, continue to the [requirements](#requirements) section.

### Asset Inventory
|Asset|Description|Format|Location|
|-----|-----------|------|--------|
|This Document|Deployment aid for scripted configuration, manual configuration, and next steps.|Text (Markdown)|N/A|
|mlz-aad-parameters.json|Script parameters|JSON|[mlz-aad-parameters.json](/src/mlz-aad-parameters.json)|
|MLZ-Admin-List.csv|File for automating account creation for named administrators.|CSV|[MLZ-Admin-List.csv](/src/MLZ-Admin-List.csv)|
|Configure-AADTenantBaseline.ps1|Main deployment script|PowerShell (\*.ps1)|[Configure-AADTenantBaseline.ps1](/src/Configure-AADTenantBaseline.ps1)|

#### MLZ-AAD-Parameters.json
This file represents the configuration that will be applied when running the baseline. The JSON-formatting parameters file can be found [here](/src/mlz-aad-parameters.json).

At minimum, modify the **GlobalParameterSet** to match the environment before running the script.

The **mlz-aad-parameters.json** file must be read into a variable and passed to the `ParametersJson` parameter of the **Configure-AADTenantBaseline.ps1** script. 

|Parameter|Description|DefaultValue|
|---------|-----------|------------|
|Environment|Azure Environment for Microsoft Graph PowerShell. Values should match "Global","USGov", or "USGovDOD"|Global|
|EAGroupName|Name of the group containing Emergency Access accounts. Used to exclude these accounts from Conditional Access policies.|Emergency Access Accounts|
|PWDLength|Length of random passwords set by the deployment script.|16|
|MissionAUs|Array of names for Administrative Units. Applicable if using delegated administration model.|[Alpha,Bravo,Charlie]|
|LicenseSKUPartNumber|License SKU for AAD P2 / E5 <br>Find using get-mgsubscribedsku|E5 Developer GUID<br><b>must be changed\*</b>|

\*To find the LicenseSKUPartNumber, use MS Graph to check the first licensed user:

```PowerShell
Get-MgUserLicenseDetail -UserId $(Get-MgContext).Account | Format-List
```
#### Using the script
The script will look for `mlz-aad-parameters.json` in the current path. If you renamed the file or want to load it from a different path, import it into the PowerShell session and supply using the command below:

```PowerShell
$mlzparms = $(get-content mlz-aad-parameters.json) | convertFrom-Json
```
**All Baseline Configurations**
To apply all configuration sections in the baseline, use the `-All` switch along with the parameters.

```PowerShell
.\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparams -All

```
> **Note** : Before applying a setting, the script will check if the settings / objects already exist.

**Apply individual configurations**
To apply individual sections, include one or more switch parameter.

```PowerShell
.\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparams -EmergencyAccess -AuthNMethods -ConditionalAccess -TenantPolicies
```

### Requirements
- [ ] New or existing (non-production) Azure Active Directory tenant
- [ ] Azure AD account with Global Administrator role
- [ ] Azure AD Premium P2 licenses*
- [ ] A trusted configuration workstation with
    - rights to install PowerShell module for MS Graph
    - DNS resolution and traffic routing for the Azure AD logon URLs
    - CDN and logon URLs in trusted sites
- [ ] Microsoft Graph PowerShell

> **Note**: \* If Azure AD Premium licenses are not available, only the following settings can be applied:
> - EmergencyAccess (assigning Global Admin via PIM will fail, add the role assignment manually)
> - AuthNMethods
> - NamedAccounts (licensing step will fail)
> - TenantPolicies
>
> If Azure AD Premium is not available, Conditional Access Policies cannot be used. [Turn on Security Defaults](https://learn.microsoft.com/en-us/microsoft-365/business-premium/m365bp-conditional-access?view=o365-worldwide#security-defaults) and follow guidance to [Protect your admin accounts](https://learn.microsoft.com/en-us/microsoft-365/business-premium/m365bp-protect-admin-accounts?view=o365-worldwide).

> 📘 **Reference**: [Office 365 IP Address and URL web service](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service?view=o365-worldwide)

# Prepare to manage Azure AD
This section outlines the preliminary activities for configuring a new Azure AD tenant for MLZ.

## Preparation Checklist
- [ ] [1. Review the MLZ Deployment Patterns](#1-review-the-mlz-deployment-patterns)
- [ ] [2. Prepare a secure workstation for managing Azure AD](#2-prepare-a-secure-workstation-for-managing-azure-ad)
- [ ] [3. ⚙️ Run the script: PSTools](#3-⚙️-run-the-script-pstools)
- [ ] [4. Connect to Azure AD with MS Graph PowerShell](#4-connect-to-azure-ad-with-microsoft-graph-powershell)
- [ ] [5. Bookmark useful URLs](#5-bookmark-useful-urls)
- [ ] [6. Create and the first Global Administrator](#6-create-the-first-global-administrator)
- [ ] [7. License the first global administrator](#7-license-the-first-global-administrator)
- [ ] [8. Activate Privileged Identity Management](#8-activate-privileged-identity-management)

<details><summary><b>Show Content</b></summary>
<p>

### 1. Review the MLZ Deployment Patterns
Review the [MLZ Deployment Patterns](./MLZ-Common-Patterns.md#decision-tree) and determine which type will be used for the MLZ tenant.

> **Warning**: The baseline configuration script should not be run in existing production Azure AD tenants, especially if M365 services are used. Settings applied in the baseline script may disrupt functionality and result in outage for end users.

### 2. Prepare a secure workstation for managing Azure AD
There are several client tools for managing Azure AD configuration. Make sure you are managing Azure and Azure AD from a secure workstation. Ensure these privileged access devices include the Azure management tools outlined in this section. 

> 📘 **Reference**: [Privileged Access Devices](https://docs.microsoft.com/en-us/security/compass/privileged-access-devices)

### 3. ⚙️ Run the script: PSTools
Install the PowerShell modules by running:
```PowerShell
Configure-AADTenantBaseline.ps1 -PSTools`
```
The script will:
1. Install MS Graph PowerShell
2. Install Azure AD Preview (deprecated - included temporarily since it is used to configure CBA in the [Microsoft documentation](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#configure-certification-authorities-using-powershell))

#### Manual module installation
Use the commands below to install the tools manually. MLZ deployment will use additional tools listed here for convenience:
- [Azure Command-Line-Interface (CLI)](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [Azure Az PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps?view=azps-9.0.1)
  - `Install-Module Az`
- [Microsoft Graph PowerShell](https://docs.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)
  - `Install-Module Microsoft.Graph`
- [Azure AD PowerShell v2](https://learn.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0)
  - `Install-Module AzureADPreview`

#### Upgrading Microsoft.Graph.PowerShell
The Graph API and PowerShell modules are constantly updated to introduce new features. [Update](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0#updating-the-sdk) to the latest version:

```PowerShell
Update-Module Microsoft.Graph
```
### 4. Connect to Azure AD with Microsoft Graph PowerShell
Now we will ensure we can connect using MS Graph PowerShell. 

1. Open PowerShell and run the following command to connect to Azure AD:
- Azure AD Commercial
  - `Connect-MgGraph`
- Azure AD Government
  - `Connect-MgGraph -Environment UsGov`
- Azure AD Government - DoD
  - `Connect-MgGraph -Environment UsGovDoD`
2. Sign in with the first administrator account.
 
Verify you are connected to the correct tenant by running:
```PowerShell
Get-MgContext
```
### 5. Bookmark useful URLs
Bookmark the following portal pages in your web browser for easy access:
 - Entra Admin Center
   - Global: **https://entra.microsoft.com**
   - Government: **https://entra.microsoft.us**
 - Azure Portal
   - Global: **https://portal.azure.com**
   - Government: **https://portal.azure.us**

 - Microsoft Graph:
   - [Getting Started with Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/get-started?view=graph-powershell-beta)
   - [Microsoft Graph API Reference](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-beta)

### 6. Create the first Global Administrator
The first user in an Azure AD tenant will have super user / root access to the Azure AD tenant. This superuser permissions are assigned via the [Global Administrator](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator) built-in role.

In some cases the first user in Azure AD is a guest / external user. This can be verified by navigating to the Users blade in the Azure AD Portal and investigating the **User Type** field. 

If the signed in account is not a **member** type, follow the steps below to create a new "first user" in the Azure AD tenant:
1. [Add a new user in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-users-azure-active-directory#add-a-new-user)
   1. Record the username, including the domain suffix
   2. Note the temporary password
2. [Assign Global Administrator role to the new user](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal)
3. Set Usage location value to **United States**. This is required for licensing.
4. Sign out of the portal or click the profile in the top right and select **sign in with a different account**
5. Enter the username and temporary password for the first member administrator account.
6. Change the password to a [strong password value](https://www.nist.gov/video/password-guidance-nist-0)
7. Register security information when prompted. This will secure the administrator account and provide a means for resetting the password.

> 📘 **Reference**: [Azure AD Setup Guide](https://go.microsoft.com/fwlink/p/?linkid=2183427)
### 7. License the first Global Administrator
1. Log in to the Azure Portal (https://portal.azure.com | https://portal.azure.us) as the first Global Administrator
2. Search for **Azure Active Directory** and click the Azure AD icon to open the AAD Administration "blade" in the Azure Portal.
3. Click **Licenses** and then **All Products**
4. Make sure you see the expected licenses.
5. Assign the first administrator an Azure AD Premium license.

> 📘 **Reference**: [Assign or remove licenses in the Azure AD Portal](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/license-users-groups?)

### 8. Activate Privileged Identity Management
While signed in to the Azure AD portal with the first administrator, perform the following:
1. Search for **Azure AD Privileged Identity Management**
2. Select **Azure AD Roles**
3. Follow the prompts to enable PIM on the tenant.

If you already have subscriptions associated with the tenant, follow the steps in the reference below to prepare PIM for Azure roles.

> 📘 **Reference**: [Prepare PIM for Azure roles](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-getting-started#prepare-pim-for-azure-roles)

We are now ready to apply the scripted configuration.
</p>
</details>

# Scripted Configuration
This section walks through the scripted configuration using `Configure-AADTenantBaseline.ps1`.

The document layout matches each section in the PowerShell script.
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

> 📘 **Reference:** [Administrative units in Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/roles/administrative-units)

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

> 📘 **Reference**: [Manage Emergency Access Accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

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
Configure-AADTenantBaseline.ps1 -EmergencyAccess`
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

> 📘 **Reference:** [Manage emergency access accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

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
Configure-AADTenantBaseline.ps1 -NamedAccounts`
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

> 📘 **Reference**: 
> - [Authentication methods in Azure AD](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods)
> - [Phishing-resistant methods](https://docs.microsoft.com/en-us/azure/active-directory/standards/memo-22-09-multi-factor-authentication#phishing-resistant-methods)

#### Distribute accounts for administrators
Complete setup for the named administrator accounts:
1. Manually reset the password from each administrator.
2. Provide the password to the admin.
3. Instruct the admin to change password and [register security info](https://support.microsoft.com/en-us/account-billing/set-up-the-microsoft-authenticator-app-as-your-verification-method-33452159-6af9-438f-8f82-63ce94cf3d29) by setting Microsoft Authenticator App as a verification method.

> 📘 **Reference**: 
> - [Reset a user's password using Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-users-reset-password-azure-portal)
> - [Assign licenses to users by group membership in Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-groups-assign)

</p>
</details>

## Authentication Methods
Azure AD authenticaton methods allow an administrator to configure how users can authenticate to Azure AD.

- [ ] [⚙️ Run the script: AuthNMethods](#⚙️-run-the-script-authnmethods)

> 📘 **Reference**: [What authentication verification methods are available in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods)

<details><summary><b>Show Content</b></summary>
<p>

### ⚙️ Run the script: AuthNMethods
Run the script to configure authentication methods:

```PowerShell
Configure-AADTenantBaseline.ps1 -AuthNMethods`
```
The sections below describe the methods enabled. Additionally, weak methods like Software OAuth, SMS, and Email will be disabled.

#### Enable Microsoft authenticator app
The Microsoft Authenticator app for iOS and Android lets users authenticate / complete MFA challenges when Azure AD configuration (Conditional Access or Security Defaults) needs an additional factor. The Microsoft Authenticator app can be used in the following ways:
- Passwordless Phone Sign-in
- Notification
- Time-based One Time Password (TOTP) code

> 📘 **Reference**: [Microsoft Authenticator app](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-authenticator-app)

#### Enable FIDO2 security keys
FIDO2 security keys are an unphishable standards-based passwordless authentication method that come in different form factors. Most security keys resemble a USB thumb drive and communicate with device over USB.

> 📘 **Reference**: [Enable FIDO2 security keys](https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-passwordless-security-key)

#### Enable Certificate-Based authentication
Certificate-Based Authentication allows users to authenticate against Azure AD with a smartcard certificate. When enabled by the baseline scripts, x509Certificate authentication method is set to default as multifactor authentication. 

Bindings are set for certificateUserIds and onPremisesUserPrincipalName. The next section provides additional guidance for setting up CBA Authentication Method.
> 📘 **Reference**: [Azure AD Native Certificate-Based Authentication](https://docs.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication)

### 2. Disable weaker authentication methods
The deployment script will attempt to disable the following Authentication Methods:
- Temporary Access Pass
- Email
- SoftwareOath
- Sms

Sign in to the Azure Portal and verify these Authentication methods are not enabled by navigating to Azure Active Directory --> Security --> Authentication Methods.

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
Configure-AADTenantBaseline.ps1 -Groups`
```

The script will:
1. Create Security Groups for MLZ-Core and each Mission
2. Create Privileged Access Groups for User and Groups Administrator roles for each Administrative Unit

> 📘 **Reference**:
> - [Use Azure AD groups to manage role assignments](https://learn.microsoft.com/en-us/azure/active-directory/roles/groups-concept)
> - [Best Practices for Azure AD roles](https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices)
> - [Securing privileged access for hybrid and cloud deployments of Azure AD](https://learn.microsoft.com/en-us/azure/active-directory/roles/security-planning)
> - [Azure role-based access control](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/considerations/roles)

## Privileged Identity Management
Priviliged Access Management (PIM) is an Azure AD feature for providing Just-In-Time administration and eliminating standing privileges within Azure AD and Azure.

We enabled PIM when we signed in with the first AADP2-licensed Global Administrator in the [Prepare to manage Azure AD](#prepare-to-manage-azure-ad) steps.

This section assigns the groups created in the [previous section](#3-🗒️-run-the-script-groups) to Azure and AAD roles using PIM:

- [ ] [⚙️ Run the script: PIM](#1-⚙️-run-the-script-pim)
- [ ] [Review Securing Privileged Access in Azure AD](#2-review-securing-privileged-access-in-azure-ad)

### 1. ⚙️ Run the script: PIM
Run the script below to configure PIM:

```PowerShell
Configure-AADTenantBaseline.ps1 -PIM`
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

> 📘 **Reference**: [Securing privileged access for hybrid and cloud deployments in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning)

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
Configure-AADTenantBaseline.ps1 -ConditionalAccess`
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

> 📘 **Reference**:
> - [Common Conditional Access Policies](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policy-common)
> - [Device-based Conditional Access with Intune](https://docs.microsoft.com/en-us/mem/intune/protect/create-conditional-access-intune)
> - [Risk-based Conditional Access Policies](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-configure-risk-policies)
> - [Require authentication strength for external users](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-authentication-strength-external)

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
Configure-AADTenantBaseline.ps1 -TenantPolicies`
```
The settings applied by the baseline are outlined below.

> **Note**: Some settings are set during tenant creation and cannot be changed. All settings may not be available in Azure AD Government.

#### User settings
The MLZ AAD baseline will set the following Azure AD user settings:

|Setting|MLZ-Baseline|
|-------|--------|
|Users can register applications|No|
|Restrict Access to the Azure AD Admin Portal|Yes|
|Users can use preview features for My Apps|Yes|
|Combined Security Registration|Yes (Default)|
|Administrators can access My Staff|Yes (All)|
|Allow users to connect their account to LinkedIn|No|
|Users can add gallery apps to My Apps|No|
|Users can request admin consent for apps|No|

> 📘 **Reference**: [Default user permissions in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions)

#### External collaboration settings
MLZ AAD baseline will set the following Azure AD external collaboration settings:
|Setting|MLZ-Baseline|
|-------|------------|
|Guest user access|Most Restricted|
|Guest invitations|Most Restrictive (no one can invite)|
|Enable guest self-service|No|
|Allow external users to leave|Yes|
|Invitation restrictions|Most Restrictive|

> 📘 **Reference**: [B2B fundamentals](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/b2b-fundamentals)

#### Cross-Tenant Access Policy
MLZ AAD baseline will set the following inbound XTAP Settings:
|Setting|MLZ-Baseline|
|-------|------------|
|Accept MFA|True|
|Accept Compliant Device|True|
|Accept Hybrid Azure AD Joined Device|True|

> 📘 **Reference**: [Cross-tenant access overview](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/cross-tenant-access-overview)


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
Configure-AADTenantBaseline.ps1 -EntitlementsManagement`
```
Every organization is different, so the deployment script simply defines Access Package Catalogs for each Mission. 

> 📘 **Reference**: [What is entitlement management](https://learn.microsoft.com/en-us/azure/active-directory/governance/entitlement-management-overview)

</p>
</details>

# Post-Deployment
This section contains manual configuration and next steps for getting started with Azure AD for Mission Landing Zone deployments.

## Configure Certificate-Based Authentication
The Azure AD Certificate-Based Authentication feature requires additional configuration:

 - uploading certificates and CRL locations for issuing and root Certification Authorities for the user smartcard certificates.
 - setting the username binding
 - configuring default multi-factor authentication level
 - configuring CA or OID based policies

Steps for setting up Azure AD CBA with the DoD PKI can be found in [AAD-CertificateBasedAuthentication-DODPKI.md](/MLZ-Identity-AzureADSetup/doc/AAD-CertificateBasedAuthentication-DODPKI.md).

> 📘 **Reference**: [Azure AD Native Certificate-Based Authentication](https://docs.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication)

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

> 📘 **Reference**: [What is hybrid identity with Azure AD?](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-hybrid-identity)

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

> 📘 **Reference**: (Choose the right authentication method for your Azure AD hybrid identity solution)[https://docs.microsoft.com/en-us/azure/active-directory/hybrid/choose-ad-authn]

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

# Zero Trust with Azure AD
One of the first steps an organization can take in adopting zero trust principals is consolidating around a single cloud-based Identity as a Service (IdaaS) platform like Azure Active Directory. This section describes some next steps after establishing the tenant.

- [ ] [Connect applications to Azure AD](#connect-applications-to-azure-ad)
- [ ] [Use strong cloud-native authentication methods](#use-strong-authentication-methods)
- [ ] [Collaborate with Azure AD](#cross-tenant-access-policies-xtap-and-b2b-cross-cloud-collaboration)
- [ ] [Bring Device signals to Azure AD](#bring-device-signals-to-azure-ad)
- [ ] [Enable Defender for Cloud](#enable-defender-for-cloud)
- [ ] [Use Microsoft Sentinel](#use-microsoft-sentinel)
- [ ] [Least privilege with Azure AD](#least-privilege-with-azure-ad)

<details><summary><b>Show Content</b></summary>
<p>

## Connect applications to Azure AD
This section describes steps to integrate applications with Azure AD.

- [ ] [Review Identity for MLZ Applications](#review-mlz-application-identity)
- [ ] [Consolidate around an Azure AD tenant](#consolidate-around-an-azure-ad-tenant)
- [ ] [Add Enterprise Applications to Azure AD](#add-enterprise-applications-to-azure-ad)
- [ ] [Develop New Applications for Azure AD](#develop-new-applications-for-azure-ad)
- [ ] [Add On-Premises Applications to Azure AD](#add-on-premises-applications-to-azure-ad)
- [ ] [Protect APIs with Azure AD](#protect-apis-with-azure-ad)
- [ ] [Use Defender for Cloud Apps](#use-defender-for-cloud-apps)

### 📘 Review MLZ-Application-Identity
Detailed guidance around identity for MLZ applications can be found in the referenced document below.

> 📘  **Reference**: [Identity for MLZ Applications](./MLZ-Application-Identity.md)

### Consolidate around an Azure AD tenant
Standardizing around a common identity platform often requires changes to IT policy mandating new applications (procured and developed in house) targets Azure Active Directory. The Azure AD tenant containing all users in the organization, especially if it is used for M365, is a good choice because the same zero trust access and device management policies for M365 can be re-used for any application in the organization.

> 💡 **Recommendation**: 
> - Zero Trust policies for application identity should be drafted and implemented as soon as Azure Active Directory is ready.
> - Applications should be migrated from on-premises based federation services like Active Directory Federation Services.
> - Integrate as many signals as possible (device, user, application, context, authentication strength, risk) into Azure AD Conditional Access.

> 📘 **Reference**: 
> - [Planning identity for Azure Government applications](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-plan-identity)
> - [Microsoft Zero Trust Resources](https://www.microsoft.com/en-us/security/business/zero-trust)

#### Add Enterprise Applications to Azure AD
Enterprise Apps are application resources assigned to users in your Azure Active Directory. Add applications from the Azure AD Gallery or add non-gallery apps that use SAML, WS-Federation, OpenID Connect, or OAuth protocols.

> 📘 **Reference**: [Overview of the Azure Active Directory application gallery](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/overview-application-gallery)

#### Develop new applications for Azure AD
Develop new applications and APIs to use Azure AD for authentication and authorization.

> 📘 **Reference**:
>   - [Microsoft Authentication Library (MSAL)](https://learn.microsoft.com/en-us/azure/active-directory/develop/msal-overview)
>   - [Security best practices for application properties in Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/develop/security-best-practices-for-app-registration)
>   - [Microsoft Identity Platform code samples](https://learn.microsoft.com/en-us/azure/active-directory/develop/sample-v2-code)

### Add on-premises applications to Azure AD
Azure AD Application Proxy is an on-premises agent and cloud service that [securely publishes](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-security) on-premises applications that use [Kerberos-based](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-configure-single-sign-on-with-kcd), [password-based](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-configure-single-sign-on-password-vaulting), [SAML](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-configure-single-sign-on-on-premises-apps), and [header-based](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-configure-single-sign-on-with-headers) authentication protocols. This feature allows organizations to gain [single sign-on](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-config-sso-how-to) and zero trust security controls for existing applications, without expensive network appliances or VPNs. Remote access to on-premises applications is achieved without code change to applications or opening inbound ports for the external firewall.

> 💡 **Recommendation**:
> - [Deploy Azure AD Application Proxy connectors](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-deployment-plan) to every Active Directory domain containing users or applications that must be published externally. 
> - If a [Secure Hybrid Access Partner](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/secure-hybrid-access#secure-hybrid-access-through-azure-ad-partner-integrations) solution is already in use for the organization, integrate the solution with Azure Active Directory.

> 📘 **Reference**:
> - [Remote access to on-premises applications through Azure AD Application Proxy](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy)
> - [Optimize traffic flow with Azure Active Directory Application Proxy](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-network-topology)
> - [Security Benefits for Azure AD Application Proxy](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/what-is-application-proxy#security-benefits)
> - [Secure Hybrid Access Partner Integrations](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/secure-hybrid-access#secure-hybrid-access-through-azure-ad-partner-integrations)

### Protect APIs with Azure AD

Placeholder APIM

### Use Defender for Cloud Apps

Placeholder

## Use strong authentication methods
Authentication Strengths is a feature that allows a tenant administrator to label authenticators (and combinations) according to the strength of the credential. Out-of-Box settings include:
- Multifactor Authentication
- Passwordless Multifactor Authentication
- Phishing-Resistant MFA

Additional strengths, like NIST Authenticator Assurance Levels, can be configured by an administrator.

> 📘 **Reference**: Configure Authentication Strength](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-strengths)

> 💡 **Recommendation**: Configure desired MFA strength for baseline access and update the 'All Users, All Apps, MFA' Conditional Access Policy to require Authentication Strength.

## Collaborate with Azure AD
Azure AD makes it easy to collaborate with other organizations the also own Azure AD. This collaboration is facilitated by two complementary features:
- [External Identities (B2B)](#external-identities)
- [Cross-Tenant Access Policies](#cross-tenant-access-policies)

### External Identities
Azure AD B2B collaboration is a feature within External Identities that lets you invite guest users with an email invitation. Guest users use their existing account to sign-in to their home tenant, while you manage their access to your resources.
- The partner users their own identities and credentials
- you don't need to manage external accounts or passwords
- you don't need to sync or manage account lifecycle

> 📘 **Reference**: [Azure AD B2B Collaboration](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/what-is-b2b)

### Cross-Tenant Access Policies
Cross-tenant access policies (XTAP) let an administrator configure "trust" relationships with other Azure AD tenants. This allows trusting device compliance and MFA claims for external users for a more secure and productive collaboration experience. Similar settings can be configured between Azure AD Commercial tenant and an Azure AD Government tenant. Cross-cloud collaboration requires setting Inbound and Outbound XTAP settings on the respective tenants.

Integrate authentication strength with Cross-Tenant Access policies.

> 📘 **Reference**: [Cross-tenant access with Azure AD external identities](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/cross-tenant-access-overview)

## Bring Device signals to Azure AD
Connecting devices to Azure AD both improves end-user experience and enhances security. 

Joining devices to Azure Active Directory (also using Hybrid Azure AD Join) lets the device obtain a Primary Refresh Token (PRT) to facilitate single sign-on across services in the Microsoft cloud, including all non-Microsoft applications that use Azure AD as an identity provider. Registering mobile devices provides the ability to use strong passwordless authentication using Authenticator App number matching.

Intune management enables the use of device compliance rules within Conditional Access. Microsoft Defender for Endpoint can ensure managed devices are healthy and clean.

> 📘 **Reference**: [Secure Endpoints with Zero Trust](https://learn.microsoft.com/en-us/security/zero-trust/deploy/endpoints)

## Secure VM Management Interfaces
Gone are the days where admins need to use RDP and SSH to connect directly to virtual machines. Azure includes tools like [Azure Bastion](https://learn.microsoft.com/en-us/azure/bastion/bastion-overview), Azure Virtual Desktop, [Windows Admin Center](https://learn.microsoft.com/en-us/windows-server/manage/windows-admin-center/azure/manage-vm), [Windows](https://learn.microsoft.com/en-us/azure/active-directory/devices/howto-vm-sign-in-azure-ad-windows) and [Linux Login (SSH)](https://learn.microsoft.com/en-us/azure/active-directory/devices/howto-vm-sign-in-azure-ad-linux) with Azure AD identity and more.

Use [Defender for Cloud just-in-time VM access](https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage) for scenarios where direct VM access is required.

> 📘 **Reference**: [Azure Security Compass - Intermediaries](https://learn.microsoft.com/en-us/security/compass/privileged-access-intermediaries)

## Enable Defender for Cloud
Defender for Cloud enables advanced security features for Virtual Machines, App Services, Databases, Storrage, Containers, Key Vault, ARM, DNS, and more. Enabling these plans with autoprovisioning configure diagnostics settings and monitoring agents via Azure Policy.

> 📘 **Reference**: [Quickstart: Enable enhanced security features in Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security)

### Protect on-premises servers
Defender for Cloud is not just for Azure resources.

Servers on-premises or running in other clouds can be onboarded to Defender for Cloud through deployment of Azure Arc. This feature lets Defender for Cloud provide security recommendations, collect security events, and alert on misconfigurations and suspicious activity, just like it does for Azure VMs.

Arc can enable zero trust access to on-premises Linux servers using ephemeral SSH keys generated by Azure AD. No need to distribute keys, administrators assigned Virtual Machine Login roles can sign in with their Azure AD account. To learn more, see [SSH access to Azure Arc-enabled servers](https://learn.microsoft.com/en-us/azure/azure-arc/servers/ssh-arc-overview?tabs=azure-cli).

> 📘 **Reference**: [Azure Arc Overview](https://learn.microsoft.com/en-us/azure/azure-arc/overview)

## Use Microsoft Sentinel
Configure data connectors to ingest all security-related event data into Azure Sentinel. Start with the first party connectors used for MLZ:
- Azure AD Sign in and Audit Logs
- Azure AD Identity Protection
- Azure Resource Management
- Resource-specific logs from Key Vault, Storage Accounts, Firewalls, etc.
- Security Events via AMA (Windows)
- CEF logs via AMA (Linux)

Be sure to review relevant alerts and workbooks for each connector.

> 📘 **Reference**: [Quickstart: Onboard Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/quickstart-onboard)

## Least Privilege with Azure AD
Administrative Units provide a mechanism for scoping Azure AD roles to a particular set of resources. AUs can be scoped to users, groups, and devices. Resources can be assigned to an AU manually, or the AU can be configured with dynamic rules. Refer to the documentation below to learn about AUs and their use cases for scoping / delegating administration in Azure AD.

> **Note**: Not all out-of-box Azure AD roles can be scoped to an AU. Review the [limitations](https://learn.microsoft.com/en-us/azure/active-directory/roles/administrative-units#groups) for Administrative Units.

> 📘 **Reference**: [Administrative Units (AUs)](https://learn.microsoft.com/en-us/azure/active-directory/roles/administrative-units)

### Identity governance
Identity Governance defines a set of capabilities provided by Azure AD Premium P2 licensing. The main components are:
- [Entitlements Management](#entitlements-management)
- [Access Reviews](#access-reviews)

#### Entitlements Managmement
Learn about Entitlements Management in Azure AD and understand how identity governance can help with permissions and application access.

> 📘 **Reference**: [Entitlements Management](https://learn.microsoft.com/en-us/azure/active-directory/governance/entitlement-management-overview)

#### Access Reviews
Learn about Azure AD Access Reviews and understand how access granted to memebers and guests can be periodically reviewed to maintain least-privilege. The baseline configuration does not configure Access Reviews.

> 💡 **Recommendation**: Set up periodic access reviews for membership of Core MLZ and Mission RBAC groups, Privileged Access groups, and directory roles like Global Administrator and Application Administrator.

> 📘 **Reference**: [Access Reviews](https://learn.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview)

#### Connected Orgs
Guest user lifecycle can be managed automatically using Entitlements Management when a Connected Organization is established for a partner organization. Review the capability and establish a connected organization with partner organizations with users that will be invited for collaboration and application access.

> 📘 **Reference**: [Connected Organizations in Entitlements Management](https://learn.microsoft.com/en-us/azure/active-directory/governance/entitlement-management-organization)

### Entra Permissions Management
Entra permissions management helps discover, remediate, and monitor permission assignment and usage across Azure, Amazon Web Services (AWS), and Google Cloud Platform (GCP). Using a Permission Creep Index (PCI), Permissions Managemnet can track privileges over time and create custom RBAC roles to reduce privileges for what admins actually need. Check out the reference below to learn more.

> 📘 **Reference**: [What's Permissions Management](https://learn.microsoft.com/en-us/azure/active-directory/cloud-infrastructure-entitlement-management/overview)

</p>
</details>

## Plan for Zero Trust
The Microsoft cloud includes a vast array of tools and security capabilities that enable advanced zero trust outcomes. These capabilities are enhanced by cross-product integration and additional datapoints. The more Azure AD knows about the context of a user's access, the better it's access control capabilities become. The AI models powering risk-based conditional access with Azure AD Identity Protection, Sentinel User Entity Behavior Analytics, and Insider Risk, are just a few capabilties that get even better with more data.

Make Azure AD Conditional Access a well-informed Policy Enforcement Point (PEP) by integrating signals across identities, endpoints, applications, data, infrastructure, networks, and risk.

> 📘 **Reference**: 
> - [Zero Trust Rapid Modernization Plan](https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-ramp-overview)
> - [Zero Trust Resource Center](https://learn.microsoft.com/en-us/security/zero-trust/)

# See Also
## MLZ Identity Add-On
- [Common Deployment Patterns](./MLZ-Common-Patterns.md)
- [Identity for MLZ Applications](./MLZ-Application-Identity.md)
- [Permissions for MLZ](./AAD-Permissions-Management.md)
- [CBA Configuration for DOD PKI](./AAD-CertificateBasedAuthentication-DODPKI.md)
- [MLZ Identity FAQ](./MLZ-AAD-FAQ.md)
- [MLZ Identity Add-On Home](./../README.md)

## Azure AD Deployment Guides
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