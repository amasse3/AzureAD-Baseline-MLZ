# Azure Active Directory Baseline Configuration for MLZ
This document outlines the main steps an MLZ tenant owner should complete to secure Azure AD.

> **Note**:
Some steps require Azure AD P2 licensing for privileged users within the environment. Alternative steps are included in case licenses are not available during initial configuration.

# Table of Contents

  1. [Prepare a Privileged Access Workstation](#1-prepare-a-secure-workstation)  
  2. [Create Emergency Access Accounts](#2-create-emergency-access-accounts)
  3. [Create Named Administrator Accounts](#3-create-named-administrator-accounts)
  4. [Enforce MFA and Disable Legacy Protocols](#4-enforce-multi-factor-authentication-and-disable-legacy-authentication-protocols)
  5. [Configure User Settings](#5-configure-user-settings)
  6. [Configure Collaboration Settings](#6-configure-external-collaboration-settings)
  7. [Add a Custom Domain to Azure AD](#7-optional-add-a-custom-domain-to-azure-ad)
  8. [Optional: Configure Certificate-Based Authentication](#8-optional-configure-azure-ad-native-certificate-based-authentication)
  9. [Optional: Configure Hybrid Identity](#9-optional-configure-hybrid-identity)
  10.[Optional: Configure Group-Based Licensing](#10-configure-group-based-licensing)

## 1. Prepare a secure workstation for managing Azure AD
There are several client tools for managing Azure AD configuration. Make sure you are managing Azure and Azure AD from a secure workstation. Ensure these privileged access devices include the Azure management tools outlined in this section. 

Reference: [Privileged Access Devices](https://docs.microsoft.com/en-us/security/compass/privileged-access-devices)

> **Note**:
The practice of securing access with privileged access devices applies to any IT systems, not just the Azure cloud. 

### Install Azure CLI
Azure Command Line Interface (CLI) is a powerful suite of command line tools for managing Azure. Install Azure CLI on your workstation by following instructions from the Azure CLI documentation.

Reference: [Install Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)

### Install MS Graph PowerShell
The Microsoft Graph PowerShell module is used for managing Azure AD and other services that expose configuration through the Microsoft Graph. 
To install the module, launch PowerShell and run: `Install Module Microsoft.Graph`

> **Note**:
Azure AD PowerShell module is deprecated as of June 2022. Microsoft Graph PowerShell should be used going forward.

Reference: [Install Microsoft Graph PowerShell](https://docs.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)

### Connect to the Azure AD Tenant
Open PowerShell and run the following command to connect to Azure AD:
- Azure AD Commercial
  - `Connect-MgGraph -scope TBD`
- Azure AD Government
  - `Connect-MgGraph -Environment UsGov -scope TBD`
- Azure AD Government - DoD
  - `Connect-MgGraph -Environment UsGovDoD -scope TBD`

Log in with an account that is a [Global Administrator](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator) within the tenant.

## 2. Create Emergency Access Accounts
When a new Azure AD tenant is created, the user who created the tenant is the only user in the directory with administrative privileges. The first thing we need to do is create 2 Emergency Access accounts, 1 of which will be excluded from multi-factor authentication in case the Azure MFA service is degrated.

Reference: [Manage emergency access accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

### Set Password Protection Policy

`Placeholder Script to set policy to whatever the STIG is`

### Create Accounts

`Placeholder Script to create the accounts with random complex password`

**Azure AD Free or Premium P1**
For Azure AD Free or Premium P1, assign the Global Administrator Azure Active Directory Role.

`Placeholder Script to create accounts and assign Global Administrator role`

**Azure AD Premium P2**
If Azure AD Premium P2 is available in the tenant, activate the premium features and assign the Global Administrator role using Azure AD Privileged Identity Management

1. Enable Privileged Identity Management
2. Enable Identity Protection
3. Assign Global Administrator Role using PIM to the Emergency Access Accounts

`Placeholder Script to Assign Global Administrator role with PIM`

### Document and Test Emergency Access Procedures
Creation and secure storage for Emergency Access credentials is useless if the emergency procedures to retrieve and use the Emergency Access accounts is not properly documented and disseminated to all individuals who may be tasked with using the accounts.

> **Note**: Consult your Information Systems Security Officer (ISSO) for proper handling procedures for Emergency Access accounts.

**Recommendations**:(
- Record passwords for Emergency Access accounts legibly by hand (do not type or send to a printer)
- Store passwords for Emergency Access accounts in a safe that resides in a physically secure location.
- Do not save passwords to an Enterprise password vault or Privleged Access Management (PAM) system
- Do not save passwords to a personal password vault (LastPass, Apple Keychain, Google, OnePassword, Microsoft Authenticator, etc.)
- Store backup copies for Emergency Access account credentials in a geographic distant location.

Reference: [Manage Emergency Access Accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

### Set up alerts with Microsoft Sentinel
If you are configuring Azure AD for MLZ after the MLZ deployment, leverage the existing Microsoft Sentinel deployment in the Operations subscription to alert on Emergency Account usage.

1. [Connect Azure AD Sign-In Logs to Microsoft Sentinel](https://docs.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory)
2. [Configure an Analytics Rule to alert when Emergency Access account is used](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access#monitor-sign-in-and-audit-logs)

## 3. Create MLZ RBAC Security Groups
Use this set of Azure AD Security Groups and RBAC role assignments as a baseline.

### Azure Resource RBAC
Roles for Azure resource management are assigned within Azure RBAC. When using the Azure Portal, RBAC roles are assigned using the IAM button on the desired Azure resource. Permissions granted by RBAC role assignments scoped at the Reso 

|Name|Usage|RBAC Role |Role Type|Intended Scope|
|----|-----|----------|---------|--------------|
|Azure Platform Owner|Management Group and subscription lifecycle management|Owner|Built-in|Management Group|
|Security Operations|View and update permissions for Microsoft Defender for Cloud|Security Admin|Built-in|Subscription|
|Subscription Owner|Grants full access to manage all resources, including ability to assign roles with RBAC |Owner|Built-in|Subscription|
|Subscription Owner no Network Write|Delegated role for subscription owner that prohibits ability to manage role assignments and routes.SubscriptionOwnerNoNetwork|Custom|Subscription|
|Subscription Contributor|insert blurb|Contributor|Built-in|Subscription|
|Subscription Reader|insert blurb|Reader|Built-in|Subscription|
|Application Owners (DevOps)|Contributor role granted at resource group.|DevOpsAppOps|Custom|Resource Group|

### Azure AD RBAC
In addition to Azure AD roles, there are several Azure AD Directory roles that may be needed. 

|Name|Usage|
|----|-----|
|Application Developer|Register applications with Azure AD.|
|Application Administrator|Manage all Enterprise Applications in Azure AD.|
|Hybrid Identity Administrator|Configure Azure AD Connect to synchronize identities from AD DS to Azure AD|

**Azure AD Free or Premium P1**
Assign users directly to Azure AD roles using the [least-privileged role by task](https://docs.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task).

**Azure AD Premium P2**
Create [Role-Assignable Groups]() and assign eligibility to Azure AD directory roles using Privileged Identity Management (PIM).

The following role-assignable groups are used in the AAD Configuration Baseline:
|Name|Usage|AAD Role| Role Type|Scope|
|Groups Administrator|Azure AD role assignment for managing groups|Groups Administrator|Built-in AAD Role|Global|
|Mission RBAC Role Manager|Privileged Access Group|AAD Role for Groups Administrator|Administrative Unit|
|Application Developers|Azure AD role assignment for app registration|Application Developers|Built-in AAD Role|Global|
|Hybrid Identity Admins|Configure Azure AD Connect to synchronize identities from AD DS to Azure AD|Global

> **Note**:
These security group and role assignments represent baseline configuration. Modify with additional roles as needed, starting with built-in roles when possible.

### Create Azure AD Security Groups
`Script that creates security groups`
### Map MLZ RBAC Security Groups to Azure RBAC Roles

**Azure AD Free or Premium P1**
`Script`

**Azure AD Premium P2**
Azure AD Premium P2 customers should map security groups as eligible for roles using Privileged Identity Management (PIM). Choose an elevation duration and access review interval.

**Recommended Settings**:
- Global Administrator
    - Elevation Duration: 2 hours
    - Approvals Required: Yes
    - Notification: Yes
- Other Roles
    - Duration: 4 hours
    - Approval Required: No
    - Notification: Yes

`Script`

### Review Securing Privileged Access in Azure AD
Familiarize yourself with the Securing Privileged Access guidance for Azure AD and build a plan for handling privileged access to the Mission Landing Zone environment.

> **Reference**: [Securing privileged access for hybrid and cloud deployments in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning)

## 4. Create Named Administrator Accounts
Day-to-day operations requiring administrative privileges should be performed by named administrator accounts, assigned to individual users (not shared), separate from accounts used to access productivity services like Email, SharePoint, and Teams.

**Recommendations**:
- Limit the number of Global Administrators, referring to [least privileged roles by task](https://docs.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task) to assign the proper limited administrator role
- Assign permissions Just-In-Time using [Azure AD Privileged Identity Management](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)
- Periodically review role eligibility
- Leverage PIM [insights](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-security-wizard) and [alerts](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-configure-security-alerts) to further secure your organization
- Review [Privileged Access Groups](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/groups-features) and [Administrative Units](https://docs.microsoft.com/en-us/azure/active-directory/roles/administrative-units)

### Enable Multi-Factor Authentication

- **Bad:** SMS or TwoWayPhone
Some MFA is better than no MFA, but phone-based MFA is the weakest option available. SMS is especially egregious since it is susceptable to [SIM swapping attacks](https://en.wikipedia.org/wiki/SIM_swap_scam).
- **Good:** Authenticator App TOTP Code or Push notification
These methods are not phishing-resistant or passwordless. In either case, a password is used, followed by an Azure MFA prompt.
- **Better:** Passwordless Phone Sign-In on Registered Device
Passwordless, but not phishing-resistant. This required registration of an iOS or Android mobile device with the Azure AD tenant.
- **Best:** Phishing-Resistant MFA FIDO2 Security Key or Azure AD native Certificate-Based Authentication (CBA)
  - FIDO2 Security Key
  - Certificate-Based Authentication

> **Note**:
Microsoft Authenticator App is considered phishing-resistant when deployed to a managed mobile device. Since this guide assumes a new tenant, it assumes Microsoft Endpoint Manager is not configured to manage mobile devices.

## 5. Enforce Multi-Factor Authentication and disable Legacy Authentication Protocols
This section enables key recommended access policies for all apps protected by Azure AD. This includes the Azure portal, Microsoft Graph, Azure Resource Manager, M365 applications, and any future applications integrated with Azure AD.

**Azure AD Free - Turn on Security Defaults**
Azure AD Free offers a feature called Security Defaults. This feature performs basic security configuration for the Azure AD platform. To enable security defaults, see (Enable Security Defaults)[https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults].

**Azure AD Premium P1 - Create Conditional Access Policies**

1. Block Legacy Authentication
2. Require MFA for All Users all Apps
`script`

**Azure AD Premium P2 - Configure Risk-Based Conditional Access Policies**
1. Configure Azure AD Identity Protection
2. Create Conditional Access rule to Block when Sign-In Risk is **High**
`script`

> **Note**: If Microsoft Endpoint Manager (Intune) will be deployed for the Azure AD tenant used by MLZ, enroll privileged access devices and use [Conditional Access](https://docs.microsoft.com/en-us/mem/intune/protect/create-conditional-access-intune) to require a compliant device for Azure Management.

## 6. Configure User, Group, and External Collaboration Settings

### User Settings
`script`

### Group Settings
`script`

### External Collaboration Settings
`script`

## 7. Optional: Add a custom domain to Azure AD
When an Azure AD tenant is created, a default domain is assigned that looks like *tenantname.onmicrosoft.com* (*tenantname.onmicrosoft.us* for Azure AD Government). By default, all users in Azure AD get a UserPrincipalName (UPN) with the default domain suffix.

[Custom domains](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-custom-domain) let tenant administrators change the UPN suffix by verifying ownership of an organization's DNS domain via TXT record.

> **Note**:
Sometimes when custom domains are added to an Azure AD tenant, users who signed up for trial Microsoft services with their organization email address will appear in the tenant once the domain is verified. Do not be alarmed by this. To verify no other users have privileges within the tenant, [view the Azure AD role members](https://docs.microsoft.com/en-us/azure/active-directory/roles/view-assignments).

## 8. Optional: Configure Azure AD Native Certificate-Based Authentication
### Upload Certificates
### Configure CertificateBasedAuthentication Settings
> **Note**:
This capability is in Public Preview. If Certificate-Based Authentication will be used with certificates that have a large CRL size, 

## 9. Optional: Configure Hybrid Identity
### Azure AD Connect v2
### Azure AD Connect Cloud Sync
Note: Only if there is no requirement to synchronize devices
### Exclude sync account from Multi-Factor authentication Conditional Access Policy

## 10. Configure Group-Based Licensing

# See Also
Links
