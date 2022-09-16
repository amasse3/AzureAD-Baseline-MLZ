# Azure Active Directory Baseline Configuration for MLZ
This document provides key steps for deploying and securing Azure Active Directory for Mission Landing Zone.

> **Note**:
Some steps require Azure AD P2 licensing for privileged users within the environment. Alternative steps are included in case licenses are not available during initial configuration.

# Table of Contents

  1. [Prepare to manage Azure AD](#1-prepare-to-manage-azure-ad)  
  2. [Create Emergency Access Accounts](#2-create-emergency-access-accounts)
  3. [Configure Authentication Methods](#3-configure-authentication-methods)
  4. [Create Groups for MLZ RBAC](#4-create-mlz-rbac-security-groups)
  5. [Create Named Admin Accounts](#5-create-named-administrator-accounts)
  6. [Enforce Multi-Factor Authentication](#6-enforce-multi-factor-authentication-and-disable-legacy-authentication-protocols)
  7. [Configure Tenant Settings](#7-configure-user-group-and-external-collaboration-settings)
  8. [Add a Custom Domain to Azure AD](#8-optional-add-a-custom-domain-to-azure-ad)
  9. [Evaluate Hybrid Identity Configuration](#9-evaluate-hybrid-identity-needs-identity-synchronization)
  10. [Configure Additional Features](#10-configure-additional-features)

## 1. Prepare to manage Azure AD
The first user in an Azure AD tenant will have super user / root access to the entire Azure tenant. These permissions are assigned by the Global Administrator Azure AD role.

### A. Prepare a secure workstation for managing Azure AD
There are several client tools for managing Azure AD configuration. Make sure you are managing Azure and Azure AD from a secure workstation. Ensure these privileged access devices include the Azure management tools outlined in this section. 

> **Reference**: [Privileged Access Devices](https://docs.microsoft.com/en-us/security/compass/privileged-access-devices)

> **Note**:
Using privileged access devices is best practice for managing any sensitive information system, not just the Azure cloud. 

### B. Install Azure CLI
Azure Command Line Interface (CLI) is a powerful suite of command line tools for managing Azure. Install Azure CLI on your workstation by following instructions from the Azure CLI documentation.

>**Reference**: [Install Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)

### C. Install MS Graph PowerShell
The Microsoft Graph PowerShell module is used for managing Azure AD and other services that expose configuration through the Microsoft Graph. 
To install the module, launch PowerShell and run: `Install Module Microsoft.Graph`

> **Note**:
Azure AD PowerShell module is deprecated as of June 2022. Microsoft Graph PowerShell should be used going forward.

Reference: [Install Microsoft Graph PowerShell](https://docs.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)

Log in with an account that is a [Global Administrator](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator) within the tenant.

### D. Log in to the Azure Portal and license the first Global Administrator
Log in with an account that is a [Global Administrator](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator) within the tenant. In some cases, the first user that created the Azure AD tenant will be a guest / external user. This can be verified by navigating to the Users blade in the Azure AD Portal and investigating the **User Type** field. 

If the signed in account is not a **member** type, follow the steps below:
1. [Add a new user in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-users-azure-active-directory#add-a-new-user)
  - Record the username, including the domain suffix
  - Note the temporary password
2. [Assign Global Administrator role to the new user](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal)
3. Sign out of the portal or click the profile in the top right and select **sign in with a different account**
4. Enter the username and temporary password for the first member administrator account.
5. Change the password to a [strong password value](https://www.nist.gov/video/password-guidance-nist-0)
6. Register security information when prompted. This will secure the administrator account and provide a means for resetting the password.

> **Reference**: [Azure AD Setup Guide](https://go.microsoft.com/fwlink/p/?linkid=2183427)

### E. Log in to the Azure Portal and license the first Global Administrator
1. Log in to the Azure Portal (https://portal.azure.com | https://portal.azure.us) as the first Global Administrator
2. Search for "Azure Active Directory" and click the Azure AD icon to open the AAD Administration "blade" in the Azure Portal.
3. Click **Licenses** and then **All Products**
4. Make sure you see the expected licenses.
5. Assign the first administrator an Azure AD Premium license.

> **Reference**: [Assign or remove licenses in the Azure AD Portal](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/license-users-groups?)

### F. Connect to the Azure AD Tenant with Microsoft Graph PowerShell
Open PowerShell and run the following command to connect to Azure AD:
- Azure AD Commercial
  - `Connect-MgGraph -scope TBD`
- Azure AD Government
  - `Connect-MgGraph -Environment UsGov -scope TBD`
- Azure AD Government - DoD
  - `Connect-MgGraph -Environment UsGovDoD -scope TBD`

## 2. Create Emergency Access Accounts
When a new Azure AD tenant is created, the user who created the tenant is the only user in the directory with administrative privileges. The first thing we need to do is create 2 Emergency Access accounts, 1 of which will be excluded from multi-factor authentication in case the Azure MFA service is degrated.

Reference: [Manage emergency access accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

### A. Set Password Protection Policy
Configure banned password list using [Azure AD Password Protection](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad)
`Placeholder Script to set policy to whatever the STIG is`

### B. Create Accounts
Add cloud-only user accounts for initial Global Administrators.
`Placeholder Script to create the accounts with random complex password`

> **Reference**: [Add or delete users in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-users-azure-active-directory)

**Azure AD Free or Premium P1**
For Azure AD Free or Premium P1, assign the Global Administrator Azure Active Directory Role.

`Placeholder Script to create accounts and assign Global Administrator role`

**Azure AD Premium P2**
If Azure AD Premium P2 is available in the tenant, activate the premium features and assign the Global Administrator role using Azure AD Privileged Identity Management

1. Enable Privileged Identity Management
2. Enable Identity Protection
3. Assign Global Administrator Role using PIM to the Emergency Access Accounts

`Placeholder Script to Assign Global Administrator role with PIM`

### C. Document and Test Emergency Access Procedures
Creation and secure storage for Emergency Access credentials is useless if the emergency procedures to retrieve and use the Emergency Access accounts is not properly documented and disseminated to all individuals who may be tasked with using the accounts.

> **Note**: Consult your Information Systems Security Officer (ISSO) for proper handling procedures for Emergency Access accounts.

**Recommendations**:
- Record passwords for Emergency Access accounts legibly by hand (do not type or send to a printer)
- Store passwords for Emergency Access accounts in a safe that resides in a physically secure location.
- Do not save passwords to an Enterprise password vault or Privleged Access Management (PAM) system
- Do not save passwords to a personal password vault (LastPass, Apple Keychain, Google, OnePassword, Microsoft Authenticator, etc.)
- Store backup copies for Emergency Access account credentials in a geographic distant location.
- Exclude at least 1 Emergency Access account from Azure MFA
- Monitor and alert on Emergency Access account usage

> **Reference**: [Manage Emergency Access Accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

### D. Set up alerts with Microsoft Sentinel
If you are configuring Azure AD for MLZ after the MLZ deployment, leverage the existing Microsoft Sentinel deployment in the Operations subscription to alert on Emergency Account usage.

1. [Connect Azure AD Sign-In Logs to Microsoft Sentinel](https://docs.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory)
2. [Configure an Analytics Rule to alert when Emergency Access account is used](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access#monitor-sign-in-and-audit-logs)

## 3. Configure Authentication Methods
Azure AD authenticaton methods allow an administrator to configure how users can authenticate to Azure AD.

>**Refernce**: [What authentication verification methods are available in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods)

### A. Enable Microsoft Authenticator app
The Microsoft Authenticator app for iOS and Android lets users authenticate / complete MFA challenges when Azure AD configuration (Conditional Access or Security Defaults) needs an additional factor. The Microsoft Authenticator app can be used in the following ways:
- Passwordless Phone Sign-in
- Notification
- Time-based One Time Password (TOTP) code

> **Reference**: [Microsoft Authenticator app](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-authenticator-app)

### B. Enable FIDO2 security keys
FIDO2 security keys are an unphishable standards-based passwordless authentication method that come in different form factors. Most security keys resemble a USB thumb drive and communicate with device over USB.

### C. Pilot Azure AD Native Certificate-Based Authentication
Organizations that need to use smartcard (certificate-based) authentication with Azure AD should configure Azure AD Native Certificate-Based Authentication settings in Azure AD. This feature is in Public Preview and is subject to change. Follow the latest documentation to configure from the reference below.

> **Reference**: [Azure AD Native Certificate-Based Authentication](https://docs.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication)

> **Note**:
This capability is in Public Preview. If Certificate-Based Authentication will be used with certificates that have a large CRL size, a support ticket must be opened via the Azure Portal.

> **Note**: As of August 2022, user certificates can only be mapped using Principal Name and RFC822 Name values on certificates, and UserPrincipalName or OnPremisesUserPrincipalName values in Azure AD. This restricts using certificates with non-routable suffix for the Principal Name / RFC822 values for cloud-only Azure AD accounts (Azure AD UserPrincipalName must be a routable, [verified domain](#7-optional-add-a-custom-domain-to-azure-ad) in Azure AD)'

## 4. Create MLZ RBAC Security Groups
Use this set of Azure AD Security Groups and RBAC role assignments as a baseline.

### A. Azure Resource RBAC
Permissions for Azure resource management are granted through assignments to an Azure RBAC role. In the Azure Portal, RBAC role assignments can be created or viewed by selecting the IAM link. Azure RBAC assignments can apply to users (members and guests), security groups, service principals, and managed identities. 

- **💡Recommendation** : Assign permissions to Azure AD security groups. If Azure AD Premium P2 licesing is available, configure the security groups eligble for the Azure RBAC role assignments.

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

### B. Azure AD RBAC
In addition to Azure AD roles, there are several Azure AD Directory roles that may be needed. These roles can be assigned to users, groups (if group is role-assignable), and service principals.

Azure AD RBAC can be assigned at any of the following scopes:
 - Directory (default)
   - Administrative Unit
   - Azure AD Resource (Group or Application Owner)

 **💡 Recommendation**: Start by assigning Global Administrator role for Emergency Access accounts and tenant admins. When other Azure AD permissions are required, assign users using [least-privileged role by task](https://docs.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task)

|Name|Usage|
|----|-----|
|Application Developer|Register applications with Azure AD.|
|Application Administrator|Manage all Enterprise Applications in Azure AD.|
|Hybrid Identity Administrator|Configure Azure AD Connect to synchronize identities from AD DS to Azure AD|

**Azure AD Free or Premium P1**
Assign users directly to Azure AD roles.

**Azure AD Premium P2**
Create [Role-Assignable Groups]() and assign eligibility to Azure AD directory roles using Privileged Identity Management (PIM).

The following role-assignable groups are used in the AAD Configuration Baseline:
|Name|Usage|AAD Role|Role Type|Scope|
|----|-----|--------|---------|-----|
|Groups Administrator|Azure AD role assignment for managing groups|Groups Administrator|Built-in AAD Role|Global|
|Mission RBAC Role Manager|Privileged Access Group|AAD Role for Groups Administrator|Administrative Unit|
|Application Developers|Azure AD role assignment for app registration|Application Developers|Built-in AAD Role|Global|
|Hybrid Identity Admins|Configure Azure AD Connect to synchronize identities from AD DS to Azure AD|Global

> **Note**:
These security group and role assignments represent baseline configuration. Modify with additional roles as needed, starting with built-in roles when possible.

### C. Create Azure AD Security Groups
Run the script below to create Azure AD security groups:
`$groups = @() #Update for all groups`
`New-MGGroup -Example`

### D. Map MLZ RBAC Security Groups to Azure RBAC Roles
Once the groups are created, map them to the relevant RBAC role.

**Azure AD Free or Premium P1**
`Script`

**Azure AD Premium P2**
Azure AD Premium P2 customers should map security groups eligible for roles using Privileged Identity Management (PIM). Choose an elevation duration and access review interval.

**💡 Recommended Settings**:
- Global Administrator
    - **Elevation Duration:** 2 hours
    - **Approvals Required:** Yes
    - **Notification:** Yes
- Other Roles
    - **Duration:** 4 hours
    - **Approval Required:** No
    - **Notification:** Yes

`Script`

### E. Review Securing Privileged Access in Azure AD
Familiarize yourself with the Securing Privileged Access guidance for Azure AD and build a plan for handling privileged access to the Mission Landing Zone environment.

> **Reference**: [Securing privileged access for hybrid and cloud deployments in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning)

## 5. Create Named Administrator Accounts
Day-to-day operations requiring administrative privileges should be performed by named administrator accounts, assigned to individual users (not shared), separate from accounts used to access productivity services like Email, SharePoint, and Teams.

**💡 Recommendations**:
- Administration for Azure and Azure AD should use cloud-only identities and Azure AD native authentication mechanism, like FIDO2 security keys.
- Limit the number of Global Administrators, referring to [least privileged roles by task](https://docs.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task) to assign the proper limited administrator role
- Assign permissions Just-In-Time using [Azure AD Privileged Identity Management](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)
- Periodically review role eligibility
- Leverage PIM [insights](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-security-wizard) and [alerts](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-configure-security-alerts) to further secure your organization
- Review [Privileged Access Groups](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/groups-features) and [Administrative Units](https://docs.microsoft.com/en-us/azure/active-directory/roles/administrative-units)

### A. Choose a naming convention
Choose a naming convention for cloud-only administrative accounts:
- FirstName+"."+LastName+@tenant.onmicrosoft.com
- FirstInitial+LastName+@tenant.onmicrosoft.com
- "adm." + FirstInitial+LastName@tenant.onmicrosoft.com
- other

### B. Create Azure AD cloud-only identities
1. Create users in the Azure Portal or using Microsoft Graph PowerShell. 
2. Provide the temporary password for each new admin.
3. Instruct the admin to change password and [register security info](https://support.microsoft.com/en-us/account-billing/set-up-the-microsoft-authenticator-app-as-your-verification-method-33452159-6af9-438f-8f82-63ce94cf3d29) by setting Microsoft Authenticator App as a verification method.

### C. Configure phishing-resistant MFA
Configure phishing-resistant strong authentication with Azure AD. Review the list below:

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

> **Reference**: [Phishing-resistant methods](https://docs.microsoft.com/en-us/azure/active-directory/standards/memo-22-09-multi-factor-authentication#phishing-resistant-methods)

## 6. Enforce Multi-Factor Authentication and disable Legacy Authentication Protocols
This section enables key recommended access policies for all apps protected by Azure AD. This includes the Azure portal, Microsoft Graph, Azure Resource Manager, M365 applications, and any future applications integrated with Azure AD.

**Azure AD Free - Turn on Security Defaults**
Azure AD Free offers a feature called Security Defaults. This feature performs basic security configuration for the Azure AD platform. To enable security defaults, see [Enable Security Defaults](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults).

`Script`

**Azure AD Premium P1 and P2 - Create Conditional Access Policies**
Create the following Conditional Access policies:

1. [Block Legacy Authentication](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-block-legacy)
2. [Require MFA for All Users all Apps](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa)

> **Note**: If you are configuring [hybrid identity](#9-optional-configure-hybrid-identity), make sure exclude the Azure AD account used for AAD Connect Synchronization from the MFA policy.

**Azure AD Premium P2 - Configure Risk-Based Conditional Access Policies**
Enable the following [risk-based Conditional Access Policies](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-configure-risk-policies):
1. Require password change when User Risk is **High**
2. Create Conditional Access rule to Block Registering Security Info when sign-in risk is **High**

`script`

> **Note**: If Microsoft Endpoint Manager (Intune) will be deployed for the Azure AD tenant used by MLZ, enroll privileged access devices and use [Conditional Access](https://docs.microsoft.com/en-us/mem/intune/protect/create-conditional-access-intune) to require a compliant device for Azure Management.

## 7. Configure User, Group, and External Collaboration Settings
This section contains basic tenant-level settings applicable to all Azure AD versions. The MLZ baseline AAD script will set these configuration items according to the defaults outlined in each section. This configuration can be changed at any time. The baseline settings represent a starting point, and may not be functional for certain scenarios. For example, tenants that will be accessed by guests from another tenant must set the External Collaboration settings accordingly. The baseline offers a most restrictive experience, which turns off these collaboration features.

### A. User Settings
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

`script`
> **Note**: Some settings are set during tenant creation and cannot be changed. All settings may not be available in Azure AD Government.

### B. Group Settings
The MLZ AAD baseline will set the following Azure AD group settings:
|Setting|MLZ-Baseline|
|-------|------------|
|Owners can manage group membership requests in the Access Panel|Yes|
|Restrict user ability to access group features in the access panel|No|
|Users can create security groups|No|
|Users can create M365 groups|No|
|Group Naming Policy Prefix|Baseline script parameter|
|Group Naming Policy Suffix|Baseline script parameter|

`script`

### C. External Collaboration Settings
MLZ AAD baseline will set the following Azure AD external collaboration settings:
|Setting|MLZ-Baseline|
|-------|------------|
|Guest user access|Most Restricted|
|Guest invitations|Most Restrictive (no one can invite)|
|Enable guest self-service|No|
|Allow external users to leave|Yes|
|Invitation restrictions|Most Restrictive|

`script`

> **Reference**:[Default user permissions in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions)

## 8. Optional: Add a custom domain to Azure AD
When an Azure AD tenant is created, a default domain is assigned that looks like *tenantname.onmicrosoft.com* (*tenantname.onmicrosoft.us* for Azure AD Government). By default, all users in Azure AD get a UserPrincipalName (UPN) with the default domain suffix.

[Custom domains](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-custom-domain) let tenant administrators change the UPN suffix by verifying ownership of an organization's DNS domain via TXT record.

> **Note**:
Sometimes when custom domains are added to an Azure AD tenant, users who signed up for trial Microsoft services with their organization email address will appear in the tenant once the domain is verified. Do not be alarmed by this. To verify no other users have privileges within the tenant, [view the Azure AD role members](https://docs.microsoft.com/en-us/azure/active-directory/roles/view-assignments).


## 9. Evaluate Hybrid Identity Configuration
Microsoft’s identity solutions span on-premises and cloud-based capabilities. These solutions create a common user identity for authentication and authorization to all resources. This configuration has 2 parts:
- [Synchronization](#a-synchronization)
- [Authentication](#b-authentication)

>**Reference**: [What is hybrid identity with Azure AD?](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-hybrid-identity)

### A. Synchronization
Hybrid identity should be configured if an organization uses Active Directory Domain Services and wishes to synchronize users and groups to Azure AD. Microsoft offers 2 tools (named very similarly) to accomolish this function:
- [Azure AD Connect](#azure-ad-connect-v2)
- [Azure AD Connect Cloud Sync](#azure-ad-connect-cloud-sync)

Which tool you should use varies depending on the hybrid identity needs for the environment. Use Cloud Sync for simple scenarios if it supports the features your organization needs. For a full breakdown of feature support between the tools, see [Comparison between Azure AD Conect and Cloud Sync](https://docs.microsoft.com/en-us/azure/active-directory/cloud-sync/what-is-cloud-sync#comparison-between-azure-ad-connect-and-cloud-sync).

> **Note**: Synchronizing all identities to Azure AD helps establish an enterprise identity and zero trust surface for all applications. If hybrid identity is already configured for a different tenant, treat that tenant as the enterprise Azure AD for the organization. Review the tenant types.


#### i. Azure AD Connect v2
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

> **Reference**: (Choose the right authentication method for your Azure AD hybrid identity solution)[https://docs.microsoft.com/en-us/azure/active-directory/hybrid/choose-ad-authn]

#### ii. Azure AD Connect Cloud Sync
[Azure AD Connect Cloud Sync](https://docs.microsoft.com/en-us/azure/active-directory/cloud-sync/what-is-cloud-sync) is an agent-based synchronization tool managed in Azure AD. This tool is expected to replace Azure AD Connect sync for most scenarios.

Use Azure AD Connect Cloud Sync if:
- You want to synchronize identities from Active Directory Domain Services to Azure AD
- You are configuring Password Hash Sync or cloud-native Azure AD authentication with security keys, authenticator app, or certificates.
- You will be joining devices directly to Azure AD and do not need hybrid join functionality
- You do not need to synchronize extension attributes
- You do not need to filter using attribute values (Organizational Unit filtering only)
- You do not need complex or custom attribute synchronization logic

#### iii. Exclude sync account from Multi-Factor authentication Conditional Access Policy
Once a synchronization tool is configured, you should see initial synchronization fails due to single-factor authentication. Ensure this account is excluded from any MFA requirements set by Conditional Access policy. See [user exclusions](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa#user-exclusions).

### B. Authentication
Hybrid identity configuration can include [Password Hash Synchronization (PHS)](placeholder) where passwords are replicated from Active Directory to Azure AD. This is only applicable for AD environments where users have and use a password. If users access AD-protected resources with a smartcard (CAC/PIV), there is no reason to set up password hash sync.

Pass-Through Authentication (PTA) and federation with ADFS are not recommended. Hybrid authentication is less secure than Azure AD native methods, as the on-premises environment represents a significant identity attack surface.

>**Recommendation**: Use Azure AD native strong authentication method, like FIDO2 security keys or native certificate-based authentication, for administration of Azure and Azure AD.

## 10. Configure Additional Features

### A. Group-Based Licensing
Group-based licensing is an Azure AD Premium feauture that automatically applied licenses to members of a security group. Creating [dynamic groups](https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/groups-create-rule) can further automate this process, since these groups are populated based on user attribute values. To use group-based licensing, follow steps in [assign licenses to a group](https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-groups-assign).

> **Reference**: [Group-based licensing with PowerShell and Microsoft Graph](https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-ps-examples)

### B. Custom Azure AD Roles

### C. Administrative Units

### D. Identity Governance

#### i. Privileged Identity Management

#### ii. Entitlements Managmement

#### iii. Access Reviews

### iv. Connected Orgs

### E. Cross-Cloud Collaboration

# See Also: Azure AD Deployment Guides
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