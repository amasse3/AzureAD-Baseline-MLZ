# MLZ-Identity-AzureADSetup
This repository is working guidance for configuring Azure AD for Azure Mission Landing Zone. Like MLZ, this is a highly opinionated document for Azure AD security.

## Table of Contents

- [Understanding Azure AD](#Understanding-Azure-AD)
- [Prepare a New Azure AD Tenant](#prepare-a-new-azure-ad-tenant)
  - [1. Prepare a Privileged Access Workstation](#1-prepare-a-secure-workstation)  
  - [2. Create Emergency Access Accounts](#2-create-emergency-access-accounts)
  - [3. Create Named Administrator Accounts](#3-create-named-administrator-accounts)
  - [4. Enforce MFA and Disable Legacy Protocols](#4-enforce-multi-factor-authentication-and-disable-legacy-authentication-protocols)
  - [5. Configure User Settings](#5-configure-user-settings)
  - [6. Configure Collaboration Settings](#6-configure-external-collaboration-settings)
  - [7. Add a Custom Domain to Azure AD](#7-optional-add-a-custom-domain-to-azure-ad)
  - [8. Optional: Configure Certificate-Based Authentication](#8-optional-configure-azure-ad-native-certificate-based-authentication)
  - [9. Optional: Configure Hybrid Identity](#9-optional-configure-hybrid-identity)
  - [10.Optional: Configure Group-Based Licensing](#10-configure-group-based-licensing)
- [See Also](#see-also)  

# Understanding Azure AD

### What is Microsoft Entra?
Entra is the name for the family of Microsoft cloud identity and access management products.

There are currently 3 separate products in the Entra family:
1. Azure Active Directory - the Identity as a Service (IDaaS) platform for the Microsoft Cloud
2. Permissions Management - Cloud Infrastructure Entitlement Management solution for multi-cloud
3. Verified ID - Decentralized identity service

This document focuses on Azure AD, the identity platform for Microsoft Azure.

### What is Azure Active Directory?
Azure Active Directory (Azure AD) is an Identity as a Service (IDaaS) platform for the Microsoft cloud.

Reference: [What is Azure AD?](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis)

### How do I manage Azure AD?
There are several interfaces for managing Azure AD. While the M365 Admin Portal provides access to Azure AD users and licensing, it only exposes a subset of Azure AD features. We recommend using the below methods for Azure AD management:

- Azure AD Commercial
  - Entra Portal: https://entra.microsoft.com
  - Azure Portal: https://portal.azure.com
  - Microsoft Graph PowerShell: `Connect-MgGraph`
  - Microsoft Graph Explorer: https://developer.microsoft.com/en-us/graph/graph-explorer
  - Postman: https://graph.microsoft.com
- Azure AD Government and DoD
  - Azure Portal: https://portal.azure.us
  - Microsoft Graph PowerShell: `Connect-MgGraph -Environment <UsGov|UsGovDoD>`
  - Postman: https://graph.microsoft.us | https://dod-graph.microsoft.us

### Where is Azure AD Data stored?
Azure AD is a non-regional service, meaning it does not run in specific Azure regions. Data is replicated across Azure AD service locations. Separate instances exist for Azure Government and Azure Commercial clouds.

Reference: [Azure AD Architecture](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-architecture)

### What are the core components of Azure AD?
- Login Service / Security Token Service (login.microsoftonline.com | login.microsoftonline.us)
- Directory Service - users, groups, guests, application and system identities
- Microsoft Graph API - managment interface for Azure and M365

### What is an Azure AD Tenant?
An Azure AD tenant is a logically separated instance of the AAD service that belongs to an organization.

### How many Azure AD Tenants should an organization have?
Microsoft recommends each organization use 1 Azure AD tenant for *both* Microsoft 365 services and pinned Azure Subscriptions. Because Azure AD is intended to be an enterprise identity solution, a single tenant offers the most cohesive experience for end users and administrators. Nevertheless, there are situations where an organization will opt for separate Azure AD tenants. It is important to understand the implications for choosing a separate tenant for MLZ deployment.

## Understand which Tenant type MLZ subscriptions will use

### MLZ Subscriptions attached to Enterprise Azure AD tenant
An organization's Azure AD that contains all users and licenses is an **Enterprise Azure AD Tenant**. These tenants are often configured for hybrid identity with users and groups synchronized from an on-Premises Active Directory enviornment using Azure AD Connect, or provisioned into Azure AD directly from a support HR SaaS Provider. All non-Microsoft applications, including applications running on-premises, in other clouds, SaaS apps, or Azure subscriptions pinned to *other* non-Enterprise AAD should use the **Enterprise Azure AD** for identity.
- **Modern Applications** using OpenIDConnect, OAuth, SAML, WS-Federation can use Azure AD identity directly when onboarded as an [Enterprise Application](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/add-application-portal).
- **Legacy Applications** using Kerberos (Windows Authentication), NTLM, Header-Based authentication can use Azure AD identities indirectly via [Azure AD Application Proxy](https://docs.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy) or a [Secure Hybrid Access Partner](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/secure-hybrid-access) acting as a broker.

> **Important**:  
Applications hosted in MLZ should use the **Enterprise Azure AD** tenant for application identity, directly or via Azure AD Application Proxy / broker. This means applications relying on Active Directory Domain Services need AD DS extended to the MLZ Azure environment through extending existing Active Directory domain or resource forest in Azure. 
In either case, Azure AD Application proxy connectors are recommended to broker access for the Enterprise AAD identities. This allows publishing applications securely without relying on costly network appliances (application firewalls and VPN gateways), while bringing the power of Azure AD Conditional Access to enforce zero trust policies based on authentication context, session details, device health, and identity risk.

### MLZ Subscriptions attached to a separate, standalone Azure Platform tenant
In some cases, customers choose to use a separate Azure AD where their subscriptions are managed. This configuration introduces complexity for Azure services that are accessed by Azure AD identities, since users either need A) Separate Azure AD accounts and licenses in each tenant, B) Rely on Azure AD B2B Guests and switching tenant context, C) configuring light house for all Azure resource access.

# Prepare a New Azure AD Tenant
Follow these setup steps for MLZ deployed to a new Azure AD tenant.

## 1. Prepare a secure workstation for managing Azure AD
There are several client tools for managing Azure AD configuration. Make sure you are managing Azure AD from a secure workstation. Best practice is to deploy a special purpose Privileged Access Workstation that includes AAD management tools.
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

## 2. Create Emergency Access Accounts
When a new Azure AD tenant is created, the user who created the tenant is the only user in the directory with administrative privileges. The first thing we need to do is create 2 Emergency Access accounts, 1 of which will be excluded from multi-factor authentication in case the Azure MFA service is degrated.

Reference: [Manage emergency access accounts in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access)

### Set Password Protection Policy

`Placeholder Script to set policy to whatever the STIG is`

### Create Accounts

`Placeholder Script to create the accounts with random complex password`

### Azure AD Free or Premium P1

`Placeholder Script to create accounts and assign Global Administrator role`

### Azure AD Premium P2

1. Enable Privileged Identity Management
2. Assign Global Administrator Role using PIM to the Emergency Access Accounts

`Placeholder Script to create accounts and assign Global Administrator role with PIM`

### Document and Test Emergency Access Procedures
Creation and secure storage for Emergency Access credentials is useless if the emergency procedures to retrieve and use the Emergency Access accounts is not properly documented and disseminated to all individuals who may be tasked with using the accounts.

Consult your Information Systems Security Officer (ISSO) for proper handling procedures for Emergency Access accounts.

**Recommendations**:
- Record passwords for Emergency Access accounts legibly by hand (do not type or send to a printer)
- Store passwords for Emergency Access accounts in a safe that resides in a physically secure location.
- Do not save passwords to a personal password vault (LastPass, Apple Keychain, Google, OnePassword, Microsoft Authenticator, etc.)
- Do not save passwords to an Enterprise password vault or Privleged Access Management (PAM) system
- Store backup copies for Emergency Access account credentials in a geographic distant location.

### Set up alerts with Microsoft Sentinel
If you are configuring Azure AD for MLZ after the MLZ deployment, leverage the existing Microsoft Sentinel deployment in the Operations subscription to alert on Emergency Account usage.

1. [Connect Azure AD Sign-In Logs to Microsoft Sentinel](https://docs.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory)
2. [Configure an Analytics Rule to alert when Emergency Access account is used](https://docs.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access#monitor-sign-in-and-audit-logs)

## 3. Create Named Administrator Accounts
Once the Emergency Access accounts 
All named administrator accounts (not shared emergency access accounts) should register for multi-factor authentication. Security Keys are the recommended method.

**Recommendations**:
- Limit the number of Global Administrators
- Assign permissions Just-In-Time using [Azure AD Privileged Identity Management](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)
- Periodically review role eligibility
- Leverage PIM [insights](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-security-wizard) and [alerts](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-configure-security-alerts) to further secure your organization
- Use [Limited Administrator roles](https://docs.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task) whenever possible
- Review [Privileged Access Groups](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/groups-features) and [Administrative Units](https://docs.microsoft.com/en-us/azure/active-directory/roles/administrative-units)

### Create Azure AD Security Groups

### Map Azure AD Security Groups to Azure RBAC Roles

### Enable Multi-Factor Authentication

#### Bad: SMS or TwoWayPhone
Some MFA is better than no MFA, but phone-based MFA is the weakest option available. SMS is especially egregious since it is susceptable to [SIM swapping attacks](https://en.wikipedia.org/wiki/SIM_swap_scam).
#### Good: Authenticator App TOTP Code or Push notification
These methods are not phishing-resistant or passwordless. In either case, a password is used, followed by an Azure MFA prompt.
#### Better: Passwordless Phone Sign-In on Registered Device
Passwordless, but not phishing-resistant. This required registration of an iOS or Android mobile device with the Azure AD tenant.
#### Best: Phishing-Resistant MFA FIDO2 Security Key or Azure AD native Certificate-Based Authentication (CBA)
- FIDO2 Security Key
- Certificate-Based Authentication

> **Note**:
Microsoft Authenticator App is considered phishing-resistant when deployed to a managed mobile device. Since this guide assumes a new tenant, it assumes Microsoft Endpoint Manager is not configured to manage mobile devices.

## 4. Enforce Multi-Factor Authentication and disable Legacy Authentication Protocols
This section enables key recommended access policies for all apps protected by Azure AD. This includes the Azure portal, Microsoft Graph, Azure Resource Manager, M365 applications, and any future applications integrated with Azure AD.

### Azure AD Free - Turn on Security Defaults
Azure AD Free offers a feature called Security Defaults. This feature performs basic security configuration for the Azure AD platform. To enable security defaults, see (Enable Security Defaults)[https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults].

### Azure AD Premium P1 - Create Conditional Access Policies
`script`

### Azure AD Premium P2 - Configure Risk-Based Conditional Access Policies
`script`

## 5. Configure User Settings
`script`

## 6. Configure External Collaboration Settings
`script`

## 7. Optional: Add a custom domain to Azure AD

> **Note**:
Sometimes when custom domains are added to an Azure AD tenant, users who signed up for trial Microsoft services with their organization email address will appear in the tenant once the domain is verified. Do not be alarmed by this. To verify no other users have privileges within the tenant, [view the Azure AD role members](https://docs.microsoft.com/en-us/azure/active-directory/roles/view-assignments).

## 8. Optional: Configure Azure AD Native Certificate-Based Authentication
### Upload Certificates
### Configure CertificateBasedAuthentication Settings
### Preview: Open Support Ticket for CRL limit increase

## 9. Optional: Configure Hybrid Identity
### Azure AD Connect v2
### Azure AD Connect Cloud Sync
Note: Only if there is no requirement to synchronize devices
### Exclude sync account from Multi-Factor authentication Conditional Access Policy

## 10. Configure Group-Based Licensing

# See Also
Links
