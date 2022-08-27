# MLZ-Identity-AzureADSetup
This repository is working guidance for configuring Azure AD for Azure Mission Landing Zone. Like MLZ, this is a highly opinionated document for Azure AD security.

[toc]

# Level Setting

## What is Microsoft Entra?
Entra is the name for the family of Microsoft cloud identity and access management products.

There are currently 3 separate products in the Entra family:
1. Azure Active Directory - the Identity as a Service (IDaaS) platform for the Microsoft Cloud
2. Permissions Management - Cloud Infrastructure Entitlement Management solution for multi-cloud
3. Verified ID - Decentralized identity service

This document focuses on Azure AD, the identity platform for Microsoft Azure.

## What is Azure Active Directory?
Azure Active Directory (Azure AD) is an Identity as a Service (IDaaS) platform for the Microsoft cloud.

Reference: [What is Azure AD?](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis)

## How do I manage Azure AD?
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

## Where is Azure AD Data stored?
Azure AD is a non-regional service, meaning it does not run in specific Azure regions. Data is replicated across Azure AD service locations. Separate instances exist for Azure Government and Azure Commercial clouds.

Reference: [Azure AD Architecture](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-architecture)

## What are the core components of Azure AD?
- Login Service / Security Token Service (login.microsoftonline.com | login.microsoftonline.us)
- Directory Service - users, groups, guests, application and system identities
- Microsoft Graph API - managment interface for Azure and M365

## What is an Azure AD Tenant?
An Azure AD tenant is a logically separated instance of the AAD service that belongs to an organization.

## How many Azure AD Tenants should an organization have?
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

# New Azure AD Tenants
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

> **Note**:
Sometimes when custom domains are added to an Azure AD tenant, users who signed up for trial Microsoft services with their organization email address will appear in the tenant once the domain is verified. Do not be alarmed by this. To verify no other users have privileges within the tenant, [view the Azure AD role members](https://docs.microsoft.com/en-us/azure/active-directory/roles/view-assignments).

### Azure AD Free or Premium P1

Placeholder Script to create accounts and assign Global Administrator role

### Azure AD Premium P2

Placeholder Script to create accounts and assign Global Administrator role with PIM

## Enroll Administrators in Multi-Factor Authentication
All named administrator accounts (not shared emergency access accounts) should register for multi-factor authentication. Security Keys are the recommended method.
### Bad: SMS or TwoWayPhone
Some MFA is better than no MFA, but phoe-based MFA is the weakest option available. SMS is especially egregious since they are susceptable to SIM swapping attacks.
### Good: Authenticator App TOTP Code or Push notification
These methods are not phishing-resistant or passwordless. In either case, a password is used, followed by an Azure MFA prompt.
### Better: Passwordless Phone Sign-In on Registered Device
Passwordless, but not phishing-resistant. This required registration of an iOS or Android mobile device with the Azure AD tenant.
### Best: Phishing-Resistant MFA FIDO2 Security Key or Azure AD native Certificate-Based Authentication (CBA)
- FIDO2 Security Key
- Certificate-Based Authentication

> **Note:**
Microsoft Authenticator App is considered phishing-resistant when deployed to a managed mobile device. Since this guide assumes a new tenant, it assumes Microsoft Endpoint Manager is not configured to manage mobile devices.

## Enforce Multi-Factor Authentication and disable Legacy Authentication Protocols

### Azure AD Free - Turn on Security Defaults
### Azure AD Premium P1 - Create Conditional Access Policies
script
### Azure AD Premium P2 - Configure Risk-Based Conditional Access Policies
script
## Configure User Settings
script
## Configure External Collaboration Settings
script
## Configure Azure AD Native Certificate-Based Authentication
### Upload Certificates
### Configure CertificateBasedAuthentication Settings
### Preview: Open Support Ticket for CRL limit increase

## Optional: Configure Hybrid Identity
### Azure AD Connect v2
### Azure AD Connect Cloud Sync
Note: Only if there is no requirement to synchronize devices
### Exclude sync account from Multi-Factor authentication Conditional Access Policy

# Existing Azure AD Tenant
## 
