# MLZ-Identity-AzureADSetup
This repository is working guidance for configuring Azure AD for Azure Mission Landing Zone.

[toc]

# Level Setting

## What is Microsoft Entra?
Entra is the name for the family of Microsoft cloud identity and access management products.

There are 3 core components:
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
  - Microsoft Graph PowerShell: Connect-MgGraph
  - Microsoft Graph Explorer: https://developer.microsoft.com/en-us/graph/graph-explorer
  - Postman: https://graph.microsoft.com
- Azure AD Government and DoD
  - Azure Portal: https://portal.azure.us
  - Microsoft Graph PowerShell: Connect-MgGraph -Environment UsGov | UsGovDoD
  - Postman: https://graph.microsoft.us | https://dod-graph.microsoft.us

## Where is Azure AD Data stored?
Azure AD is a non-regional service, meaning it does not run in specific Azure regions. Data is replicated across Azure AD service locations. Separate instances exist for Azure Government and Azure Commercial clouds.

Reference: [Azure AD Architecture](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-architecture)

## What are the core components of Azure AD?
- Login Service / Security Token Service (login.microsoftonline.com | login.microsoftonline.us)
- Directory Service - users, groups, guests, application and system identities
- Microsoft Graph API - managment interface for Azure and M365

## What is an Azure AD Tenant?
Azure Active Directory (AAD) is the identity platform for Microsoft cloud services, including Office 365 and Azure. An Azure AD tenant is a logically separated instance of the AAD service that belongs to an organization. 

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

## Manage Azure AD from a secure workstation
### Install Azure CLI
### Install MS Graph PowerShell

## Create Emergency Access Accounts
### Azure AD Free or Premium P1
### Azure AD Premium P2

## Enroll Global Admins with Azure MFA
### Authenticator App
### FIDO2 Security Key

## Enforce Multi-Factor Authentication
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
