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
- Azure AD Commercial
  - Entra Portal: https://entra.microsoft.com
  - Azure Portal: https://portal.azure.com
  - Microsoft Graph PowerShell
  - Microsoft Graph Explorer
  - Postman
- Azure AD Government
  - Azure Portal: https://portal.azure.us

## Where is Azure AD Data stored?
Azure AD is a non-regional service, meaning it does not run in specific Azure regions. Data is replicated across Azure AD service locations. Separate instances exist for Azure Government and Azure Commercial clouds.

Reference: [Azure AD Architecture](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-architecture)

## What are the core components of Azure AD?
- Login Service / Security Token Service (login.microsoftonline.com | login.microsoftonline.us)
- Directory Service - users, groups, guests, application and system identities
- Microsoft Graph API - managment interface for Azure and M365

## What is an Azure AD Tenant?

## Standalone Tenant vs Enterprise Tenant

# New Azure AD Tenants
If MLZ is deployed in a new Azure AD tenant
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
