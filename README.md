# MLZ-Identity-AzureADSetup
This repository is working guidance for configuring Azure AD for Azure Mission Landing Zone.
[toc]

# Level Setting

## What is Azure Active Directory?
Azure Active Directory is an Identity as a Service (IDaaS) platform for the Microsoft cloud. An Azure AD supports Azure, Microsoft 365, and can be used for nearly any enterprise application.

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
