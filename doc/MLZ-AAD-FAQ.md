# Frequently asked Questions

## Contents
- [What is Microsoft Entra?](#what-is-microsoft-entra)
- [What is Azure AD?](#what-is-azure-active-directory)
- [What is an Azure AD Tenant?](#what-is-an-azure-ad-tenant)
- [How many Azure AD Tenants should my organization have?](#how-many-azure-ad-tenants-should-an-organization-have)
- [How do I manage Azure AD?](#how-do-i-manage-azure-ad)
- [How are permissions work in Azure?](#how-do-permissions-work-in-azure)
- [Can I share resources with users in a different Azure AD?](#can-i-share-resources-with-users-in-a-different-azure-ad)
- [Where is Azure AD Data Stored?](#where-is-azure-ad-data-stored)
- [What are the core components?](#what-are-the-core-components-of-azure-ad)

### What is Microsoft Entra?
Entra is the name for the family of Microsoft cloud identity and access management products.

There are currently 3 products in the Entra family:
1. Azure Active Directory - the Identity as a Service (IDaaS) platform for the Microsoft Cloud
2. Permissions Management - Cloud Infrastructure Entitlement Management solution for multi-cloud
3. Verified ID - Decentralized identity service

This document focuses on Azure AD, the identity platform for Microsoft Azure.

### What is Azure Active Directory?
Azure Active Directory (Azure AD) is an Identity as a Service (IDaaS) platform for the Microsoft cloud.

> **Reference**: [What is Azure AD?](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis)

### What is an Azure AD Tenant?
An Azure AD tenant is a logically separated instance of the AAD service that belongs to an organization.

### How many Azure AD Tenants should an organization have?
Microsoft recommends each organization use 1 Azure AD tenant for *both* Microsoft 365 services and pinned Azure Subscriptions. Because Azure AD is intended to be an enterprise identity solution, a single tenant offers the most cohesive experience for end users and administrators.

> **Reference**: Placeholder - Link to Tenant Types elsewhere in docs

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

### How do permissions work in Azure?
Placeholder

### Can I share resources with users in a different Azure AD?
Placeholder

### Where is Azure AD Data stored?
Azure AD is a non-regional service, meaning it does not run in specific Azure regions. Data is replicated across Azure AD service locations. Separate instances exist for Azure Government and Azure Commercial clouds.

> **Reference**: [Azure AD Architecture](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-architecture)

### What are the core components of Azure AD?
- Login Service (Security Token Service)
- Directory - users, groups, guests, application and resource identities
- Microsoft Graph API - managment interface for Azure and M365

