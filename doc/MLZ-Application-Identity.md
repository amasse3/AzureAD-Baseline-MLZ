# Identity for Mission Landing Zone Applications
Placeholder Content. Will describe how applications running in Azure subscriptions will use the Azure AD enterprise tenant for identity.

## Table of Contents
- [Understanding Azure AD Identities](#understanding-azure-ad-identities)
- [Azure AD tenant types](#azure-ad-tenant-types)
- [Enterprise Azure AD tenant](#enterprise-azure-ad-tenant)
- [Application Types](#application-types)
  - Modern Apps
  - Legacy Apps
- Zero Trust
  - Policy Enforcement Point
  - Conditional Access
-- Azure AD for application identity
  - Modern Apps
  - Legacy Apps
- Azure AD Application Proxy and Secure Hybrid Access Partners
- B2B guest identities
- Common Scenarios
  - 1. MLZ subscriptions attached to a separate Azure Platform (MLZ) tenant
  - 2. MLZ subscriptions attached to an Enterprise tenant
  - 3. B2B guests and MLZ
- See Also

## Understanding Azure AD Identities

## Azure AD tenant types

## Enterprise Azure AD tenant

## Application Types

### Modern Apps

### Legacy Apps

## Active Directory Domain Services in Azure

## Azure AD Application Proxy

### MLZ Subscriptions attached to Enterprise Azure AD tenant
An organization's Azure AD that contains all users and licenses is an **Enterprise Azure AD Tenant**. These tenants are often configured for hybrid identity with users and groups synchronized from an on-Premises Active Directory enviornment using Azure AD Connect, or provisioned into Azure AD directly from a support HR SaaS Provider. All non-Microsoft applications, including applications running on-premises, in other clouds, SaaS apps, or Azure subscriptions pinned to *other* non-Enterprise AAD should use the **Enterprise Azure AD** for identity.
- **Modern Applications** using OpenIDConnect, OAuth, SAML, WS-Federation can use Azure AD identity directly when onboarded as an [Enterprise Application](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/add-application-portal).
- **Legacy Applications** using Kerberos (Windows Authentication), NTLM, Header-Based authentication can use Azure AD identities indirectly via [Azure AD Application Proxy](https://docs.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy) or a [Secure Hybrid Access Partner](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/secure-hybrid-access) acting as a broker.

> **Important**:  
Applications hosted in MLZ should use the **Enterprise Azure AD** tenant for application identity, directly or via Azure AD Application Proxy / broker. This means applications relying on Active Directory Domain Services need AD DS extended to the MLZ Azure environment through extending existing Active Directory domain or resource forest in Azure. 
In either case, Azure AD Application proxy connectors are recommended to broker access for the Enterprise AAD identities. This allows publishing applications securely without relying on costly network appliances (application firewalls and VPN gateways), while bringing the power of Azure AD Conditional Access to enforce zero trust policies based on authentication context, session details, device health, and identity risk.

### MLZ Subscriptions attached to a separate, standalone Azure Platform tenant
In some cases, customers choose to use a separate Azure AD where their subscriptions are managed. This configuration introduces complexity for Azure services that are accessed by Azure AD identities, since users either need A) Separate Azure AD accounts and licenses in each tenant, B) Rely on Azure AD B2B Guests and switching tenant context, C) configuring light house for all Azure resource access.

## See Also
Relevant links