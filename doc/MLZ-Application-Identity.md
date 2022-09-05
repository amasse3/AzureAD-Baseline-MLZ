# Identity for Mission Landing Zone Applications
This document contains identity guidance for applications running in Mission Landing Zone.



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

## Azure AD - the everything identity platform
Azure Active Directory is not just the Microsoft cloud Identity as a Service (IDaaS) platform, but the everything identity platform for all enterprise applications.

While AAD is the identity platform for Azure and M365, it also directly supports identity for modern applications that implement industry-standard protocols. Azure AD Application Proxy and Secure Hybrid Access partner integrations allow Azure AD to also provide identity services to legacy apps on-premises, in Azure, and in other clouds like AWS or GCP.

## Understanding Azure AD Identities

## Azure AD tenant types

|Type|Users|Identities|Services|
|----|-----|-------------|--------|
|Enterprise|All employees, contractors, guests|hybrid (synced)|Microsoft 365, Azure, enterprise apps|
|Standalone Azure Platform|Azure admins and developers|cloud-only|Azure subscriptions|

## Enterprise Azure AD tenant
An organization's Azure AD that contains all users and licenses is an **Enterprise Azure AD Tenant**. These tenants are often configured for hybrid identity with users and groups synchronized from an on-Premises Active Directory enviornment using Azure AD Connect, or provisioned into Azure AD directly from a support HR SaaS Provider. All non-Microsoft applications, including applications running on-premises, in other clouds, SaaS apps, or Azure subscriptions pinned to *other* non-Enterprise AAD should use the **Enterprise Azure AD** for identity.

## The MyApps Portal
[My Apps](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/myapps-overview) is a customizable portal that offers a launchpad for accessing enterprise applications integrated with Azure AD.

## Application Types
Applications used within the enterprise should use standard protocols for authentication and authorization that offer integration with most identity provider systems. To simplify the conversation, apps can be categorized based on the type of identity protocols they use. 
- [Modern applications](#legacy-apps)
- [Legacy applications](#modern-apps)

### Modern Apps
**Modern applications** use identity protocols that build on top of Hypertext Transfer Protocol and TLS-secured communications over the internet on port 443.

Authentication to these apps uses a passive client, like a web browser, to perform sign-in with an identity provider that is also accessible over the internet. After successful authentication to the identity provider, the identity provider sends an HTTP response with 302-redirect back to the application sign-in endpoint with a cryptographically signed (and sometimes encrypted) token. Once the application verifies the token, the application sign-in is complete.

Common protocols for modern apps include [OpenID-Connect](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/auth-oidc), [OAuth 2.0](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/auth-oauth2), [SAML](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/auth-saml), [WS-Federation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adfsod/204de335-ea34-4f9b-ae73-8b7d4c8152d1).

**Example Modern App**
- Realm: internet
- Protocol: OpenID Connect
- Token: JWT
- Authorization: Role claim
- SDK: MS Authentication Library (MSAL)

### Legacy Apps
**Legacy applications** use protocols intended for client-server authentication within a trusted realm such as a corporate network. Authentication happens using credentials supplied directly to the application. These applications often use [Kerberos](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview) ([Windows Authentication](https://docs.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview)), [NTLM](https://docs.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview), [LDAP](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/auth-ldap), or [header-based](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/auth-header-based) authentication.

**Example Legacy App**
- Realm: Active Directory (Kerberos Domain)
- Protocol: Kerberos
- Token: Kerberos ticket
- Authorization: Privileged Attribute Certificate (PAC)
- SDK: Windows Identity Framework

## Azure AD and on-premises applications

> **Note**: The location of the application hosting infrastructure has no bearing on whether or not Azure AD can be an identity provider. Azure AD can be used for modern apps as long as authenticating clients have internet access and a network path to the application. 
> Azure AD can be used for legacy apps as long as Azure AD Application Proxy or Secure Hybrid Access Partner broker is used.

> **Reference**: [Secure Hybrid Access with Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/secure-hybrid-access)

### Azure AD Application Proxy
### Secure Hybrid Access Partners
### Active Directory Domain Services in Azure

## Collaboration with Azure AD
### B2B Collaboration
### Identity broker

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