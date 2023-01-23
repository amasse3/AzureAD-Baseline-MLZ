# Zero Trust with Azure AD
One of the first steps an organization can take in adopting zero trust principals is consolidating around a single cloud-based Identity as a Service (IdaaS) platform like Azure Active Directory. 

This section describes some next steps after establishing the tenant.

- [Choose an enterprise Azure AD](#choose-an-enterprise-azure-ad)
- [Connect applications to Azure AD](#connect-applications-to-azure-ad)
- [Use strong cloud-native authentication methods](#use-strong-authentication-methods)
- [Collaborate with Azure AD](#cross-tenant-access-policies-xtap-and-b2b-cross-cloud-collaboration)
- [Bring Device signals to Azure AD](#bring-device-signals-to-azure-ad)
- [Enable Defender for Cloud](#enable-defender-for-cloud)
- [Use Microsoft Sentinel](#use-microsoft-sentinel)
- [Least privilege with Azure AD](#least-privilege-with-azure-ad)

## Choose an Enterprise Azure AD
Before you can integrate applications and use Azure AD as a policy enforcement point for zero trust, you need to establish an enterprise Azure AD tenant.

For organizations with more than one Azure AD, review the [common patterns](/doc/MLZ-Common-Patterns.md) to determine which tenant contains the licensed end-users for the application. This will be the "enterprise" Azure AD where we will onboard applications and assign for user access.

> 📘 [Choosing your identity authority](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-plan-identity#choosing-your-identity-authority)

## Connect applications to Azure AD
This section describes steps to integrate applications with Azure AD.

- [ ] [Review Identity for MLZ Applications](#review-mlz-application-identity)
- [ ] [Consolidate around an Azure AD tenant](#consolidate-around-an-azure-ad-tenant)
- [ ] [Add Enterprise Applications to Azure AD](#add-enterprise-applications-to-azure-ad)
- [ ] [Develop New Applications for Azure AD](#develop-new-applications-for-azure-ad)
- [ ] [Add On-Premises Applications to Azure AD](#add-on-premises-applications-to-azure-ad)
- [ ] [Protect APIs with Azure AD](#protect-apis-with-azure-ad)
- [ ] [Use Defender for Cloud Apps](#use-defender-for-cloud-apps)

### Review MLZ-Application-Identity
Detailed guidance around identity for MLZ applications can be found in the referenced document below.

> 📘 [Identity for MLZ Applications](../MLZ-Application-Identity.md)

### Consolidate around an Azure AD tenant
Standardizing around a common identity platform often requires changes to IT policy mandating new applications (procured and developed in house) targets Azure Active Directory. The Azure AD tenant containing all users in the organization, especially if it is used for M365, is a good choice because the same zero trust access and device management policies for M365 can be re-used for any application in the organization.

> 💡 **Recommendation**: 
> - Zero Trust policies for application identity should be drafted and implemented as soon as Azure Active Directory is ready.
> - Applications should be migrated from on-premises based federation services like Active Directory Federation Services.
> - Integrate as many signals as possible (device, user, application, context, authentication strength, risk) into Azure AD Conditional Access.

> 📘 [Planning identity for Azure Government applications](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-plan-identity)\
> 📘 [Microsoft Zero Trust Resources](https://www.microsoft.com/en-us/security/business/zero-trust)

#### Add Enterprise Applications to Azure AD
Enterprise Apps are application resources assigned to users in your Azure Active Directory. Add applications from the Azure AD Gallery or add non-gallery apps that use SAML, WS-Federation, OpenID Connect, or OAuth protocols.

> 📘 **Reference**: [Overview of the Azure Active Directory application gallery](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/overview-application-gallery)

#### Develop new applications for Azure AD
Develop new applications and APIs to use Azure AD for authentication and authorization.

> 📘 [Microsoft Authentication Library (MSAL)](https://learn.microsoft.com/en-us/azure/active-directory/develop/msal-overview)\
> 📘 [Security best practices for application properties in Azure Active Directory](https://learn.microsoft.com/en-us/azure/active-directory/develop/security-best-practices-for-app-registration)\
> 📘 [Microsoft Identity Platform code samples](https://learn.microsoft.com/en-us/azure/active-directory/develop/sample-v2-code)

### Add on-premises applications to Azure AD
Azure AD Application Proxy is an on-premises agent and cloud service that [securely publishes](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-security) on-premises applications that use [Kerberos-based](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-configure-single-sign-on-with-kcd), [password-based](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-configure-single-sign-on-password-vaulting), [SAML](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-configure-single-sign-on-on-premises-apps), and [header-based](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-configure-single-sign-on-with-headers) authentication protocols. This feature allows organizations to gain [single sign-on](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-config-sso-how-to) and zero trust security controls for existing applications, without expensive network appliances or VPNs. Remote access to on-premises applications is achieved without code change to applications or opening inbound ports for the external firewall.

> 💡 **Recommendation**:
> - [Deploy Azure AD Application Proxy connectors](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-deployment-plan) to every Active Directory domain containing users or applications that must be published externally. 
> - If a [Secure Hybrid Access Partner](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/secure-hybrid-access#secure-hybrid-access-through-azure-ad-partner-integrations) solution is already in use for the organization, integrate the solution with Azure Active Directory.

> 📘 [Remote access to on-premises applications through Azure AD Application Proxy](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy)\
> 📘 [Optimize traffic flow with Azure Active Directory Application Proxy](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/application-proxy-network-topology)\
> 📘 [Security Benefits for Azure AD Application Proxy](https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/what-is-application-proxy#security-benefits)\
> 📘 [Secure Hybrid Access Partner Integrations](https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/secure-hybrid-access#secure-hybrid-access-through-azure-ad-partner-integrations)

### Protect APIs with Azure AD

Develop web APIs that use Azure AD, leveraging the [Web API code samples](https://learn.microsoft.com/en-us/azure/active-directory/develop/sample-v2-code#web-api).

API Management can protect existing APIs, even ones that don't use Azure AD, by adding OAuth 2.0 Authorization policy for API access.

> 📘 [Protect an API in Azure API Management](https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-protect-backend-with-aad)

### Use Defender for Cloud Apps

Defender for Cloud Apps is Microsoft's Cloud Access Security Broker service, part of M365 E5. This service can monitor and limit sessions to web applications, and flag risky OAuth apps.

Defender for Cloud Apps integrates with Conditional Access to broker sessions to protected applications. Session restrictions can limit downloads for content matching defined policies. It can even stack with Azure AD Application Proxy (the session between client and AAD App Proxy Service is brokered with Defender for Cloud Apps) to protect web sessions with legacy on-premises applications.

> 📘 [Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/what-is-defender-for-cloud-apps)

## Use strong authentication methods
Authentication Strengths is a feature that allows a tenant administrator to label authenticators (and combinations) according to the strength of the credential. Out-of-Box settings include:
- Multifactor Authentication
- Passwordless Multifactor Authentication
- Phishing-Resistant MFA

Additional strengths, like [NIST Authenticator Assurance Levels](https://learn.microsoft.com/en-us/azure/active-directory/standards/nist-overview), can be configured by an administrator. 

Organizations should strongly consider Authentication Strength (and its integration with [Cross-Tenant Access Policies](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/cross-tenant-access-overview)) as they look to meet [requirements outlined in Memorandum 22-09](https://learn.microsoft.com/en-us/azure/active-directory/standards/memo-22-09-multi-factor-authentication).

> 💡 **Recommendation**: Configure desired MFA strength for baseline access and update the 'All Users, All Apps, MFA' Conditional Access Policy to require Authentication Strength.

> 📘 [Configure Authentication Strength](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-strengths)

## Collaborate with Azure AD
Azure AD makes it easy to collaborate with other organizations the also own Azure AD. This collaboration is facilitated by two complementary features:
- [External Identities (B2B)](#external-identities)
- [Cross-Tenant Access Policies](#cross-tenant-access-policies)

### External Identities
Azure AD B2B collaboration is a feature within External Identities that lets you invite guest users with an email invitation. Guest users use their existing account to sign-in to their home tenant, while you manage their access to your resources.
- The partner users their own identities and credentials
- you don't need to manage external accounts or passwords
- you don't need to sync or manage account lifecycle

> 📘 [Azure AD B2B Collaboration](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/what-is-b2b)

### Cross-Tenant Access Policies
Cross-tenant access policies (XTAP) let an administrator configure "trust" relationships with other Azure AD tenants. This allows trusting device compliance and MFA claims for external users for a more secure and productive collaboration experience. Similar settings can be configured between Azure AD Commercial tenant and an Azure AD Government tenant. Cross-cloud collaboration requires setting Inbound and Outbound XTAP settings on the respective tenants.

Integrate authentication strength with Cross-Tenant Access policies.

> 📘 [Cross-tenant access with Azure AD external identities](https://learn.microsoft.com/en-us/azure/active-directory/external-identities/cross-tenant-access-overview)

## Bring Device signals to Azure AD
Connecting devices to Azure AD both improves end-user experience and enhances security. 

Joining devices to Azure Active Directory (also using Hybrid Azure AD Join) lets the device obtain a Primary Refresh Token (PRT) to facilitate single sign-on across services in the Microsoft cloud, including all non-Microsoft applications that use Azure AD as an identity provider. Registering mobile devices provides the ability to use strong passwordless authentication using Authenticator App number matching.

Intune management enables the use of device compliance rules within Conditional Access. Microsoft Defender for Endpoint can ensure managed devices are healthy and clean.

> 📘 [Secure Endpoints with Zero Trust](https://learn.microsoft.com/en-us/security/zero-trust/deploy/endpoints)

## Secure VM Management Interfaces
Gone are the days where admins need to use RDP and SSH to connect directly to virtual machines. Azure includes tools like [Azure Bastion](https://learn.microsoft.com/en-us/azure/bastion/bastion-overview), Azure Virtual Desktop, [Windows Admin Center](https://learn.microsoft.com/en-us/windows-server/manage/windows-admin-center/azure/manage-vm), [Windows](https://learn.microsoft.com/en-us/azure/active-directory/devices/howto-vm-sign-in-azure-ad-windows) and [Linux Login (SSH)](https://learn.microsoft.com/en-us/azure/active-directory/devices/howto-vm-sign-in-azure-ad-linux) with Azure AD identity and more.

Use [Defender for Cloud just-in-time VM access](https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage) for scenarios where direct VM access is required.

> 📘 [Azure Security Compass - Intermediaries](https://learn.microsoft.com/en-us/security/compass/privileged-access-intermediaries)

## Enable Defender for Cloud
Defender for Cloud enables advanced security features for Virtual Machines, App Services, Databases, Storrage, Containers, Key Vault, ARM, DNS, and more. Enabling these plans with autoprovisioning configure diagnostics settings and monitoring agents via Azure Policy.

> 📘 [Quickstart: Enable enhanced security features in Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security)

### Protect on-premises servers
Defender for Cloud is not just for Azure resources.

Servers on-premises or running in other clouds can be onboarded to Defender for Cloud through deployment of Azure Arc. This feature lets Defender for Cloud provide security recommendations, collect security events, and alert on misconfigurations and suspicious activity, just like it does for Azure VMs.

Arc can enable zero trust access to on-premises Linux servers using ephemeral SSH keys generated by Azure AD. No need to distribute keys, administrators assigned Virtual Machine Login roles can sign in with their Azure AD account. To learn more, see [SSH access to Azure Arc-enabled servers](https://learn.microsoft.com/en-us/azure/azure-arc/servers/ssh-arc-overview?tabs=azure-cli).

> 📘 [Azure Arc Overview](https://learn.microsoft.com/en-us/azure/azure-arc/overview)

## Use Microsoft Sentinel
Configure data connectors to ingest all security-related event data into Azure Sentinel. Start with the first party connectors used for MLZ:
- Azure AD Sign in and Audit Logs
- Azure AD Identity Protection
- Azure Resource Management
- Resource-specific logs from Key Vault, Storage Accounts, Firewalls, etc.
- Security Events via AMA (Windows)
- CEF logs via AMA (Linux)

Be sure to review relevant alerts and workbooks for each connector.

> 📘 [Quickstart: Onboard Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/quickstart-onboard)

## Least Privilege with Azure AD
Administrative Units provide a mechanism for scoping Azure AD roles to a particular set of resources. AUs can be scoped to users, groups, and devices. Resources can be assigned to an AU manually, or the AU can be configured with dynamic rules. Refer to the documentation below to learn about AUs and their use cases for scoping / delegating administration in Azure AD.

> **Note**: Not all out-of-box Azure AD roles can be scoped to an AU. Review the [limitations](https://learn.microsoft.com/en-us/azure/active-directory/roles/administrative-units#groups) for Administrative Units.

> 📘 [Administrative Units (AUs)](https://learn.microsoft.com/en-us/azure/active-directory/roles/administrative-units)

### Identity governance
Identity Governance defines a set of capabilities provided by Azure AD Premium P2 licensing. The main components are:
- [Entitlements Management](#entitlements-management)
- [Access Reviews](#access-reviews)

#### Entitlements Managmement
Learn about Entitlements Management in Azure AD and understand how identity governance can help with permissions and application access.

> 📘 [Entitlements Management](https://learn.microsoft.com/en-us/azure/active-directory/governance/entitlement-management-overview)

#### Access Reviews
Learn about Azure AD Access Reviews and understand how access granted to memebers and guests can be periodically reviewed to maintain least-privilege. The baseline configuration does not configure Access Reviews.

> 💡 **Recommendation**: Set up periodic access reviews for membership of Core MLZ and Mission RBAC groups, Privileged Access groups, and directory roles like Global Administrator and Application Administrator.

> 📘 [Access Reviews](https://learn.microsoft.com/en-us/azure/active-directory/governance/access-reviews-overview)

#### Connected Orgs
Guest user lifecycle can be managed automatically using Entitlements Management when a Connected Organization is established for a partner organization. Review the capability and establish a connected organization with partner organizations with users that will be invited for collaboration and application access.

> 📘 [Connected Organizations in Entitlements Management](https://learn.microsoft.com/en-us/azure/active-directory/governance/entitlement-management-organization)

### Entra Permissions Management
Entra permissions management helps discover, remediate, and monitor permission assignment and usage across Azure, Amazon Web Services (AWS), and Google Cloud Platform (GCP). Using a Permission Creep Index (PCI), Permissions Managemnet can track privileges over time and create custom RBAC roles to reduce privileges for what admins actually need. Check out the reference below to learn more.

> 📘 [What's Permissions Management](https://learn.microsoft.com/en-us/azure/active-directory/cloud-infrastructure-entitlement-management/overview)

</p>
</details>

## See Also
- [Azure AD Baseline](/doc/AAD-Config-Baseline.md)
- [MLZ Application Identity](/doc/MLZ-Application-Identity.md)
- [MLZ Identity Add-On Home](./../README.md)