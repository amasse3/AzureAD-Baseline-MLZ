# MLZ-Identity-AzureADSetup
This repository is working guidance for configuring Azure AD for Azure Mission Landing Zone (MLZ) deployments. Like MLZ, this set of documents contains highly opinionated guidance for Azure AD security. Settings recommended within this repository docs and sample scripts are more restrictive than some default Azure AD tenant settings and should be evaluated to ensure user access and guest collaboration scenarios will function as desired.

**Settings and recommendations provided here are a starting point for standing up a new Azure AD tenant for MLZ**

Guidance contained within this repository is not intended to supplant recommendations from [Microsoft Docs](https://learn.microsoft.com/) or the official [Entra (Azure AD) Blog](https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/bg-p/Identity).

Furthermore, this content is not intended to replace or contradict guidance provided by Microsoft professional services (MCS), Fast Track for Azure (FTA), Customer Experience Program (CXP) architects and program managers, or Cloud Solution Architects (CSA). Zero trust capabilities in the Microsoft cloud are constantly evolving, so it is likely this documentation will not account for the latest generally available and preview features.

> **Note**: Always defer to Microsoft official documentation located at https://learn.microsoft.com/.

> **Warning**: Sample scripts in this repository are not supported under any Microsoft support program or service.
> Scripts are provided AS IS without warranty of any kind. All warranties including, without limitation,
> any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising
> out of the use of sample scripts or configuration documentation remains with you. In no event shall Microsoft,
> its authors, or anyone else involved in the creation, produciton, or delivery of this content be liable
> for any damages whatsoever (including, without limitation, damages for loss of business profits, business 
> interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
> inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
> possibility of such damages.

Now that we have the warnings out of the way, we can get started with the MLZ identity add-on.  Use the links below to navigate the MLZ Identity Add-On components.

## [Azure AD Configuration Baseline](doc/AAD-Config-Baseline.md)

This page walks through steps to set up a new Azure AD tenant using a configuration baseline applied with Microsoft Graph PowerShell.

Azure AD and cloud identity is critical to enabling zero trust outcomes. While configuring Azure AD is the first step, using and adopting it is far more important. For this reason, the second part of the baseline is dedicated to [Zero Trust with Azure AD](doc/AAD-Config-Baseline.md/#zero-trust-with-azure-ad).

## Supporting Content

### [Common Deployment Patterns](/doc/MLZ-Common-Patterns.md)
This page includes 3 common deployment types for MLZ customers, especially valuable for organizations with multiple Azure AD tenants.

### [Identity for MLZ Applications](doc/MLZ-Application-Identity.md)
Application identity can be complex, especially in multi-tenant organizations. This page aims to simplify scenarios by application type and audience.

### [Permissions in Azure and Azure AD](/doc/AAD-Permissions-Management.md)
This page describes Azure AD and Azure RBAC permissions, approaches to delegated and centralized management.

### Other Pages
- [DOD CAC Authentication Setup](doc/AAD-CertificateBasedAuthentication-DODPKI.md)
- [Azure AD FAQ](/doc/MLZ-AAD-FAQ.md)  

## See Also
[Mission Landing Zone](https://github.com/azure/missionlz)