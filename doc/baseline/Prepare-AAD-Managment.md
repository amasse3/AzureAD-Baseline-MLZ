# Prepare to manage Azure AD
This page outlines the preliminary activities for configuring a new Azure AD tenant using the baseline in this repository.

## Preparation Checklist
- [ ] [1. Review the MLZ Deployment Patterns](#1-review-the-mlz-deployment-patterns)
- [ ] [2. Prepare a secure workstation for managing Azure AD](#2-prepare-a-secure-workstation-for-managing-azure-ad)
- [ ] [3. ⚙️ Run the script: PSTools](#3-⚙️-run-the-script-pstools)
- [ ] [4. Connect to Azure AD with MS Graph PowerShell](#4-connect-to-azure-ad-with-microsoft-graph-powershell)
- [ ] [5. Bookmark useful URLs](#5-bookmark-useful-urls)
- [ ] [6. Create and the first Global Administrator](#6-create-the-first-global-administrator)
- [ ] [7. License the first global administrator](#7-license-the-first-global-administrator)
- [ ] [8. Activate Privileged Identity Management](#8-activate-privileged-identity-management)

### 1. Review the MLZ Deployment Patterns
Review the [MLZ Deployment Patterns](./MLZ-Common-Patterns.md#decision-tree) and determine which type will be used for the MLZ tenant.

> **Warning**: The baseline configuration script should not be run in existing production Azure AD tenants, especially if M365 services are used. Settings applied in the baseline script may disrupt functionality and result in outage for end users.

### 2. Prepare a secure workstation for managing Azure AD
There are several client tools for managing Azure AD configuration. Make sure you are managing Azure and Azure AD from a secure workstation. Ensure these privileged access devices include the Azure management tools outlined in this section. 

> 📘 [Privileged Access Devices](https://docs.microsoft.com/en-us/security/compass/privileged-access-devices)

### 3. ⚙️ Run the script: PSTools
Install the PowerShell modules by running:
```PowerShell
Configure-AADTenantBaseline.ps1 -PSTools
```
The script will:
1. Install MS Graph PowerShell
2. Install Azure AD Preview (deprecated - included temporarily since it is used to configure CBA in the [Microsoft documentation](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#configure-certification-authorities-using-powershell))

#### Manual module installation
Use the commands below to install the tools manually. MLZ deployment will use additional tools listed here for convenience:
- [Azure Command-Line-Interface (CLI)](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [Azure Az PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps?view=azps-9.0.1)
  - `Install-Module Az`
- [Microsoft Graph PowerShell](https://docs.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)
  - `Install-Module Microsoft.Graph`
- [Azure AD PowerShell v2](https://learn.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0)
  - `Install-Module AzureADPreview`

#### Upgrading Microsoft.Graph.PowerShell
The Graph API and PowerShell modules are constantly updated to introduce new features. [Update](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0#updating-the-sdk) to the latest version:

```PowerShell
Update-Module Microsoft.Graph
```
### 4. Connect to Azure AD with Microsoft Graph PowerShell
Now we will ensure we can connect using MS Graph PowerShell. 

1. Open PowerShell and run the following command to connect to Azure AD:
- Azure AD Commercial
  - `Connect-MgGraph`
- Azure AD Government
  - `Connect-MgGraph -Environment UsGov`
- Azure AD Government - DoD
  - `Connect-MgGraph -Environment UsGovDoD`
2. Sign in with the first administrator account.
 
Verify you are connected to the correct tenant by running:
```PowerShell
Get-MgContext
```
### 5. Bookmark useful URLs
Bookmark the following portal pages in your web browser for easy access:
 - Entra Admin Center
   - Global: **https://entra.microsoft.com**
   - Government: **https://entra.microsoft.us**
 - Azure Portal
   - Global: **https://portal.azure.com**
   - Government: **https://portal.azure.us**

 - Microsoft Graph:
   - [Getting Started with Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/get-started?view=graph-powershell-beta)
   - [Microsoft Graph API Reference](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-beta)

### 6. Create the first Global Administrator
The first user in an Azure AD tenant will have super user / root access to the Azure AD tenant. This superuser permissions are assigned via the [Global Administrator](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator) built-in role.

In some cases the first user in Azure AD is a guest / external user. This can be verified by navigating to the Users blade in the Azure AD Portal and investigating the **User Type** field. 

If the signed in account is not a **member** type, follow the steps below to create a new "first user" in the Azure AD tenant:
1. [Add a new user in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/add-users-azure-active-directory#add-a-new-user)
   1. Record the username, including the domain suffix
   2. Note the temporary password
2. [Assign Global Administrator role to the new user](https://docs.microsoft.com/en-us/azure/active-directory/roles/manage-roles-portal)
3. Set Usage location value to **United States**. This is required for licensing.
4. Sign out of the portal or click the profile in the top right and select **sign in with a different account**
5. Enter the username and temporary password for the first member administrator account.
6. Change the password to a [strong password value](https://www.nist.gov/video/password-guidance-nist-0)
7. Register security information when prompted. This will secure the administrator account and provide a means for resetting the password.

> 📘 [Azure AD Setup Guide](https://go.microsoft.com/fwlink/p/?linkid=2183427)

### 7. License the first Global Administrator
1. Log in to the Azure Portal (https://portal.azure.com | https://portal.azure.us) as the first Global Administrator
2. Search for **Azure Active Directory** and click the Azure AD icon to open the AAD Administration "blade" in the Azure Portal.
3. Click **Licenses** and then **All Products**
4. Make sure you see the expected licenses.
5. Assign the first administrator an Azure AD Premium license.

> 📘 [Assign or remove licenses in the Azure AD Portal](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/license-users-groups?)

### 8. Activate Privileged Identity Management
While signed in to the Azure AD portal with the first administrator, perform the following:
1. Search for **Azure AD Privileged Identity Management**
2. Select **Azure AD Roles**
3. Follow the prompts to enable PIM on the tenant.

If you already have subscriptions associated with the tenant, follow the steps in the reference below to prepare PIM for Azure roles.

> 📘 [Prepare PIM for Azure roles](https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-getting-started#prepare-pim-for-azure-roles)

We are now ready to apply the scripted configuration.

## Next Step: [Apply the scripted configuration](/doc/AAD-Config-Baseline.md)

## See Also
- [Azure AD Baseline](/doc/AAD-Config-Baseline.md)
- [MLZ Identity Add-On Home](./../README.md)