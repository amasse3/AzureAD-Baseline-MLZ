# About the baseline configuration
The Azure AD tenant baseline is a PowerShell script ([Configure-AADTenantBaseline.ps1](/src/Configure-AADTenantBaseline.ps1)) that applies settings using Microsoft Graph PowerShell based on configuration defintion stored in a JSON-formatted parameters file.

The script itself includes some features to simplify the deployment including:
- Parameter switches for running individual sections
- Loading modules and connecting to MS Graph with required scope within each section
- Checking for existing resources before creating duplicates
- Parameters file where individual settings can be adjusted
- Load the default parameters file from the relative path if no ParametersJSON argument is passed

## Table of Contents
 - [Documentation layout](#documentation-layout)
 - [Asset inventory](#asset-inventory)
 - [Requirements](#requirements)

## Documentation layout
Each section in [Scripted Configuration](#scripted-configuration) is broken down by the parameter switch for the configuration script. Generally, each section follows this format:
- Brief overview of the configuration section
- Table of contents
- Configuration Steps
- Related recommendations and references

🗒️Modify Configuration: Steps for manually editing parameter or configuration files use 🗒️.

⚙️ Run the script: Steps for running the configuration step use Steps use ⚙️.

To simplify navigation, detailed content for each section is hidden by default. Use the **Show Content** buttons to display this information.
<details><summary><b>Show Content</b></summary>
<p>
Wow! That's a lot of content!
</p>
</details>

> **Note** : Notes will look like this

> 💡**Recommendations**: will include the light bulb emoji

> **Warning**: Priority notes, including ones with security implication, will be displayed like this.

> 📘 References will use the blue book emoji

Checklist format is used to draw attention to required steps.
- [ ] Do this first
- [ ] Then this

To get started, continue to the [requirements](#requirements) section.

## Asset Inventory
|Asset|Description|Format|Location|
|-----|-----------|------|--------|
|This Document|Deployment aid for scripted configuration, manual configuration, and next steps.|Text (Markdown)|N/A|
|mlz-aad-parameters.json|Script parameters|JSON|[mlz-aad-parameters.json](/src/mlz-aad-parameters.json)|
|MLZ-Admin-List.csv|File for automating account creation for named administrators.|CSV|[MLZ-Admin-List.csv](/src/MLZ-Admin-List.csv)|
|Configure-AADTenantBaseline.ps1|Main deployment script|PowerShell (\*.ps1)|[Configure-AADTenantBaseline.ps1](/src/Configure-AADTenantBaseline.ps1)|

### MLZ-AAD-Parameters.json
This file represents the configuration that will be applied when running the baseline. The JSON-formatting parameters file can be found [here](/src/mlz-aad-parameters.json).

At minimum, modify the **GlobalParameterSet** to match the environment before running the script.

The **mlz-aad-parameters.json** file must be read into a variable and passed to the `ParametersJson` parameter of the **Configure-AADTenantBaseline.ps1** script. 

|Parameter|Description|DefaultValue|
|---------|-----------|------------|
|Environment|Azure Environment for Microsoft Graph PowerShell. Values should match "Global","USGov", or "USGovDOD"|Global|
|EAGroupName|Name of the group containing Emergency Access accounts. Used to exclude these accounts from Conditional Access policies.|Emergency Access Accounts|
|PWDLength|Length of random passwords set by the deployment script.|16|
|MissionAUs|Array of names for Administrative Units. Applicable if using delegated administration model.|[Alpha,Bravo,Charlie]|
|LicenseSKUPartNumber|License SKU for AAD P2 / E5 <br>Find using get-mgsubscribedsku|E5 Developer GUID<br><b>must be changed\*</b>|

\*To find the LicenseSKUPartNumber, use MS Graph to check the first licensed user:

```PowerShell
Get-MgUserLicenseDetail -UserId $(Get-MgContext).Account | Format-List
```
### Using the script
The script will look for `mlz-aad-parameters.json` in the current path. If you renamed the file or want to load it from a different path, import it into the PowerShell session and supply using the command below:

```PowerShell
$mlzparms = $(get-content mlz-aad-parameters.json) | convertFrom-Json
```
**All Baseline Configurations**
To apply all configuration sections in the baseline, use the `-All` switch along with the parameters.

```PowerShell
.\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparams -All

```
> **Note** : Before applying a setting, the script will check if the settings / objects already exist.

**Apply individual configurations**
To apply individual sections, include one or more switch parameter.

```PowerShell
.\Configure-AADTenantBaseline.ps1 -ParametersJson $mlzparams -EmergencyAccess -AuthNMethods -ConditionalAccess -TenantPolicies
```

## Requirements
- [ ] New or existing (non-production) Azure Active Directory tenant
- [ ] Azure AD account with Global Administrator role
- [ ] Azure AD Premium P2 licenses*
- [ ] A trusted configuration workstation with
    - rights to install PowerShell module for MS Graph
    - DNS resolution and traffic routing for the Azure AD logon URLs
    - CDN and logon URLs in trusted sites
- [ ] Microsoft Graph PowerShell

> **Note**: \* If Azure AD Premium licenses are not available, only the following settings can be applied:
> - EmergencyAccess (assigning Global Admin via PIM will fail, add the role assignment manually)
> - AuthNMethods
> - NamedAccounts (licensing step will fail)
> - TenantPolicies
>
> If Azure AD Premium is not available, Conditional Access Policies cannot be used. [Turn on Security Defaults](https://learn.microsoft.com/en-us/microsoft-365/business-premium/m365bp-conditional-access?view=o365-worldwide#security-defaults) and follow guidance to [Protect your admin accounts](https://learn.microsoft.com/en-us/microsoft-365/business-premium/m365bp-protect-admin-accounts?view=o365-worldwide).

> 📘 **Reference**: [Office 365 IP Address and URL web service](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service?view=o365-worldwide)

## See Also
- [Azure AD Baseline](/doc/AAD-Config-Baseline.md)
- [MLZ Application Identity](/doc/MLZ-Application-Identity.md)
- [MLZ Identity Add-On Home](./../README.md)