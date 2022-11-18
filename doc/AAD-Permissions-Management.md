# Permissions in Azure and Azure AD
Document to describe roles relevant to Mission Landing Zone deployment and management.

## Table of Contents
- Placeholder
- Placeholder

## Permissions Types
There are slightly different permissions models for various Microsoft cloud services. The table below describes the permissions for setting up and managing Mission Landing Zone environments. Permissions for individual M365 services are beyond the scope of this document.

| Type | Assigned To | Exclusions | Scope |
| Azure AD Permission | All security principals (users, groups, applications<sup>1</sup>,managed identities<sup>2</sup>) | Only cloud-only security groups designated as Role-Assignable (Privileged Access Groups) | <ul><li>Directory</li><li>Administrative Unit</li><li>Resource<sup>3</sup></li></ul> |
| Azure Resources | <ul><li>All security principals (users, groups, applications)</li><li>Security principals in other tenants (Azure Lighthouse)</li></ul>| N/A | <ul><li>Management Group</li><li>Subscription</li><li>Resource Group</li><li>Resource</li></ul>|
| Microsoft Graph API | API Scope<sup>4</sup> | 

<sup>1</sup>: The identity of an application registration is a Service Principal. Application / App Registration / Service Principal may be used interchangeably to describe an application identity.
<sup>2</sup>: Managed identities are non-person identities automatically assigned to many Azure resources. Resources use this identity to access applications, APIs, and other resources protected by Azure AD. 

> **Warning**: Do not assign managed identities or service principals to Azure AD roles. Doing this can create a scenario where privilege escalation is possible within the environment.

<sup>3</sup>: Here "resource" is an individual security principal that can have Owner be another security principal. For example, a group or application may have an Owner that can manage all aspects of the application, without any additional privileges in Azure AD.
<sup>4</sup>: MS Graph API scope is a resource-level permission, e.g. User.Read.All or User.ReadWrite.All.

> 📘 **Reference**:
>  - [Azure AD built-in roles](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)
>  - [Azure AD least-privilege roles by task](https://learn.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task)
>  - [Azure RBAC Docs](https://learn.microsoft.com/en-us/azure/role-based-access-control/)
>  - [Overview of Microsoft Graph](https://learn.microsoft.com/en-us/graph/overview?view=graph-rest-1.0)

## Security Boundary
The security boundary for an Azure environment is the Azure AD tenant. Global Administrator, the highest level Azure AD permission, can assign themselves to User Access Administrator / Owner for any subscription pinned to that Azure AD.

For Azure resources, the subscription itself plays a special role for 2 reasons:
1. Some Azure RBAC permissions, like VM Contributor, allow actions *only* when the role is assigned at the subscription level or higher
2. While Magement Groups sit above the subscriptions in the Azure RBAC scope hierarchy, they *usually* are not used for scope within Azure RBAC roles. Management Groups are primarily used for assigning Azure Policy.

### Azure AD Management


#### Centralized Management

#### Delegated Management

### MLZ Subscription Management

#### MLZ Core

#### MLZ Spokes

### Microsoft Sentinel Security

### Defender for Cloud Security

## Advanced Topics

### Hybrid Identity Attack Paths

### Management-Data Plane Crossover

## See Also
- [Return Home](/README.md)