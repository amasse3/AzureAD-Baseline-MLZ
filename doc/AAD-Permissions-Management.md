# Permissions in Azure and Azure AD
Document to describe roles relevant to Mission Landing Zone deployment and management.

## Table of Contents
- [Permissions Types](#permissions-in-azure-and-azure-ad)
- [Security Boundary](#security-boundary)
  - [Azure AD Management](#azure-ad-management)
  - 

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

> **Note**: Azure Lighthouse is a technology that enables RBAC assignments for security principals in another tenant. In an MSSP model, users from the managing tenant may have access to subscriptions without having a security principal in the tenant itself.

## Azure AD Management
Since the identity platform is the [security boundary](#security-boundary) for Azure, securing and managing it are important undertakings. This section covers two models for managing Azure AD for MLZ deployments:
- [Centralized Management](#centralized-management)
- [Delegated Management](#delegated-management)

### Centralized Management
In the centralized management model, one team within the organization is tasked with all tasks within the identity platform.

Common tasks include:
- Creating and managing users / groups
- Assigning licenses
- Assigning permissions
- Creating and managing applications
- Configuring Conditional Access
- Configuring and managing hybrid identity components like Azure AD Connect
- Enabling new features

Use Centralized Management for
 - [x] Small organizations with few administrators
 - [x] Initial model for tenant setup

> **Warning**: Centralized management does **not** mean all admins should be Global Administrators. Refer to [Azure AD least-privilege roles by task](https://learn.microsoft.com/en-us/azure/active-directory/roles/delegate-by-task) and assign role eligibility using Privileged Identity Management.

### Delegated Management
Delegated management is more common for enterprise environments. In this model, common tasks are delegated to mission owners so various groups in the organization can manage aspects of the identity platform. This section outlines common tasks and delegation configuration.

> **Note**: Not every activity within Azure AD can or should be delegated.

#### User and Group Management

| Task | Configuration |
|------|---------------|
| User creation | At the time of writing, this task cannot be delegated without assigning User Administrator role at the directory level|
| User management | Create an Administrative Unit and scope **User Administrator** role to the AU|
| Group creation | Create an AU and scope **Group Administrator** role to the AU |
| Group management | Assign owner directly, or move the group in an AU and scope **Group Administrator** role to the AU |

> **Reference**: Placeholder

#### Application Management

| Task | Configuration |
|------|---------------|
| Enterprise App Creation | At the time of writing, this task cannot be delegated without assigning Cloud Application Administrator role at the directory level|
| App Registration | Assign **Application Developer** role which allows Create As Owner permissions for App Registrations and Service Principals|
| Application Management | Assign owner directly to the Enterprise Application and/or App Registration|

**Note**: If the User Setting "Restrict Portal Access to the Azure AD Administration Portal" is set to **Yes**, application management blade will not be available unless the user is assigned an Azure AD directory role. This restriction holds even if the user is an owner of the application.

#### Subscription Management

| Task | Configuration |
|------|---------------|
| Manage RBAC assignments | Assign RBAC role via group, assign managers as owner to the group |
| Create new RBAC groups | Assign **User Access Administrator** via RBAC role. Delegate ability to create security groups (see [User and Group Management](#user-and-group-management))|
| Remove an RBAC assingment | Remove user from a group providing RBAC access. This can be done as **Group Administrator** for the AU, or owner of the group|

### Security Management


#### Microsoft Sentinel


#### Defender for Cloud Security

## Advanced Topics

### Mitigate Hybrid Identity Attack Paths

### Understand Management-Data Plane Crossover

## See Also
- [Return Home](/README.md)