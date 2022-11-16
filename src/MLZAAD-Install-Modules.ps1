#MLZAAD-Install-Modules.ps1
<#
.SYNOPSIS

Installs some PowerShell modules needed for Azure and Azure Active Directory management.

.DESCRIPTION

Installs modules. Takes no input. There are many additional PowerShell modules that may be needed for Azure Management which are not included in this script.

.INPUTS

None. You cannot pipe objects to MLZ-Install-Modules.

.OUTPUTS

System.String.

.EXAMPLE

PS> ./MLZAAD-Install-Modules.ps1

.LINK

Placeholder

#>

#Install Modules
Install-Module Microsoft.Graph

Install-Module az

Install-Module AzureADPreview