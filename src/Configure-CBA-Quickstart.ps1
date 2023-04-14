#Configure-CBA-Quickstart.ps1
#
# Version: 0.3 Testing
# LastModified: 04/14/2023
#
# Warning: Sample scripts in this repository are not supported under any Microsoft support program or service. 
# Scripts are provided AS IS without warranty of any kind. All warranties including, without limitation, any 
# implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of 
# the use of sample scripts or configuration documentation remains with you. In no event shall Microsoft, its 
# authors, or anyone else involved in the creation, production, or delivery of this content be liable for any 
# damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, 
# loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample
# scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
#

Param(
    [Parameter (Mandatory = $False, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateSet("userPrincipalName","onPremisesUserPrincipalName","certificateUserIds")]
    [String]$AADAttribute = "onPremisesUserPrincipalName",
    [Parameter (Mandatory = $False, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateSet("PrincipalName","RFC822Name","SubjectKeyIdentifier","SHA1PublicKey")]
    [String]$CertificateField = "PrincipalName",
    [Parameter (Mandatory = $False, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [String]$PKIJsonFilePath = "DODPKI.json",
    [Parameter (Mandatory = $False, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [String]$PilotGroupName = "Azure AD CBA Pilot",
    [Parameter (Mandatory = $False, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateSet("USGov","Global")]
    [String]$AzureEnvironmentName = "Global"
)

#region functions
function Convert-HexStringToByteArray {
    [CmdletBinding()]Param(
    [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
    [String]$String)
 
    #Clean string
    #$String = $String.ToLower() -replace "[^a-f0-9\\,x\-\:]",""
    #$String = $String -replace "0x|\x|\-|,",":"
    #$String = $String -replace "^:+|:+$|x|\",""
 
    #Convert the rest
    if ($String.Length -eq 0) {,@() ; return}
 
    #Split string with or without colon delimiters.
    if ($String.Length -eq 1) {
        ,@([System.Convert]::ToByte($String,16))
    } elseif (($String.Length % 2 -eq 0) -and ($String.IndexOf(":") -eq -1)) {
        ,@($String -split '([a-f0-9]{2})' | foreach-object {
            if ($_) {[System.Convert]::ToByte($_,16)}
        })
    } elseif ($String.IndexOf(":") -ne -1) {
        ,@($String -split ':+' | foreach-object {[System.Convert]::ToByte($_,16)})
    }
    else {,@()}
}
#endregion

#region warning
$msg = "WARNING:`nSample scripts in this repository are not supported under any Microsoft support program or service. Scripts are provided AS IS without warranty of any kind. All warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use of sample scripts or configuration documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, produciton, or delivery of this content be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages."
Write-Host $msg -ForegroundColor Yellow
write-host "`nThis script is under active development. Do not run in a production environment.`n" -ForegroundColor Red
$response = read-host "If you agree to continue, press `"c`". Press any other key to exit."
$continue = $response -eq "c"
if (!$continue) {
    write-host "Exiting script..."
    start-sleep -Seconds 3
    exit
}
#endregion

# Read in Certificates Json
$CertConfig = Get-Content $PKIJsonFilePath | ConvertFrom-Json

if (!($CertConfig)) {
    Write-Host -ForegroundColor Red "PKI Json file not found at $PKIJsonFilePath."
    return
}

# Connect to Azure AD PowerShell
switch ($AzureEnvironmentName) {
    USGov {$AADEnvironment="AzureUSGovernment";$MSGraphURI="https://graph.microsoft.com"}
    Global {$AADEnvironment="AzureCloud";$MSGraphURI="https://graph.microsoft.us"}
}

Try {$connected = Get-AzureADTenantDetail -ErrorAction Stop} Catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {Write-Warning "Not authenticated to Azure AD. Connecting"
    $connected = Connect-AzureAD -AzureEnvironmentName $AADEnvironment
}

Start-Sleep -Seconds 4

#Get existing certificate configuration
$TenantCertificates = Get-AzureADTrustedCertificateAuthority

#Check to see if certificates exist, if not add AzureADTrustedCertificateAuthority
foreach ($cert in $Certconfig) {
    if ($cert.Subject -in $TenantCertificates.TrustedIssuer) {
        Write-host "Certificate $($cert.Subject) already exists."
    } else {
        Write-Host "Creating certificate $($cert.Subject.split(",")[0])." -ForegroundColor Cyan
        $new_ca=New-Object -TypeName Microsoft.Open.AzureAD.Model.CertificateAuthorityInformation
        $new_ca.AuthorityType=$($cert.authority)
        $new_ca.TrustedCertificate=$(Convert-HexStringToByteArray -String $cert.RawData)
        $new_ca.crlDistributionPoint=$($cert.crl)
        New-AzureADTrustedCertificateAuthority -CertificateAuthorityInformation $new_ca | Out-Null
    }
}

# Connect to MS Graph PowerShell
Connect-MGGraph -Environment $AzureEnvironmentName -Scopes Group.ReadWrite.All,Policy.ReadWrite.FeatureRollout,Policy.ReadWrite.AuthenticationMethod

# Create Pilot Group
$MailNickname = $PilotGroupName -replace '[\W]', ''

# Create group if it does not already exist
$GroupExists = Get-MgGroup -Filter "mailnickname eq `'$MailNickname`'"
if (!($GroupExists)) {
    Write-Host "Creating Pilot Group $MailNickname."
    $GroupObj = New-MgGroup -DisplayName $PilotGroupName -MailEnabled:$false -MailNickname $MailNickname -SecurityEnabled:$true
    Write-Host "Created Pilot Group $($GroupObj.id)." -ForegroundColor Cyan
} else {
    if ($GroupExists.count -gt 1) {
        $GroupObj = $GroupExists[0]
        Write-Host "$($GroupExists.count) groups exist with mailnickname value $Mailnickname. Configuring CBA with $($GroupObj.Id)." -ForegroundColor Yellow
    } else {
        $GroupObj = $GroupExists
        Write-Host "Pilot Group $MailNickname already exists with id $($GroupObj.Id)."
    }
}

# Update Staged Rollout
$FeatureRolloutPolicy = Get-MgPolicyFeatureRolloutPolicy | ?{$_.Feature -eq "certificateBasedAuthentication"}

if ($FeatureRolloutPolicy) {
    Write-Host "Enabling Azure AD CBA feature rollout policy." -ForegroundColor Cyan
    Update-MgPolicyFeatureRolloutPolicy -FeatureRolloutPolicyId $FeatureRolloutPolicy.Id -IsEnabled:$true

} else {

    Write-Host "Creating Azure AD CBA feature rollout policy." -ForegroundColor Cyan
    $params = @{
	    DisplayName = "CBA rollout policy"
	    Description = ""
	    Feature = "certificateBasedAuthentication"
	    IsEnabled = $true
	    IsAppliedToOrganization = $false
    }
    $FeatureRolloutPolicy = New-MgPolicyFeatureRolloutPolicy -BodyParameter $params
}

#Add pilot group to staged rollout
Write-Host "Adding the pilot group $($GroupObj.Id) to CBA staged rollout." -ForegroundColor Cyan
$params = @{
    "@odata.id" = "$MSGraphURI/v1.0/directoryObjects/$($GroupObj.Id)"
}

Try {
    $policyref = New-MgPolicyFeatureRolloutPolicyApplyToByRef -FeatureRolloutPolicyId $FeatureRolloutPolicy.Id -BodyParameter $params -ErrorAction SilentlyContinue
} Catch [exception] {}


# Configure Authentication Method
Write-host "Enabling CBA Authentication method." -ForegroundColor Cyan

$params = @{
    "@odata.context" = "$MSGraphURI/v1.0/$metadata#authenticationMethodsPolicy"
    AuthenticationMethodConfigurations = @(
		@{
            "@odata.type"= "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
            "id"= "X509Certificate"
            "state"= "enabled"
            "excludeTargets"= @()
            "certificateUserBindings" = @(
                @{
                    "x509CertificateField" = $CertificateField
                    "userProperty" = $AADAttribute
                    "priority"= 1
                }
            )
            "authenticationModeConfiguration" = @{
                "x509CertificateAuthenticationDefaultMode" = "x509CertificateMultiFactor"
                "rules" = @()
            }
            "includeTargets@odata.context" = "https://graph.microsoft.com/beta/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('X509Certificate')/microsoft.graph.x509CertificateAuthenticationMethodConfiguration/includeTargets"
            "includeTargets"= @(
                @{
                    "targetType" = "group"
                    "id" = $($GroupObj.Id)
                    "isRegistrationRequired"= $false
                }
            )
		}
	)
}

Update-MgPolicyAuthenticationMethodPolicy -BodyParameter $params | Out-Null

Write-Host "CBA Configuration complete." -ForegroundColor Green

Write-Host "Summary:`n - Uploaded certificates from $PKIJsonFilePath`n - Configured group $($GroupObj.MailNickname) $($GroupObj.Id)`n - Configured Staged Rollout for Azure AD CBA`n - Configured Azure AD Authentication Method for CBA`n - Set certificate binding $CertificateField = user.$AADAttribute"

<#if ($error.Count -gt 0) {
    Write-Host -ForegroundColor Yellow "There were errors during configuration."
} else {
    Write-Host "Summary:`n - Uploaded certificates from $PKIJsonFilePath`n - Configured group $($GroupObj.MailNickname) $($GroupObj.Id)`n - Configured Staged Rollout for Azure AD CBA`n - Configured Azure AD Authentication Method for CBA`n - Set certificate binding $CertificateField = user.$AADAttribute"
}#>
