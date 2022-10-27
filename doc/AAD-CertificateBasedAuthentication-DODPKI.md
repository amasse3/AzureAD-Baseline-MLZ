# Configure DoD PKI for Azure AD native certificate-based authentication
This document provides step-by-step guidance for configuring DoD PKI with Azure AD Native CBA.

## Prerequisites
- Azure AD PowerShell v2
  - `Install-Module -Name AzureAD -RequiredVersion 2.0.0.33`
- Microsoft Graph PowerShell
  - `Install-Module Microsoft.Graph`

## Table of contents
1. [Determine username mapping policy](#1-determine-username-mapping-policy)
2. [Create a Pilot Group](#2-create-a-pilot-group)
3. [Optional: Enable Staged Rolout](#3-optional-enable-staged-rollout)
4. [Download DoD PKI Certificates](#4-download-dod-pki-certificates)
5. [Upload DoD PKI Certificates](#5-upload-dod-pki-certificates)
6. [Configure AAD Authentication Method](#6-configure-the-cba-authentication-method)

## 1. Determine username mapping policy
For DOD Common Access Card (CAC) certificates, the `Principal Name` Subject Alternative Name (SAN) value needs to be mapped to an Azure AD attribute. Depending on the hybrid identity configuration, this value can be stored on either:
- [OnPremisesUserPrincipalName (synchronized)](#onpremisessamaccountname-synchronized-users)
- [UserCertificateIds (cloud-only)](#usercertificateids-cloud-only-users)

> 📘 **Reference**: [Configure authentication binding policy](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#step-3-configure-authentication-binding-policy)

### OnPremisesSamAccountName (synchronized users)
When Alternate Login ID is configured with Azure AD Connect Sync, the Active Directory `userPrincipalName` is automatically sent to Azure AD as the `OnPremisesUserPrincipalName` attribute. In this case, binding can be configured for this attribute.

````mermaid
flowchart BT
    subgraph Azure AD User Object
    UserPrincipalName
    OnPremisesUserPrincipalName
    Mail
    ImmutableID
    end
    subgraph AD User Object
    userPrincipalName
    mail
    objectGUID
    ms-DS-ConsistencyGUID
    end
    userPrincipalName--sync-->OnPremisesUserPrincipalName
    mail--sync-->UserPrincipalName
    mail--sync-->Mail
    ImmutableID--sync-->ms-DS-ConsistencyGUID
    objectGUID--sync-->ImmutableID
    
````

### UserCertificateIds (cloud-only Users)
Cloud-only users authenticating with DoD CAC need the Principal Name Subject Alternative Name (SAN) value on the CAC certificate to match an Azure AD user attribute. Since @mil value is non-routable, it cannnot be a `UserPrincipalName` value in Azure AD. `OnPremisesUserPrincipalName` attribute is reserved for synchronized identities, and cannot be modified. An alternative attribute called `userCertificateIds` can be used for this purpose. Configure using the Azure Portal following the reference below.

> 📘 **Reference**: [Certificate user IDs](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-certificateuserids)

Programatic updates to userCertificateIds attribute can be perfomed using Microsoft Graph API. See sample script:
<details><summary><b>Show Script</b></summary>
<p>

````PowerShell
function UpdateUserCertIDs {
    Param ([string]$UPN,[string]$CACPrincipalName)
    $certids = "X509:<PN>$CACPrincipalName"
    $body=@{
        "@odata.context"= "https://graph.microsoft.us/beta/$metadata#users/$entity"
        "authorizationInfo"= @{
            "certificateUserIds"= @(
                $certids
            )
        }
    }
    write-host -ForegroundColor Yellow "UPDATE: Adding userCertificateIds for $UPN. New Value: $CACPrincipalName"
    Update-MgUser -UserId $UPN -BodyParameter $body
}

##### UPDATE PARAMETERS #####
[string]$UPN = "mytestuser@contoso.onmicrosoft.us"
[string]$PrincipalName = "123456789101112@mil"

Connect-MgGraph -Environment USGov -Scopes User.ReadWrite.All
UpdateUserCertIDs -UPN $upn -CACPrincipalName $PrincipalName

# Verify value for single user
$user = Get-MgUser -UserId $UPN
$user.AuthorizationInfo.CertificateUserIds

````
</p>
</details>

## 2. Create a Pilot Group
Create a pilot group for targetting the certificate-based authentication method to an Azure AD security group. For this document, the name `Azure AD CBA Pilot` is used. Use the Azure Portal or Microsoft Graph PowerShell like the example below.

> 📘 **Reference**: [Manage groups in the Azure AD Portal](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/how-to-manage-groups)
<details><summary><b>Show Script</b></summary>
<p>

````PowerShell
##### UPDATE PARAMETERS #####
$DisplayName = "Azure AD CBA Pilot"
$MailNickname = "AzureADCBAPilot"
Connect-MGGraph -Environment USGov -Scopes Group.ReadWrite.All
New-MgGroup -DisplayName $DisplayName -MailEnabled:$false -MailNickname $MailNickname -SecurityEnabled:$true
````

</p>
</details>

## 3. Optional: Enable Staged Rollout
If the user domain is federated, staged rollout feature must be enabled to interrupt automatic re-direct to the federation service during user sign in. To configure staged rollout for the Azure AD CBA Pilot group created in the previous step, follow the Microsoft documentation below.

> 📘 **Reference**: [Migrate to cloud authentication using Staged Rollout](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-staged-rollout)

## 4. Configure Certification Authorities

### Download DOD PKI Certificates
Manually download the certificate files in *.cer format from https://public.cyber.mil/pki-pke/tools-configuration-files/ or write a PowerShell script using the sample below.

<details><summary><b>Show Script</b></summary>
<p>

````PowerShell
##### UPDATE PARAMETERS #####
$Environment = "USGov"
$CertFileURL = "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/certificates_pkcs7_DoD.zip"
$WorkingDirectory = "$env:USERPROFILE"+"\DoDPKI\"

function GetCertificateFiles {
    Param($CertFileURL,$WorkingDirectory)
    $outfile = $("$WorkingDirectory/certificates_pkcs7_DOD.zip")
    curl $CertFileURL -OutFile $outfile
    Return $outfile
}

$zip = GetCertificateFiles -CertFileURL $CertFileURL -WorkingDirectory $WorkingDirectory
Expand-Archive -Path $zip -DestinationPath $WorkingDirectory

$p7bfile = Get-ChildItem -Path $WorkingDirectory -Include *.der.p7b -Recurse -ErrorAction SilentlyContinue | ?{$_.Name -notmatch "Root"}
$DoDCerts = Import-Certificate -FilePath $p7bfile -CertStoreLocation Cert:\CurrentUser\My
$IDCerts = $DoDCerts | ?{$_.Subject -match "^(CN=DOD ID CA)" -or $_.Subject -match "^(CN=DOD Root CA)"}

Write-Host -ForegroundColor Green "Certificates Downloaded Successfully"
````
</p>
</details>

## 5. Upload DoD PKI Certificates
Manually upload the DOD PKI certificate authorities using the [Azure Portal](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#configure-certification-authorities-using-the-azure-portal) or [PowerShell](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#configure-certification-authorities-using-powershell).

<details><summary><b>Show Script</b></summary>
<p>

````PowerShell
#region functions
function UploadDoDCertificates {
    Param([array]$IDCerts,[array]$IDCACrls)
    foreach ($cert in $IDCerts) {
        $crl = ''
        $root = $cert.Subject -match "root"
        $num = $cert.Subject.split("=")[1] -replace "[^0-9]+",""
        $crl = $IDCACRLs | ?{$_ -match $num}
        if (!$crl -and !$root) {
            $crl = "http://crl.disa.mil/crl/DODIDCA_"+$num+".crl"
        }
        Try {
            UploadCert -certbinary $cert.RawData -crl $crl -isroot $root
        } catch [exception] {
            write-host -ForegroundColor Cyan "Certificate already exists"
        }
    }
}

function UploadCert {
    Param($certbinary,$crl,$deltacrl,$isroot)
    if ($isroot) {$authority=0} else {$authority=1}
    $new_ca=New-Object -TypeName Microsoft.Open.AzureAD.Model.CertificateAuthorityInformation
    $new_ca.AuthorityType=$authority
    $new_ca.TrustedCertificate=$certbinary
    $new_ca.crlDistributionPoint=$crl
    New-AzureADTrustedCertificateAuthority -CertificateAuthorityInformation $new_ca
}
#endregion

$IDCACRLs = @(`
"http://crl.disa.mil/crl/DODROOTCA2.crl",`
"http://crl.disa.mil/crl/DODROOTCA3.crl",`
"http://crl.disa.mil/crl/DODROOTCA4.crl",`
"http://crl.disa.mil/crl/DODROOTCA5.crl",`
"http://crl.disa.mil/crl/DODIDCA_33.crl",`
"http://crl.disa.mil/crl/DODIDCA_34.crl",`
"http://crl.disa.mil/crl/DODIDCA_39.crl",`
"http://crl.disa.mil/crl/DODIDCA_40.crl",`
"http://crl.disa.mil/crl/DODIDCA_41.crl",`
"http://crl.disa.mil/crl/DODIDCA_42.crl",`
"http://crl.disa.mil/crl/DODIDCA_43.crl",`
"http://crl.disa.mil/crl/DODIDCA_44.crl",`
"http://crl.disa.mil/crl/DODIDCA_49.crl",`
"http://crl.disa.mil/crl/DODIDCA_50.crl",`
"http://crl.disa.mil/crl/DODIDCA_51.crl",`
"http://crl.disa.mil/crl/DODIDCA_52.crl",`
"http://crl.disa.mil/crl/DODIDCA_59.crl",`
"http://crl.disa.mil/crl/DODIDCA_62.crl",`
"http://crl.disa.mil/crl/DODIDCA_63.crl",`
"http://crl.disa.mil/crl/DODIDCA_64.crl",`
"http://crl.disa.mil/crl/DODIDCA_65.crl")

# Match the certificates to CRLs and upload with AAD PowerShell
Write-Host -ForegroundColor Cyan "Connecting to Azure AD PowerShell module. Sign in as a Global Administrator."
Connect-AzureAD -AzureEnvironmentName AzureUSGovernment

#Upload certs
UploadDoDCertificates -IDCerts $IDCerts -IDCACrls $IDCACRLs

Write-Host -ForegroundColor Green "Certificates Uploaded Successfully"
````
</p>
</details>

## 6. Configure the CBA Authentication Method
Enable the CBA on the Azure AD tenant following the reference below. Use the following settings:

|Setting|Value|
|-------|-----|
|Enable | Yes |
|Target |Select Users - Azure AD CBA Pilot|
|Protection Level|Multi-Factor Authentication|
|Binding Policy | [See step 1.](#1-determine-username-mapping-policy)|

> 📘 **Reference**: [Enable CBA on the tenant](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#step-2-enable-cba-on-the-tenant)

## 7. Test signing in with a certificate
1. Add a user to the `Azure AD CBA Pilot` group. 
2. For cloud-only users, ensure `UserCertificateIds` value is populated with the [appropriate value](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-technical-deep-dive#achieve-higher-security-with-certificate-bindings).
3. Open a web browser and navigate to https://portal.azure.us
4. Sign in with the test user, choosing **certificate authentication**
5. Select the CAC certificate and enter the PIN
6. Verify the user signed in successfully. Reference the [documentation](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-technical-deep-dive#understanding-the-certificate-based-authentication-error-page) to troubleshoot any issues.

> 📘 **Reference**: [How Azure AD CBA Works](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-technical-deep-dive)



