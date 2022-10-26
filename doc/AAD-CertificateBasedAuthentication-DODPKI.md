# Configure DoD PKI for Azure AD native certificate-based authentication
This document provides step-by-step guidance for configuring DoD PKI with Azure AD Native CBA.

## Prerequisites
- Azure AD PowerShell v2
  - `Install-Module -Name AzureAD -RequiredVersion 2.0.0.33`
- Microsoft Graph PowerShell
  - `Install-Module Microsoft.Graph`

## Table of contents

1. Determine username mapping policy
2. Create a Pilot Group
3. Optional: Enable Staged Rolout
4. Download DoD PKI Certificates
5. Upload DoD PKI Certificates

## 1. Determine username mapping policy

Placeholder

### OnPremisesSamAccountName (Synchronized Users)
When Alternate Login ID is configured with Azure AD Connect Sync, the Active Directory `userPrincipalName` is automatically sent to Azure AD as the `OnPremisesUserPrincipalName` attribute. In this case, binding can be configured for this attribute.

````mermaid
flowchart BT
    subgraph Azure AD User Object
    UserPrincipalName
    OnPremisesUserPrincipalName
    Mail
    end
    subgraph AD User Object
    userPrincipalName
    mail
    end
    userPrincipalName-->OnPremisesUserPrincipalName
    mail-->UserPrincipalName
    mail-->Mail
````
> 📘 **Reference**: [Configure authentication binding policy](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#step-3-configure-authentication-binding-policy)

### UserCertificateIds (Cloud-Only Users)
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

## 4. Download DoD PKI Certificates

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


