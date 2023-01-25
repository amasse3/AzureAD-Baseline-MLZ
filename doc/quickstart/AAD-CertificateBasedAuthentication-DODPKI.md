# Configure DoD PKI for Azure AD native certificate-based authentication
This document provides step-by-step guidance for configuring DoD PKI with Azure AD Native CBA.

## Prerequisites
- Azure AD PowerShell v2
  - `Install-Module -Name AzureAD -RequiredVersion 2.0.0.33`
- Microsoft Graph PowerShell
  - `Install-Module Microsoft.Graph`
- User with Global Administrator role in Azure AD

## Table of contents
 - [Configuration Steps](#configuration-steps)
   - [1. Determine username mapping policy](#1-determine-username-mapping-policy)
   - [2. Optional: Create a Pilot Group](#2-optional-create-a-pilot-group)
   - [3. Optional: Enable Staged Rollout](#3-optional-enable-staged-rollout)
   - [4. Configure the Certification Authorities](#4-configure-the-certification-authorities)
   - [5. Configure AAD Authentication Method](#5-configure-the-cba-authentication-method)
 - [Test signing in with certificate](#test-signing-in-with-a-certificate)
 - [Preview - Sign in with certificate on mobile device](#preview---sign-in-with-certificate-on-mobile-device)
 - [See Also](#see-also)

## Configuration Steps
Azure AD Certificate-based Authentication (CBA) can be configured with the Azure Portal or using PowerShell. This section outlines the steps for configuring the feauture for DOD Common Access Cards (CAC).

### 1. Determine username mapping policy
For DOD Common Access Card (CAC) certificates, the `Principal Name` Subject Alternative Name (SAN) value needs to be mapped to an attribute on your Azure AD user accounts. Depending on the hybrid identity configuration, this value can be stored on either:
- [OnPremisesUserPrincipalName (synchronized users)](#onpremisessamaccountname-synchronized-users)
- [UserCertificateIds (cloud-only users)](#usercertificateids-cloud-only-users)

Use the following flow chart to determine which attribute you should use.

````mermaid
flowchart LR
    A(Start) -->B{Hybrid\nIdentity?}
    B -->|yes| C{Synced Users Only?}
    B -->|no| D(<b>Use certificateUserIds\nbinding</b>)
    C -->|yes|E(<b>Use\nonPremisesUserPrincipalName\nbinding</b>)
    C -->|no|F[Both Cloud-Only\nand\nSynced Users]
    F --> D
````

> 📘 [Configure authentication binding policy](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#step-3-configure-authentication-binding-policy)

#### Synchronized Users
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
    ms-DS-ConsistencyGUID
    objectGUID
    end
    userPrincipalName-->|sync|OnPremisesUserPrincipalName
    mail-->|sync|UserPrincipalName
    mail-->|sync|Mail
    objectGUID-->|sync|ImmutableID
    ms-DS-ConsistencyGUID<-->|writeback|ImmutableID
````

#### Cloud-Only Users (or combination of cloud-only and synchronized)
Cloud-only users authenticating with DoD CAC need the Principal Name Subject Alternative Name (SAN) value on the CAC certificate to match an Azure AD user attribute. Since @mil value is non-routable, it cannnot be a `UserPrincipalName` value in Azure AD. The attribute `OnPremisesUserPrincipalName` contains the Active Directory UPN for synchronized identities. This attribute cannot be modified for synchronized users and cannot be used for cloud-only identities.

An alternative attribute, `certificateUserIds`, can be used in this scenario. It is multi-valued, allowing a user to have and use more than one certificate credential. The fields and value patterns are listed in the table below:

|**Certificate mapping field**|**certificateUserIds Pattern**|**Example**|
|-----------------------------|------------------------------|-----------|
|PrincipalName|`X509:<PN>` + `value`|X509:<PN>123456789101112@mil|
|RFC822Name (Email)|`X509:<RFC822>` + `value`|bob@contoso.com|
|X509 Subject Key Identifier|`X509:<SKI>` + `value`|X509:<SKI>123456789abcdef|
|X509 SHA1 Public Key|`X509:<SHA1-PUKEY>` + `value`|X509:<SHA1-PUKEY>123456789abcdef|

Configure using the Azure Portal following the reference below.

> 📘 [Certificate user IDs](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-certificateuserids)

You may also want to use this attribute for synchronized users for scenarios where `OnPremisesUserPrincipalName` will not contain the right attribute value to match the certificate. To use Azure AD Connect to populate the attribute, see [update certificateUserIds with Azure AD Connect](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-certificateuserids#update-certificate-user-ids-using-azure-ad-connect).

Programatic updates to userCertificateIds attribute can be perfomed using Microsoft Graph API. Sample script included below:
<details><summary><b>Show Script</b></summary>
<p>

````PowerShell
function UpdateUserCertIDs {
    Param(
        [String]$UserPrincipalName,
        [ValidateSet("PrincipalName","RFC822Name","X509SKI","X509SHA1PublicKey")]
        [String]$binding,
        [String]$value,
        [Switch]$USGov
    )
  
    switch ($binding) {
        PrincipalName {$pattern = "X509:<PN>"}
        RFC822Name {$pattern = "X509:<RFC822>"}
        X509SKI {$pattern = "X509:<SKI>"}
        X509SHA1PublicKey {$pattern = "X509:<SHA1-PUKEY>"}
    }

    if ($USGov) {$MSGraphURI="https://graph.microsoft.us/beta"} else {"https://graph.microsoft.us/beta"}

    #prepare the value
    $body=@{
        "@odata.context"= "$MSGraphURI/$metadata#users/$entity"
        "authorizationInfo"= @{
            "certificateUserIds"= @(
                $pattern + $value
            )
        }
    }
    write-host -ForegroundColor Yellow "UPDATE: Adding userCertificateIds for $UserPrincipalName. New Value: $CACPrincipalName"
    Update-MgUser -UserId $UserPrincipalName -BodyParameter $body -ErrorAction Stop
}

##### UPDATE PARAMETERS #####
[string]$UPN = "mytestuser@contoso.onmicrosoft.us"
[string]$CACPNValue = "123456789101112@mil"

# Connect to MS Graph (example for Azure AD Government)
Connect-MgGraph -Environment USGov -Scopes User.ReadWrite.All
UpdateUserCertIDs -UserPrincipalName $UPN -binding PrincipalName -value $CACPNValue -USGov

# Verify value for single user
$user = Get-MgUser -UserId $UPN
$user.AuthorizationInfo.CertificateUserIds
````
</p>
</details>

### 2. Optional: Create a Pilot Group
You may want to target a pilot group for Azure AD CBA. For this document, the name `Azure AD CBA Pilot` is used. Use the Azure Portal or Microsoft Graph PowerShell like the example below.

> 📘 [Manage groups in the Azure AD Portal](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/how-to-manage-groups)
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

### 3. Optional: Enable Staged Rollout
If the user belongs to a federated domain (they authenticate to Azure AD using AD FS or some other provider), staged rollout feature must be enabled to interrupt automatic re-direct to the federation service during sign-in.

To configure staged rollout for the Azure AD CBA Pilot group created in the previous step, follow the Microsoft documentation below.

> 📘 [Migrate to cloud authentication using Staged Rollout](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-staged-rollout)

### 4. Configure the Certification Authorities
This step provides 2 options for configuring the certification authorities:
 - [Option A: Automated Configuration](#option-a-automated-configuration)
 - [Option B: Manual Configuration](#option-b-manual-configuration)

#### Option A: Automated Configuration
The automated configuration uses a JSON file pre-populated with the certificate details for the DOD PKI.

1. Download [DODPKI.json](/src/DODPKI.json) from this repository.
2. Copy it to the workstation you will be running the Azure AD PowerShell cmdlets from. Note the file path and update the `$JsonPath` variable in the script parameters.
3. Run the script:

<details><summary><b>Show Script</b></summary>
<p>

```PowerShell
##### UPDATE PARAMETERS #####
$JsonPath = "c:\temp\DODPKI.json"
$CertConfig = Get-Content $JsonPath | ConvertFrom-Json
#############################

#Connect to Azure AD
Connect-AzureAD -AzureEnvironmentName AzureUSGovernment

#Get existing certificate configuration
$TenantCertificates = Get-AzureADTrustedCertificateAuthority

#Check to see if certificates exist, if not add AzureADTrustedCertificateAuthority
foreach ($cert in $Certconfig) {
    if ($cert.Subject -in $TenantCertificates.TrustedIssuer) {
        Write-host "Certificate $($cert.Subject) already exists."
    } else {
        $new_ca=New-Object -TypeName Microsoft.Open.AzureAD.Model.CertificateAuthorityInformation
        $new_ca.AuthorityType=$($cert.authority)
        $new_ca.TrustedCertificate=$(Convert-HexStringToByteArray -String $cert.RawData)
        $new_ca.crlDistributionPoint=$($cert.crl)
    }  
    New-AzureADTrustedCertificateAuthority -CertificateAuthorityInformation $new_ca
}
```
</p>
</details>

> 📘 [Configure certification authorities - New-AzureADTrustedCertificateAuthority](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#add)

#### Option B: Manual Configuration
**Download the certificates and CRL locations**
1. Open your web browser and navigate to the public-facing cyber.mil website: [https://public.cyber.mil/pki-pke/tools-configuration-files/]
2. Download the PKI CA Certificate Bundles (DoD PKI Only). The current version as of January 2023 is version 5.9 found [here](https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/certificates_pkcs7_DoD.zip).
3. Expand the ZIP archive.
4. Double-click the .der.p7b file (e.g. Certificates_PKCS7_v5.9_DoD.der.p7b) to open certmgr.
5. Expand the AppData folder and click **Certificates**
6. Right-click on the certificates listed below, select **All Tasks --> Export...**, select **DER encoded binary X.509 (.CER)** format, and choose a location to save the file.
    - DoD Root CA 3
    - DoD Root CA 4
    - DoD Root CA 5
    - DOD ID CA-59
    - DOD ID CA-62
    - DOD ID CA-63
    - DOD ID CA-64
    - DOD ID CA-65
7. Next, open the latest **DoD and ECA CRL Distribution Points (CRLDPs)** from [https://public.cyber.mil/pki-pke/tools-configuration-files/]. The current version as of January 2023 is [here](https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/txt/unclass-dod_eca_crldps_nipr_20210415.txt).
8. Keep this list open for reference.

**Upload the certificates to the Azure AD Portal**
Follow the [manual steps](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#step-1-configure-the-certification-authorities) to upload the certificates in the order below:

|No.|Certificate|CRL|Is Root CA|
|---|-----------|---|----------|
|1|DoD Root CA 3|http://crl.disa.mil/crl/DODROOTCA3.crl|Yes|
|2|DoD Root CA 4|http://crl.disa.mil/crl/DODROOTCA4.crl|Yes|
|3|DoD Root CA 5|http://crl.disa.mil/crl/DODROOTCA5.crl|Yes|
|4|DOD ID CA-59|http://crl.disa.mil/crl/DODIDCA_59.crl|No|
|5|DOD ID CA-62|http://crl.disa.mil/crl/DODIDCA_62.crl|No|
|6|DOD ID CA-63|http://crl.disa.mil/crl/DODIDCA_63.crl|No|
|7|DOD ID CA-64|http://crl.disa.mil/crl/DODIDCA_64.crl|No|
|8|DOD ID CA-65|http://crl.disa.mil/crl/DODIDCA_65.crl|No|

> 📘 [Configure certification authorities](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#step-1-configure-the-certification-authorities)

### 5. Configure the CBA Authentication Method
Enable the CBA on the Azure AD tenant following the reference below. Use the following settings:

|Setting|Value|
|-------|-----|
|Enable | Yes |
|Target |Select Users - Azure AD CBA Pilot|
|Protection Level|Multi-Factor Authentication|
|Binding Policy | [See step 1](#1-determine-username-mapping-policy).|

> 📘 [Enable CBA on the tenant](https://learn.microsoft.com/en-us/azure/active-directory/authentication/how-to-certificate-based-authentication#step-2-enable-cba-on-the-tenant)

## Test signing in with a certificate

> **Warning**: It will take around 30 minutes for settings to propogate for Staged Rollout and Certificate Authorities configuration.

1. Add a user to the `Azure AD CBA Pilot` group. 
2. For cloud-only users, ensure `UserCertificateIds` value is populated with the [appropriate value](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-technical-deep-dive#achieve-higher-security-with-certificate-bindings).
3. Open a web browser and navigate to https://portal.azure.us
4. Sign in with the test user, choosing **certificate authentication**
5. Select the CAC certificate and enter the PIN
6. Verify the user signed in successfully. Reference the [documentation](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-technical-deep-dive#understanding-the-certificate-based-authentication-error-page) to troubleshoot any issues.

> 📘 [How Azure AD CBA Works](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-technical-deep-dive)

## Preview - Sign in with certificate on mobile device
Mobile devices now support certificate-based authentication in the native browser using certificate stored in the PIV app for Yubikey devices. This new capability differs from previous mobile CBA implementations becuase A) ADFS is not required, B) it is true MFA since PIN / private key is used.

**Useful information**
| Platform | Yubikey Type | OS Requirement | Application Requirement | Behavior |
|----------|--------------|----------------|-------------------------|----------|
| iOS      | NFC, Lightning | iOS 14.2+       | Safari, Yubico Authenticator 17 | Use Yubico Authenticator to load the public key for the certificate into iOS Keychain. After tapping sign-in with certificate, a notification banner for Yubico Authenticaotr will appear. Tap it to provide PIN in the Yubico Authenticator app. Use the breadcrumb in the top left to navigate back to the browser.*|
| iPadOS  | Lightning, USB-C | iPadOS 16 | Safari, Yubico Authentciator | Use Yubico Authenticator to load the public key for the certificate into iOS Keychain. After tapping sign-in with certificate, Safari will launch a PIN prompt in the same browser window. Once PIN is entered and certificate is verified, sign-in will succeed.|
| Android | USB-C (NFC not supported currently) | Android 12 (earlier versions may work) | Chrome |No prerequisites. After tapping sign-in with certificate, Chrome will launch a PIN prompt in the same browser window. Once PIN is entered and certificate is verified, sign-in will succeed.|

> **Warning**: iOS requires notifications enabled for Yubico Authenticator app. Ensure that Focus Modes include Yubico Authenticator to bypass the notification block. When the notification does not succeed, the certificate authentication page (certauth.login.microsoftonline) will hang and time out with TLS error.

> 📘 [Android devices - Support for certificates on hardware security key (preview)](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-mobile-android#support-for-certificates-on-hardware-security-key-preview)\
> 📘 [iOS devices- Support for certificates on hardware security key (preview)](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-certificate-based-authentication-mobile-ios#support-for-certificates-on-hardware-security-key-preview)

## Common Configuration Issues
This section covers the most common configuration errors that may cause issues with CBA.

Placeholder. To do: Add AAD error values and details.

|No.|Issue|Common Cause|Fix|
|---|-----|------------|---|
|1|Timeout fetching CRL|A CRL endpoint was used that is not accessible by the Azure AD logon service.|Use a publicly accessible CRL|
|2|Certificate does not map uniquely to an Azure AD user|More than one user has the same certificateUserIds or OnPremisesUserPrincipalName (for multi-forest AD DS customers) value|Update the Azure AD users so the value on the certificate maps to a unique user.|
|3|Authentication fails because the CRL is invalid.|The CRL found at the CRL loccation is for a different certificate|Delete the certificate and upload again, specifying the proper CRL location.|      


## See Also
- [Home](/README.md)
- [Azure AD Configuration Baseline](/doc/AAD-Config-Baseline.md)