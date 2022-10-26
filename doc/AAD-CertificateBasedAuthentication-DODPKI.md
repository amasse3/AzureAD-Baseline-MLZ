# Configure DoD PKI for Azure AD native certificate-based authentication
This document provides step-by-step guidance for configuring DoD PKI with Azure AD Native CBA.

## Prerequisites
- Azure AD PowerShell v2
  - `Install-Module AzureADPreview`
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

### OnPremisesSamAccountName

### UserCertificateIds

## 2. Create a Pilot Group

````PowerShell
$Sample = "abc"
if ($sample.Length() -gt 2) {
    Write-Host "hello this string is $($sample.length())"
}
````

## 3. Optional: Enable Staged Rollout

Script

## 4. Download DoD PKI Certificates

## 5. Upload DoD PKI Certificates



